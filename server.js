/**
 * Maarsseveen Pechhulp — auth backend
 * =====================================
 * Regelt: inloggen, accounts aanmaken, en een ECHTE "wachtwoord vergeten"
 * met een e-mail via Resend (https://resend.com — gratis laag beschikbaar).
 *
 * Wachtwoorden worden gehasht opgeslagen (bcrypt) — nooit in platte tekst.
 * Data staat in een SQLite-bestand (auth.db), blijft bewaard na herstart.
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const db = new Database(process.env.DB_PATH || "auth.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    naam TEXT NOT NULL,
    rol TEXT NOT NULL,
    permissie TEXT NOT NULL DEFAULT 'Standaard'
  );
  CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    verloopt_op INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS employees (
    discord_id TEXT PRIMARY KEY,
    roepnummer TEXT,
    naam TEXT NOT NULL,
    ingame TEXT DEFAULT '',
    rol TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Actief',
    opmerkingen TEXT DEFAULT '',
    strikes INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    naam TEXT, van_rol TEXT, naar_rol TEXT,
    datum TEXT, door TEXT, reden TEXT,
    run_id INTEGER
  );
  CREATE TABLE IF NOT EXISTS tijden_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    datum INTEGER NOT NULL,
    medewerkers_met_promotie INTEGER NOT NULL DEFAULT 0,
    uren_gehaald INTEGER NOT NULL DEFAULT 0,
    uren_niet_gehaald INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS week_winner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    discord_id TEXT, naam TEXT, uren REAL, handmatig INTEGER NOT NULL DEFAULT 0
  );
`);
// Migratie voor bestaande databases die nog geen permissie/ingame/run_id-kolom hebben
try { db.exec("ALTER TABLE accounts ADD COLUMN permissie TEXT NOT NULL DEFAULT 'Standaard'"); } catch (e) { /* kolom bestaat al */ }
try { db.exec("ALTER TABLE employees ADD COLUMN ingame TEXT DEFAULT ''"); } catch (e) { /* kolom bestaat al */ }
try { db.exec("ALTER TABLE promotions ADD COLUMN run_id INTEGER"); } catch (e) { /* kolom bestaat al */ }

// --- Gedeelde rollen-ladder (zelfde als bot en website) --------------------

const ROLE_INFO = [
  { naam: "Directeur", range: [1, 3], salaris: 29000, tier: 9 },
  { naam: "Chef Werkplaats", range: [4, 9], salaris: 26000, tier: 8 },
  { naam: "Technisch Specialist", range: [10, 23], salaris: 23000, tier: 7 },
  { naam: "Autotechnicus", range: [24, 34], salaris: 21000, tier: 6 },
  { naam: "Hoofd Monteur", range: [35, 54], salaris: 20000, tier: 5 },
  { naam: "Ervaren Monteur", range: [55, 74], salaris: 18000, tier: 4 },
  { naam: "Monteur", range: [75, 94], salaris: 16000, tier: 3 },
  { naam: "Beginnend Monteur", range: [95, 134], salaris: 15000, tier: 2 },
  { naam: "Stagiair", range: [135, 185], salaris: 0, tier: 1 },
];
const AUTO_PROMOTIE_PLAFOND = 8; // Chef Werkplaats
const MONTEUR_VARIANTEN = ["Monteur", "Ervaren Monteur", "Hoofd Monteur", "Beginnend Monteur"];

function roleInfo(naam) { return ROLE_INFO.find((r) => r.naam === naam); }
function tierRole(tier) { return ROLE_INFO.find((r) => r.tier === tier); }
function formatNum(n) { return n < 100 ? String(n).padStart(2, "0") : String(n); }

function nextRoepnummer(rolNaam, excludeId) {
  const info = roleInfo(rolNaam);
  if (!info) return null;
  const bestaand = db.prepare("SELECT discord_id, roepnummer FROM employees WHERE discord_id != ?").all(excludeId || "");
  const gebruikt = new Set(bestaand.map((e) => e.roepnummer));
  const [lo, hi] = info.range;
  for (let n = lo; n <= hi; n++) {
    const kandidaat = `A-${formatNum(n)}`;
    if (!gebruikt.has(kandidaat)) return kandidaat;
  }
  return `A-${formatNum(hi)}`;
}

// Eenvoudige gedeelde-sleutel-check voor de bot (en desgewenst de website)
const API_KEY = process.env.API_KEY;
function checkApiKey(req, res, next) {
  if (!API_KEY) return next(); // geen key ingesteld = open (handig tijdens lokaal testen)
  const ontvangen = req.header("x-api-key");
  if (ontvangen !== API_KEY) {
    console.log("[API_KEY DEBUG] verwacht-lengte:", API_KEY.length, "ontvangen-lengte:", ontvangen ? ontvangen.length : "GEEN HEADER");
    console.log("[API_KEY DEBUG] verwacht (eerste/laatste 4):", API_KEY.slice(0, 4), "...", API_KEY.slice(-4));
    console.log("[API_KEY DEBUG] ontvangen (eerste/laatste 4):", ontvangen ? ontvangen.slice(0, 4) + " ... " + ontvangen.slice(-4) : "n.v.t.");
    return res.status(401).json({ error: "Ongeldige of ontbrekende API key." });
  }
  next();
}

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const EMAIL_USER = process.env.EMAIL_USER; // bv. maarsseveenpechhulp@gmail.com
const EMAIL_APP_PASSWORD = process.env.EMAIL_APP_PASSWORD; // Gmail app-wachtwoord, geen normaal wachtwoord

const mailer = EMAIL_USER && EMAIL_APP_PASSWORD
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: EMAIL_USER, pass: EMAIL_APP_PASSWORD },
    })
  : null;

// Eerste account aanmaken als de tabel nog leeg is
function seedEersteAccount() {
  const aantal = db.prepare("SELECT COUNT(*) AS n FROM accounts").get().n;
  if (aantal > 0) return;
  const username = process.env.SEED_USERNAME;
  const wachtwoord = process.env.SEED_PASSWORD;
  if (!username || !wachtwoord) return;
  const hash = bcrypt.hashSync(wachtwoord, 10);
  db.prepare("INSERT INTO accounts (username, password_hash, naam, rol, permissie) VALUES (?, ?, ?, ?, ?)")
    .run(username, hash, "Beheerder", "Directeur", "Admin");
  console.log(`Eerste account aangemaakt voor ${username}`);
}
seedEersteAccount();

async function stuurEmail(to, subject, html) {
  if (!mailer) {
    console.log(`[GEEN EMAIL_USER/EMAIL_APP_PASSWORD INGESTELD] Zou e-mail sturen naar ${to}: ${subject}\n${html}`);
    return;
  }
  try {
    await mailer.sendMail({ from: `"Maarsseveen Pechhulp" <${EMAIL_USER}>`, to, subject, html });
  } catch (e) {
    console.error("Fout bij versturen e-mail:", e.message);
  }
}

// --- Inloggen -----------------------------------------------------------

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const acc = db.prepare("SELECT * FROM accounts WHERE username = ?").get(username);
  if (!acc || !bcrypt.compareSync(password, acc.password_hash)) {
    return res.status(401).json({ error: "Gebruikersnaam of wachtwoord onjuist." });
  }
  res.json({ username: acc.username, naam: acc.naam, rol: acc.rol, permissie: acc.permissie });
});

// --- Nieuw account aanmaken (bv. via Gebruikers-paneel) -----------------

app.post("/api/accounts", (req, res) => {
  const { username, password, naam, rol, permissie, beheerderUsername } = req.body;
  if (!username || !password || !naam || !rol) {
    return res.status(400).json({ error: "Alle velden zijn verplicht." });
  }

  const beheerder = db.prepare("SELECT * FROM accounts WHERE username = ?").get(beheerderUsername);
  if (!beheerder || beheerder.permissie !== "Admin") {
    return res.status(403).json({ error: "Alleen Admin-accounts mogen nieuwe accounts aanmaken." });
  }

  const bestaat = db.prepare("SELECT 1 FROM accounts WHERE username = ?").get(username);
  if (bestaat) return res.status(409).json({ error: "Deze gebruikersnaam bestaat al." });

  const gekozenPermissie = permissie === "Admin" ? "Admin" : "Standaard";
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO accounts (username, password_hash, naam, rol, permissie) VALUES (?, ?, ?, ?, ?)").run(username, hash, naam, rol, gekozenPermissie);
  res.status(201).json({ username, naam, rol, permissie: gekozenPermissie });
});

app.get("/api/accounts", (req, res) => {
  const accounts = db.prepare("SELECT username, naam, rol, permissie FROM accounts").all();
  res.json(accounts);
});

app.delete("/api/accounts/:username", (req, res) => {
  const { username } = req.params;
  const { beheerderUsername } = req.body;

  const beheerder = db.prepare("SELECT * FROM accounts WHERE username = ?").get(beheerderUsername);
  if (!beheerder || beheerder.permissie !== "Admin") {
    return res.status(403).json({ error: "Alleen Admin-accounts mogen accounts verwijderen." });
  }
  if (username === beheerderUsername) {
    return res.status(400).json({ error: "Je kan je eigen account niet verwijderen." });
  }

  const bestaat = db.prepare("SELECT 1 FROM accounts WHERE username = ?").get(username);
  if (!bestaat) return res.status(404).json({ error: "Account niet gevonden." });

  db.prepare("DELETE FROM accounts WHERE username = ?").run(username);
  res.json({ verwijderd: username });
});

// --- Wachtwoord vergeten --------------------------------------------------

app.post("/api/forgot-password", async (req, res) => {
  const { username } = req.body;
  const acc = db.prepare("SELECT * FROM accounts WHERE username = ?").get(username);

  // Altijd hetzelfde antwoord, ook als het account niet bestaat —
  // zo kan niemand via deze route uitvinden welke accounts wel/niet bestaan.
  if (acc) {
    const token = crypto.randomBytes(32).toString("hex");
    const verlooptOp = Date.now() + 15 * 60 * 1000; // 15 minuten geldig
    db.prepare("INSERT INTO reset_tokens (token, username, verloopt_op) VALUES (?, ?, ?)").run(token, username, verlooptOp);

    const link = `${FRONTEND_URL}/#/reset-password?token=${token}`;
    await stuurEmail(
      username,
      "Wachtwoord resetten — Maarsseveen Pechhulp",
      `<p>Klik op onderstaande link om je wachtwoord te resetten. Deze link is 15 minuten geldig.</p>
       <p><a href="${link}">${link}</a></p>
       <p>Niet zelf aangevraagd? Dan kan je deze e-mail negeren.</p>`
    );
  }

  res.json({ message: "Als dit account bestaat, is er een e-mail verstuurd." });
});

app.post("/api/reset-password", (req, res) => {
  const { token, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Wachtwoord moet minstens 6 tekens zijn." });
  }

  const rij = db.prepare("SELECT * FROM reset_tokens WHERE token = ?").get(token);
  if (!rij || rij.verloopt_op < Date.now()) {
    return res.status(400).json({ error: "Deze link is ongeldig of verlopen. Vraag een nieuwe aan." });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE accounts SET password_hash = ? WHERE username = ?").run(hash, rij.username);
  db.prepare("DELETE FROM reset_tokens WHERE token = ?").run(token);

  res.json({ message: "Wachtwoord is aangepast." });
});

// --- Medewerkers ----------------------------------------------------------

app.get("/api/employees", checkApiKey, (req, res) => {
  res.json(db.prepare("SELECT * FROM employees").all());
});

app.post("/api/employees", checkApiKey, (req, res) => {
  const { discordId, naam, ingame, rol, opmerkingen } = req.body;
  if (!discordId || !naam || !rol || !roleInfo(rol) && rol !== "Extra Eenheid") {
    return res.status(400).json({ error: "discordId, naam en een geldige rol zijn verplicht." });
  }
  const bestaat = db.prepare("SELECT 1 FROM employees WHERE discord_id = ?").get(discordId);
  if (bestaat) return res.status(409).json({ error: "Deze medewerker staat al in het systeem." });

  const roepnummer = rol === "Extra Eenheid" ? null : nextRoepnummer(rol);
  db.prepare("INSERT INTO employees (discord_id, roepnummer, naam, ingame, rol, status, opmerkingen, strikes) VALUES (?, ?, ?, ?, ?, 'Actief', ?, 0)")
    .run(discordId, roepnummer, naam, ingame || naam, rol, opmerkingen || "");
  res.status(201).json(db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(discordId));
});

app.patch("/api/employees/:discordId", checkApiKey, (req, res) => {
  const { discordId } = req.params;
  const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(discordId);
  if (!emp) return res.status(404).json({ error: "Medewerker niet gevonden." });

  const { rol, status, opmerkingen, ingame, roepnummer, naam } = req.body;
  const nieuweRol = rol || emp.rol;
  const nieuweNaam = naam && naam.trim() ? naam.trim() : emp.naam;

  let nieuweRoepnummer = rol && rol !== emp.rol ? nextRoepnummer(nieuweRol, discordId) : emp.roepnummer;
  if (roepnummer !== undefined && roepnummer !== null && roepnummer !== "") {
    const bezet = db.prepare("SELECT 1 FROM employees WHERE roepnummer = ? AND discord_id != ?").get(roepnummer, discordId);
    if (bezet) return res.status(409).json({ error: `Roepnummer ${roepnummer} is al in gebruik.` });
    nieuweRoepnummer = roepnummer;
  }

  db.prepare("UPDATE employees SET rol = ?, roepnummer = ?, status = ?, opmerkingen = ?, ingame = ?, naam = ? WHERE discord_id = ?")
    .run(nieuweRol, nieuweRoepnummer, status || emp.status, opmerkingen ?? emp.opmerkingen, ingame ?? emp.ingame, nieuweNaam, discordId);
  res.json(db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(discordId));
});

app.delete("/api/employees/:discordId", checkApiKey, (req, res) => {
  const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(req.params.discordId);
  if (!emp) return res.status(404).json({ error: "Medewerker niet gevonden." });
  db.prepare("DELETE FROM employees WHERE discord_id = ?").run(req.params.discordId);
  res.json({ verwijderd: emp });
});

app.post("/api/employees/:discordId/promote", checkApiKey, (req, res) => {
  const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(req.params.discordId);
  if (!emp) return res.status(404).json({ error: "Medewerker niet gevonden." });
  const info = roleInfo(emp.rol);
  if (!info || info.tier >= 9) return res.status(400).json({ error: `${emp.naam} staat al op de hoogste rol.` });

  const { reden, door } = req.body;
  const naarRol = tierRole(info.tier + 1).naam;
  const roepnummer = nextRoepnummer(naarRol, emp.discord_id);
  db.prepare("UPDATE employees SET rol = ?, roepnummer = ?, status = 'Actief', strikes = 0 WHERE discord_id = ?").run(naarRol, roepnummer, emp.discord_id);
  db.prepare("INSERT INTO promotions (naam, van_rol, naar_rol, datum, door, reden) VALUES (?, ?, ?, ?, ?, ?)")
    .run(emp.naam, emp.rol, naarRol, new Date().toLocaleDateString("nl-NL"), door || "Onbekend", reden || "Handmatige promotie");
  res.json(db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(emp.discord_id));
});

app.post("/api/employees/:discordId/demote", checkApiKey, (req, res) => {
  const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(req.params.discordId);
  if (!emp) return res.status(404).json({ error: "Medewerker niet gevonden." });
  const info = roleInfo(emp.rol);
  if (!info || info.tier <= 1) return res.status(400).json({ error: `${emp.naam} staat al op de laagste rol.` });

  const { reden, door } = req.body;
  const naarRol = tierRole(info.tier - 1).naam;
  const roepnummer = nextRoepnummer(naarRol, emp.discord_id);
  db.prepare("UPDATE employees SET rol = ?, roepnummer = ? WHERE discord_id = ?").run(naarRol, roepnummer, emp.discord_id);
  db.prepare("INSERT INTO promotions (naam, van_rol, naar_rol, datum, door, reden) VALUES (?, ?, ?, ?, ?, ?)")
    .run(emp.naam, emp.rol, naarRol, new Date().toLocaleDateString("nl-NL"), door || "Onbekend", reden || "Handmatige demotie");
  res.json(db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(emp.discord_id));
});

// --- Promoties (geschiedenis) ---------------------------------------------

app.get("/api/promotions", checkApiKey, (req, res) => {
  res.json(db.prepare("SELECT * FROM promotions ORDER BY id DESC").all());
});

// --- Tijden verwerken (plak-lijst -> voorstel -> doorvoeren) ---------------

function parseTijdString(str) {
  const uurM = str.match(/(\d+)\s*uur/);
  const minM = str.match(/(\d+)\s*minuten?/);
  const secM = str.match(/(\d+)\s*seconden?/);
  const uur = uurM ? parseInt(uurM[1], 10) : 0;
  const min = minM ? parseInt(minM[1], 10) : 0;
  const sec = secM ? parseInt(secM[1], 10) : 0;
  return uur + min / 60 + sec / 3600;
}

function berekenActies(tekst) {
  const regex = /<@(\d+)>\s*\(id:(\d+)\)\s*Totale tijd:\s*([^\n<]+)/g;
  const acties = [];
  let winnaar = null;
  let match;

  while ((match = regex.exec(tekst)) !== null) {
    const discordId = match[2];
    const uren = parseTijdString(match[3]);
    const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(discordId);
    if (!emp) continue;
    if (emp.status === "Afwezig") continue; // afwezige medewerkers worden niet meegenomen

    if (MONTEUR_VARIANTEN.includes(emp.rol)) {
      if (!winnaar || uren > winnaar.uren) winnaar = { naam: emp.naam, uren, discordId };
    }

    if (uren < 5) {
      acties.push({ discordId, naam: emp.naam, uren, type: emp.strikes >= 1 ? "ontslag" : "inactief", vanRol: emp.rol });
      continue;
    }
    const info = roleInfo(emp.rol);
    if (!info || info.tier === 9) {
      acties.push({ discordId, naam: emp.naam, uren, type: !info ? "buiten-ladder" : "plafond", vanRol: emp.rol });
      continue;
    }

    const stappen = uren >= 20 ? 2 : uren >= 10 ? 1 : 0;
    if (stappen === 0) {
      acties.push({ discordId, naam: emp.naam, uren, type: "geen", vanRol: emp.rol });
      continue;
    }
    const nieuweTier = Math.min(info.tier + stappen, AUTO_PROMOTIE_PLAFOND);
    if (nieuweTier <= info.tier) {
      acties.push({ discordId, naam: emp.naam, uren, type: "plafond", vanRol: emp.rol });
      continue;
    }

    acties.push({ discordId, naam: emp.naam, uren, type: "promotie", vanRol: emp.rol, naarRol: tierRole(nieuweTier).naam });
  }

  return { acties, winnaar };
}

app.post("/api/tijden/preview", checkApiKey, (req, res) => {
  const { tekst } = req.body;
  if (!tekst) return res.status(400).json({ error: "tekst is verplicht." });
  res.json(berekenActies(tekst));
});

app.post("/api/tijden/execute", checkApiKey, (req, res) => {
  const { acties, door, ontslagLabel, winnaar } = req.body;
  if (!Array.isArray(acties)) return res.status(400).json({ error: "acties (array) is verplicht." });

  const runInsert = db.prepare("INSERT INTO tijden_runs (datum, medewerkers_met_promotie, uren_gehaald, uren_niet_gehaald) VALUES (?, 0, 0, 0)").run(Date.now());
  const runId = runInsert.lastInsertRowid;

  let metPromotie = 0, gehaald = 0, nietGehaald = 0;
  const verslag = [];

  for (const a of acties) {
    const emp = db.prepare("SELECT * FROM employees WHERE discord_id = ?").get(a.discordId);
    if (!emp) continue;

    if (a.type === "ontslag") {
      db.prepare("DELETE FROM employees WHERE discord_id = ?").run(a.discordId);
      nietGehaald++;
      verslag.push({ ...a, resultaat: `${ontslagLabel || "Ontslagen"} (te weinig uren, 2e keer)` });
    } else if (a.type === "inactief") {
      db.prepare("UPDATE employees SET status = 'Inactief', strikes = strikes + 1 WHERE discord_id = ?").run(a.discordId);
      nietGehaald++;
      verslag.push({ ...a, resultaat: "Inactief gezet" });
    } else if (a.type === "promotie") {
      const roepnummer = nextRoepnummer(a.naarRol, a.discordId);
      db.prepare("UPDATE employees SET rol = ?, roepnummer = ?, status = 'Actief', strikes = 0 WHERE discord_id = ?").run(a.naarRol, roepnummer, a.discordId);
      db.prepare("INSERT INTO promotions (naam, van_rol, naar_rol, datum, door, reden, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(a.naam, a.vanRol, a.naarRol, new Date().toLocaleDateString("nl-NL"), door || "Systeem", `${a.uren.toFixed(1)} uur gewerkt`, runId);
      metPromotie++;
      verslag.push({ ...a, resultaat: `${a.vanRol} -> ${a.naarRol}` });
    } else if (a.type === "geen" || a.type === "plafond") {
      gehaald++;
    }
  }

  db.prepare("UPDATE tijden_runs SET medewerkers_met_promotie = ?, uren_gehaald = ?, uren_niet_gehaald = ? WHERE id = ?")
    .run(metPromotie, gehaald, nietGehaald, runId);

  // Automatische "monteur van de week" alleen bijwerken als er nog geen handmatige keuze staat
  const huidigeWinnaar = db.prepare("SELECT * FROM week_winner WHERE id = 1").get();
  if (winnaar && (!huidigeWinnaar || !huidigeWinnaar.handmatig)) {
    db.prepare("INSERT INTO week_winner (id, discord_id, naam, uren, handmatig) VALUES (1, ?, ?, ?, 0) ON CONFLICT(id) DO UPDATE SET discord_id=excluded.discord_id, naam=excluded.naam, uren=excluded.uren, handmatig=0")
      .run(winnaar.discordId, winnaar.naam, winnaar.uren);
  }

  res.json({ verslag, runId });
});

// --- Runs (verwerkingsrondes van "Medewerkers tijden") -------------------

app.get("/api/runs", checkApiKey, (req, res) => {
  const runs = db.prepare("SELECT * FROM tijden_runs ORDER BY id DESC").all();
  const metDetails = runs.map((run) => ({
    ...run,
    details: db.prepare("SELECT * FROM promotions WHERE run_id = ? ORDER BY id ASC").all(run.id),
  }));
  res.json(metDetails);
});

// --- Monteur van de week ---------------------------------------------------

app.get("/api/week-winner", checkApiKey, (req, res) => {
  const winner = db.prepare("SELECT * FROM week_winner WHERE id = 1").get();
  res.json(winner || null);
});

app.post("/api/week-winner", checkApiKey, (req, res) => {
  const { discordId, naam } = req.body;
  if (!discordId || !naam) return res.status(400).json({ error: "discordId en naam zijn verplicht." });
  db.prepare("INSERT INTO week_winner (id, discord_id, naam, uren, handmatig) VALUES (1, ?, ?, NULL, 1) ON CONFLICT(id) DO UPDATE SET discord_id=excluded.discord_id, naam=excluded.naam, uren=NULL, handmatig=1")
    .run(discordId, naam);
  res.json(db.prepare("SELECT * FROM week_winner WHERE id = 1").get());
});

app.get("/", (req, res) => res.send("Maarsseveen Pechhulp auth-backend draait."));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Auth-backend draait op poort ${PORT}`));
