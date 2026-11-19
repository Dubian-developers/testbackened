const express = require("express"), cors = require("cors"), Database = require("better-sqlite3");
const bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const db = new Database(process.env.DB_PATH || "data.db");
db.pragma("journal_mode = WAL");

// ---- Schema ---------------------------------------------------------------
// Resources that get plain CRUD endpoints: table -> column definitions
const R = {
  users: { name: "TEXT NOT NULL", phone: "TEXT UNIQUE", email: "TEXT", status: "TEXT DEFAULT 'active'", balance: "REAL DEFAULT 0" },
  products: { name: "TEXT NOT NULL", price: "REAL DEFAULT 0", stock: "INTEGER DEFAULT 0", active: "INTEGER DEFAULT 1" },
  orders: { user_id: "INTEGER", product_id: "INTEGER", qty: "INTEGER DEFAULT 1", total: "REAL DEFAULT 0", status: "TEXT DEFAULT 'pending'" },
  coupons: { code: "TEXT UNIQUE NOT NULL", discount_pct: "REAL DEFAULT 0", max_uses: "INTEGER DEFAULT 0", used: "INTEGER DEFAULT 0", active: "INTEGER DEFAULT 1" },
  incentives: { title: "TEXT NOT NULL", amount: "REAL DEFAULT 0", active: "INTEGER DEFAULT 1" },
  incentive_requests: { user_id: "INTEGER", incentive_id: "INTEGER", status: "TEXT DEFAULT 'pending'" },
  bonuses: { user_id: "INTEGER", amount: "REAL DEFAULT 0", reason: "TEXT" },
  rewards: { user_id: "INTEGER", title: "TEXT", points: "INTEGER DEFAULT 0" },
};
const READONLY = ["balance", "used"]; // changed only by the system, never by CRUD

for (const [t, c] of Object.entries(R))
  db.exec(`CREATE TABLE IF NOT EXISTS ${t}(id INTEGER PRIMARY KEY, ${Object.entries(c).map(([k, v]) => k + " " + v).join(", ")}, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
db.exec(`
  CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'superadmin', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS platform_wallets(type TEXT PRIMARY KEY, balance REAL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL, method TEXT, reference TEXT, status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  INSERT OR IGNORE INTO platform_wallets(type) VALUES ('payment'), ('service');
`);

if (!db.prepare("SELECT 1 FROM admins").get()) {
  const email = process.env.ADMIN_EMAIL || "admin@example.com", pw = process.env.ADMIN_PASSWORD || "admin123";
  db.prepare("INSERT INTO admins(name,email,password) VALUES(?,?,?)").run("Admin", email, bcrypt.hashSync(pw, 10));
  console.log(`Created first admin: ${email} (change the password via ADMIN_PASSWORD or the Admins page)`);
}

// ---- Helpers --------------------------------------------------------------
const one = (sql, ...p) => db.prepare(sql).get(...p);
const wrap = fn => (q, s) => { Promise.resolve().then(() => fn(q, s)).catch(e => s.status(400).json({ error: e.message })); };
const auth = (q, s, n) => {
  try { q.admin = jwt.verify((q.headers.authorization || "").slice(7), SECRET); n(); }
  catch { s.status(401).json({ error: "Unauthorized" }); }
};
const positive = v => { if (!(Number(v) > 0)) throw new Error("Amount must be greater than zero"); return Number(v); };

// ---- API ------------------------------------------------------------------
const { headers, limiter, audit } = require("./security");
const api = express.Router();
api.use(limiter(300, 60_000));

api.post("/auth/login", limiter(10, 15 * 60_000), wrap((q, s) => {
  const a = one("SELECT * FROM admins WHERE email=?", q.body.email);
  if (!a || !bcrypt.compareSync(q.body.password || "", a.password))
    return s.status(401).json({ error: "Invalid email or password" });
  s.json({ token: jwt.sign({ id: a.id, name: a.name, role: a.role }, SECRET, { expiresIn: "12h" }), name: a.name });
}));

api.use(auth);
// Roles: superadmin = everything; admin = everything except admins/platform wallets/audit log; support = read-only
const superOnly = (q, s, n) => q.admin.role === "superadmin" ? n() : s.status(403).json({ error: "Superadmin access required" });
api.use((q, s, n) => q.method !== "GET" && q.admin.role === "support" ? s.status(403).json({ error: "Your role is read-only" }) : n());
api.use(["/admins", "/wallets/platform", "/audit-log"], superOnly);
api.use(audit(db));

api.get("/dashboard", wrap((q, s) => {
  const sum = (type, mod) => one(
    `SELECT COALESCE(SUM(amount),0) v FROM transactions WHERE status='approved' AND type=? AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now','start of month'${mod})`, type).v;
  s.json({
    wallets: Object.fromEntries(db.prepare("SELECT * FROM platform_wallets").all().map(w => [w.type, w.balance])),
    totalBalance: one("SELECT COALESCE(SUM(balance),0) v FROM users").v,
    deposits: { month: sum("deposit", ""), last: sum("deposit", ",'-1 month'") },
    withdrawals: { month: sum("withdrawal", ""), last: sum("withdrawal", ",'-1 month'") },
    users: {
      total: one("SELECT COUNT(*) v FROM users").v,
      active: one("SELECT COUNT(DISTINCT user_id) v FROM transactions WHERE created_at >= datetime('now','-30 days')").v,
      today: one("SELECT COUNT(*) v FROM users WHERE date(created_at)=date('now')").v,
    },
    signups: db.prepare("SELECT strftime('%Y-%m',created_at) m, COUNT(*) c FROM users GROUP BY m ORDER BY m DESC LIMIT 12").all().reverse(),
    txCounts: db.prepare("SELECT type, status, COUNT(*) c FROM transactions GROUP BY type, status").all(),
    pending: one("SELECT COUNT(*) v FROM transactions WHERE status='pending'").v,
  });
}));

// Wallets
api.get("/wallets", wrap((q, s) => s.json({
  platform: db.prepare("SELECT * FROM platform_wallets").all(),
  users: db.prepare("SELECT id, name, phone, balance FROM users ORDER BY balance DESC LIMIT 500").all(),
})));
api.post("/wallets/topup", wrap((q, s) => {
  const amount = positive(q.body.amount);
  db.transaction(() => {
    if (!db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(amount, q.body.user_id).changes) throw new Error("User not found");
    db.prepare("INSERT INTO transactions(user_id,type,amount,method,status) VALUES(?,'deposit',?,'admin topup','approved')").run(q.body.user_id, amount);
  })();
  s.json({ ok: true });
}));
api.post("/wallets/platform", wrap((q, s) => {
  if (!Number.isFinite(Number(q.body.amount))) throw new Error("Invalid amount");
  if (!db.prepare("UPDATE platform_wallets SET balance=balance+? WHERE type=?").run(Number(q.body.amount), q.body.type).changes) throw new Error("Unknown wallet");
  s.json({ ok: true });
}));

const pay = require("./payments")(db, api, { wrap, positive, one, superOnly });

// Admins
api.get("/admins", wrap((q, s) => s.json(db.prepare("SELECT id,name,email,role,created_at FROM admins").all())));
api.post("/admins", wrap((q, s) => {
  const { name, email, password, role = "admin" } = q.body;
  if (!["superadmin", "admin", "support"].includes(role)) throw new Error("Invalid role");
  if (!email || !password || password.length < 8) throw new Error("Email and a password of 8+ characters are required");
  const r = db.prepare("INSERT INTO admins(name,email,password,role) VALUES(?,?,?,?)").run(name, email, bcrypt.hashSync(password, 10), role);
  s.status(201).json({ id: r.lastInsertRowid });
}));
api.delete("/admins/:id", wrap((q, s) => {
  if (Number(q.params.id) === q.admin.id) throw new Error("You can't delete your own account");
  db.prepare("DELETE FROM admins WHERE id=?").run(q.params.id); s.sendStatus(204);
}));

// Generic CRUD for everything in R
for (const [t, cols] of Object.entries(R)) {
  const f = Object.keys(cols).filter(c => !READONLY.includes(c));
  const pick = b => f.filter(c => b[c] !== undefined);
  api.get(`/${t}`, wrap((q, s) => s.json(db.prepare(`SELECT * FROM ${t} ORDER BY id DESC LIMIT 500`).all().map(({ password, ...r }) => r))));
  api.post(`/${t}`, wrap((q, s) => {
    const k = pick(q.body); if (!k.length) throw new Error("No fields provided");
    const r = db.prepare(`INSERT INTO ${t}(${k}) VALUES(${k.map(() => "?")})`).run(...k.map(c => q.body[c]));
    s.status(201).json({ id: r.lastInsertRowid });
  }));
  api.put(`/${t}/:id`, wrap((q, s) => {
    const k = pick(q.body); if (!k.length) throw new Error("No fields provided");
    db.prepare(`UPDATE ${t} SET ${k.map(c => c + "=?").join(",")} WHERE id=?`).run(...k.map(c => q.body[c]), q.params.id);
    s.json({ ok: true });
  }));
  api.delete(`/${t}/:id`, wrap((q, s) => { db.prepare(`DELETE FROM ${t} WHERE id=?`).run(q.params.id); s.sendStatus(204); }));
}

// ---- App ------------------------------------------------------------------
const app = express();
const { userApi, callbacks } = require("./userapi")(db, pay, { wrap, positive, one, limiter, SECRET });
app.set("trust proxy", 1); // behind Railway/other proxies, so rate limits see real client IPs
app.disable("x-powered-by");
app.use(headers);
app.use(cors(process.env.ALLOWED_ORIGINS ? { origin: process.env.ALLOWED_ORIGINS.split(",") } : {}));
app.use(express.json({ limit: "100kb" }));
app.get("/health", (q, s) => s.json({ ok: true }));
app.use("/mpesa", callbacks);
app.use("/v1", limiter(120, 60_000), userApi);
app.use("/api", api);
app.use(express.static(__dirname + "/public"));
app.get("/admin/*", (q, s) => s.sendFile(__dirname + "/public/index.html"));
app.listen(process.env.PORT || 3000, () => console.log("Admin running on port " + (process.env.PORT || 3000)));
