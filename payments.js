// Transactions, platform settings, audit log. Withdrawals hold funds when requested,
// then either pay out (M-Pesa B2C) or refund if rejected/failed.
const bcrypt = require("bcryptjs"), mpesa = require("./mpesa");

module.exports = (db, api, { wrap, positive, one, superOnly }) => {
  const addCol = (t, c, d) => { try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${d}`); } catch {} }; // no-op if it exists
  addCol("admins", "role", "TEXT DEFAULT 'superadmin'");
  addCol("users", "password", "TEXT");
  addCol("products", "image", "TEXT");
  [["fee", "REAL DEFAULT 0"], ["checkout_id", "TEXT"], ["receipt", "TEXT"], ["note", "TEXT"]].forEach(([c, d]) => addCol("transactions", c, d));

  db.exec("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value REAL)");
  const DEF = { maintenance_mode: 0, signups_enabled: 1, deposits_enabled: 1, withdrawals_enabled: 1, auto_approve_withdrawals: 0,
    min_deposit: 10, min_withdrawal: 50, max_withdrawal: 150000, withdrawal_fee_pct: 0 };
  for (const [k, v] of Object.entries(DEF)) db.prepare("INSERT OR IGNORE INTO settings VALUES(?,?)").run(k, v);
  const settings = () => Object.fromEntries(db.prepare("SELECT key, value FROM settings").all().map(r => [r.key, r.value]));

  const createTx = db.transaction((user_id, type, amount, method, reference) => {
    const u = one("SELECT * FROM users WHERE id=?", user_id);
    if (!u) throw new Error("User not found");
    if (u.status !== "active") throw new Error("Account is not active");
    let fee = 0;
    if (type === "withdrawal") {
      fee = Math.round(amount * settings().withdrawal_fee_pct) / 100;
      if (u.balance < amount + fee) throw new Error("Insufficient balance");
      db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount + fee, user_id); // held until settled
    }
    return db.prepare("INSERT INTO transactions(user_id,type,amount,fee,method,reference) VALUES(?,?,?,?,?,?)").run(user_id, type, amount, fee, method, reference).lastInsertRowid;
  });

  // status: approved | rejected | failed. Only pending/processing transactions can be settled.
  const finish = db.transaction((id, status, receipt = null, note = null) => {
    const t = one("SELECT * FROM transactions WHERE id=?", id);
    if (!t) throw new Error("Transaction not found");
    if (!["pending", "processing"].includes(t.status)) throw new Error(`Already ${t.status}`);
    const ok = status === "approved";
    if (t.type === "deposit" && ok) db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(t.amount, t.user_id);
    if (t.type === "withdrawal") {
      if (ok) db.prepare("UPDATE platform_wallets SET balance=balance+? WHERE type='service'").run(t.fee); // fee income
      else db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(t.amount + t.fee, t.user_id);   // refund the hold
    }
    db.prepare("UPDATE transactions SET status=?, receipt=COALESCE(?,receipt), note=? WHERE id=?").run(status, receipt, note, id);
    return t;
  });

  const payout = async id => {
    const t = one("SELECT t.*, u.phone FROM transactions t JOIN users u ON u.id=t.user_id WHERE t.id=?", id);
    if (!db.prepare("UPDATE transactions SET status='processing' WHERE id=? AND status='pending'").run(id).changes) throw new Error("Already processed");
    try {
      const r = await mpesa.b2c(t.phone, t.amount, `W${id}`);
      db.prepare("UPDATE transactions SET checkout_id=? WHERE id=?").run(r.OriginatorConversationID, id); // result arrives via callback
    } catch (e) { finish(id, "failed", null, e.message); }
  };

  api.get("/transactions", wrap((q, s) => s.json(q.query.status
    ? db.prepare("SELECT * FROM transactions WHERE status=? ORDER BY id DESC LIMIT 500").all(q.query.status)
    : db.prepare("SELECT * FROM transactions ORDER BY id DESC LIMIT 500").all())));
  api.post("/transactions", wrap((q, s) => {
    const type = q.body.type;
    if (!["deposit", "withdrawal"].includes(type)) throw new Error("Type must be deposit or withdrawal");
    const method = q.body.method === "mpesa" ? "mpesa" : "manual";
    s.status(201).json({ id: createTx(q.body.user_id, type, positive(q.body.amount), method, q.body.reference) });
  }));
  // Approving an M-Pesa withdrawal sends the payout; anything else settles immediately.
  api.post("/transactions/:id/:action(approve|reject)", wrap(async (q, s) => {
    const t = one("SELECT * FROM transactions WHERE id=?", q.params.id);
    if (!t) throw new Error("Transaction not found");
    if (q.params.action === "approve" && t.type === "withdrawal" && t.method === "mpesa") await payout(t.id);
    else finish(t.id, q.params.action === "approve" ? "approved" : "rejected");
    s.json({ ok: true });
  }));

  api.get("/settings", wrap((q, s) => s.json(settings())));
  api.put("/settings", superOnly, wrap((q, s) => {
    for (const k of Object.keys(DEF)) if (q.body[k] !== undefined) {
      const v = Number(q.body[k]); if (!Number.isFinite(v) || v < 0) throw new Error(`Invalid value for ${k.replace(/_/g, " ")}`);
      db.prepare("UPDATE settings SET value=? WHERE key=?").run(v, k);
    }
    s.json(settings());
  }));
  api.get("/audit-log", wrap((q, s) => s.json(db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").all())));
  api.post("/users/:id/reset-password", wrap((q, s) => {
    if (!q.body.password || q.body.password.length < 8) throw new Error("Password must be 8+ characters");
    db.prepare("UPDATE users SET password=? WHERE id=?").run(bcrypt.hashSync(q.body.password, 10), q.params.id);
    s.json({ ok: true });
  }));

  return { settings, createTx, finish, payout };
};
