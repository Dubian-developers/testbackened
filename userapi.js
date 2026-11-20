// Public API for end users / mobile apps (/v1) and Safaricom callbacks (/mpesa)
const express = require("express"), bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken"), mpesa = require("./mpesa");

module.exports = (db, { settings, createTx, finish, payout }, { wrap, positive, one, limiter, SECRET }) => {
  const USER_SECRET = SECRET + ":user"; // user tokens can never pass admin auth
  const sign = id => jwt.sign({ uid: id }, USER_SECRET, { expiresIn: "30d" });
  const auth = (q, s, n) => { try { q.uid = jwt.verify((q.headers.authorization || "").slice(7), USER_SECRET).uid; n(); } catch { s.status(401).json({ error: "Unauthorized" }); } };
  const whole = v => { const n = positive(v); if (!Number.isInteger(n)) throw new Error("Amount must be a whole number of KES"); return n; };

  const u = express.Router(), strict = limiter(10, 15 * 60_000);
  u.use((q, s, n) => settings().maintenance_mode ? s.status(503).json({ error: "Down for maintenance, please try again soon" }) : n());

  u.post("/auth/register", strict, wrap((q, s) => {
    if (!settings().signups_enabled) throw new Error("Sign-ups are closed");
    const { name, password, email } = q.body, phone = mpesa.phone(q.body.phone);
    if (!name || !password || password.length < 8) throw new Error("Name and a password of 8+ characters are required");
    if (one("SELECT 1 FROM users WHERE phone=?", phone)) throw new Error("This phone number is already registered");
    const id = db.prepare("INSERT INTO users(name,phone,email,password) VALUES(?,?,?,?)").run(name, phone, email, bcrypt.hashSync(password, 10)).lastInsertRowid;
    s.status(201).json({ token: sign(id) });
  }));
  u.post("/auth/login", strict, wrap((q, s) => {
    const user = one("SELECT * FROM users WHERE phone=?", mpesa.phone(q.body.phone));
    if (!user || !user.password || !bcrypt.compareSync(q.body.password || "", user.password)) return s.status(401).json({ error: "Invalid phone or password" });
    if (user.status !== "active") return s.status(403).json({ error: "Account suspended" });
    s.json({ token: sign(user.id) });
  }));

  u.use(auth);
  u.get("/me", wrap((q, s) => s.json(one("SELECT id,name,phone,email,balance,status FROM users WHERE id=?", q.uid))));
  u.get("/products", wrap((q, s) => s.json(db.prepare("SELECT id,name,price,stock,image FROM products WHERE active=1").all())));
  u.get("/transactions", wrap((q, s) => s.json(db.prepare("SELECT id,type,amount,fee,method,receipt,status,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 100").all(q.uid))));

  // Deposit: STK push to the user's phone; the balance is credited when the callback confirms payment
  u.post("/deposits", wrap(async (q, s) => {
    const st = settings(), amount = whole(q.body.amount);
    if (!st.deposits_enabled) throw new Error("Deposits are paused");
    if (amount < st.min_deposit) throw new Error(`Minimum deposit is KES ${st.min_deposit}`);
    const id = createTx(q.uid, "deposit", amount, "mpesa", null);
    try {
      const r = await mpesa.stkPush(one("SELECT phone FROM users WHERE id=?", q.uid).phone, amount, `D${id}`);
      db.prepare("UPDATE transactions SET checkout_id=? WHERE id=?").run(r.CheckoutRequestID, id);
      s.status(201).json({ id, message: "Check your phone and enter your M-Pesa PIN" });
    } catch (e) { finish(id, "failed", null, e.message); throw e; }
  }));

  // Withdrawal: funds are held now; paid out on admin approval (or instantly if auto-approve is on)
  u.post("/withdrawals", wrap(async (q, s) => {
    const st = settings(), amount = whole(q.body.amount);
    if (!st.withdrawals_enabled) throw new Error("Withdrawals are paused");
    if (amount < st.min_withdrawal || amount > st.max_withdrawal) throw new Error(`Withdrawals must be between KES ${st.min_withdrawal} and KES ${st.max_withdrawal}`);
    const id = createTx(q.uid, "withdrawal", amount, "mpesa", null);
    if (st.auto_approve_withdrawals) await payout(id);
    s.status(201).json({ id, status: one("SELECT status FROM transactions WHERE id=?", id).status });
  }));

  u.post("/orders", wrap((q, s) => {
    const qty = Math.max(1, parseInt(q.body.qty) || 1);
    const id = db.transaction(() => {
      const me = one("SELECT * FROM users WHERE id=?", q.uid), p = one("SELECT * FROM products WHERE id=? AND active=1", q.body.product_id);
      if (me.status !== "active") throw new Error("Account is not active");
      if (!p || p.stock < qty) throw new Error("Product unavailable or out of stock");
      let total = p.price * qty;
      if (q.body.coupon) {
        const c = one("SELECT * FROM coupons WHERE code=? AND active=1", q.body.coupon);
        if (!c || (c.max_uses && c.used >= c.max_uses)) throw new Error("Invalid or used-up coupon");
        total = Math.round(total * Math.max(0, 100 - c.discount_pct)) / 100;
        db.prepare("UPDATE coupons SET used=used+1 WHERE id=?").run(c.id);
      }
      if (me.balance < total) throw new Error("Insufficient balance");
      db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(total, me.id);
      db.prepare("UPDATE products SET stock=stock-? WHERE id=?").run(qty, p.id);
      return db.prepare("INSERT INTO orders(user_id,product_id,qty,total,status) VALUES(?,?,?,?,'paid')").run(me.id, p.id, qty, total).lastInsertRowid;
    })();
    s.status(201).json({ id });
  }));

  // ---- Safaricom callbacks: the secret in the URL is the only authentication Daraja allows
  const cb = express.Router(), ack = s => s.json({ ResultCode: 0, ResultDesc: "Accepted" });
  const guard = (q, s, n) => q.params.secret && q.params.secret === process.env.MPESA_CALLBACK_SECRET ? n() : s.sendStatus(403);
  const byCheckout = id => one("SELECT * FROM transactions WHERE checkout_id=?", id);

  cb.post("/stk/:secret", guard, (q, s) => {
    try {
      const c = q.body.Body.stkCallback, t = byCheckout(c.CheckoutRequestID);
      if (t && t.status === "pending") {
        const m = Object.fromEntries((c.CallbackMetadata?.Item || []).map(i => [i.Name, i.Value]));
        if (c.ResultCode !== 0) finish(t.id, "failed", null, c.ResultDesc);
        else if (Number(m.Amount) !== t.amount) db.prepare("UPDATE transactions SET note=? WHERE id=?").run(`Amount mismatch: paid ${m.Amount}, expected ${t.amount}. Review manually.`, t.id);
        else finish(t.id, "approved", m.MpesaReceiptNumber);
      }
    } catch (e) { console.error("STK callback error:", e.message); }
    ack(s);
  });
  cb.post("/b2c/result/:secret", guard, (q, s) => {
    try {
      const r = q.body.Result, t = byCheckout(r.OriginatorConversationID);
      if (t && t.status === "processing") {
        const ok = Number(r.ResultCode) === 0, receipt = r.ResultParameters?.ResultParameter?.find(p => p.Key === "TransactionReceipt")?.Value;
        finish(t.id, ok ? "approved" : "failed", receipt, ok ? null : r.ResultDesc);
      }
    } catch (e) { console.error("B2C result error:", e.message); }
    ack(s);
  });
  // On timeout the payout stays "processing": confirm in the Daraja portal before refunding anyone
  cb.post("/b2c/timeout/:secret", guard, (q, s) => { console.warn("B2C timeout:", JSON.stringify(q.body)); ack(s); });

  return { userApi: u, callbacks: cb };
};
