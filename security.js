// Security headers, in-memory rate limiting, and the admin audit log
exports.headers = (q, s, n) => {
  s.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=15552000",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'" });
  n();
};
exports.limiter = (max, windowMs) => {
  const hits = new Map();
  setInterval(() => { const t = Date.now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); }, windowMs).unref();
  return (q, s, n) => {
    const now = Date.now(); let h = hits.get(q.ip);
    if (!h || h.reset < now) { h = { c: 0, reset: now + windowMs }; hits.set(q.ip, h); }
    if (++h.c > max) { s.set("Retry-After", Math.ceil((h.reset - now) / 1000)); return s.status(429).json({ error: "Too many requests, try again later" }); }
    n();
  };
};
exports.audit = db => {
  db.exec("CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, admin_id INTEGER, admin_name TEXT, method TEXT, path TEXT, detail TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)");
  return (q, s, n) => {
    if (q.method !== "GET") s.on("finish", () => {
      if (s.statusCode >= 400) return;
      const b = { ...q.body }; delete b.password;
      db.prepare("INSERT INTO audit_log(admin_id,admin_name,method,path,detail,ip) VALUES(?,?,?,?,?,?)")
        .run(q.admin.id, q.admin.name, q.method, q.originalUrl, JSON.stringify(b).slice(0, 500), q.ip);
    });
    n();
  };
};
