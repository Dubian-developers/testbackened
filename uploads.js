// Product images: raw image upload, stored on disk next to the database (so it persists on a Render disk)
const express = require("express"), fs = require("fs"), path = require("path"), crypto = require("crypto");

module.exports = (db, api, { wrap, one }) => {
  const DIR = process.env.UPLOAD_DIR || path.join(path.dirname(path.resolve(process.env.DB_PATH || "data.db")), "uploads");
  fs.mkdirSync(DIR, { recursive: true });
  const rm = img => img && fs.rm(path.join(DIR, path.basename(img)), { force: true }, () => {});
  // Identify the real format from the file's first bytes, not from what the client claims
  const kind = b => b.length < 12 ? null
    : b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF ? "jpg"
    : b[0] === 0x89 && b.toString("latin1", 1, 4) === "PNG" ? "png"
    : b.toString("latin1", 0, 4) === "RIFF" && b.toString("latin1", 8, 12) === "WEBP" ? "webp" : null;

  api.post("/products/:id/image", express.raw({ type: ["image/jpeg", "image/png", "image/webp"], limit: "5mb" }), wrap((q, s) => {
    const p = one("SELECT * FROM products WHERE id=?", q.params.id);
    if (!p) throw new Error("Product not found");
    const ext = Buffer.isBuffer(q.body) && kind(q.body);
    if (!ext) throw new Error("Upload a JPEG, PNG or WebP image under 5 MB");
    const name = `${p.id}-${crypto.randomBytes(6).toString("hex")}.${ext}`;
    fs.writeFileSync(path.join(DIR, name), q.body);
    db.prepare("UPDATE products SET image=? WHERE id=?").run("/uploads/" + name, p.id);
    rm(p.image); // replace, don't pile up old files
    s.json({ image: "/uploads/" + name });
  }));
  // Runs before the generic delete so the file goes with the product
  api.delete("/products/:id", (q, s, n) => { rm(one("SELECT image FROM products WHERE id=?", q.params.id)?.image); n(); });
  return DIR;
};
