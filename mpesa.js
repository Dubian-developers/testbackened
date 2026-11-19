// Safaricom Daraja client: STK Push (deposits) and B2C (withdrawals)
const crypto = require("crypto"), fs = require("fs"), E = process.env;
const BASE = E.MPESA_ENV === "production" ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";
let tok = { v: null, exp: 0 };

async function token() {
  if (!E.MPESA_CONSUMER_KEY || !E.MPESA_CONSUMER_SECRET) throw new Error("M-Pesa is not configured");
  if (tok.v && Date.now() < tok.exp) return tok.v;
  const r = await fetch(`${BASE}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: "Basic " + Buffer.from(`${E.MPESA_CONSUMER_KEY}:${E.MPESA_CONSUMER_SECRET}`).toString("base64") } });
  if (!r.ok) throw new Error("M-Pesa authentication failed");
  const d = await r.json(); tok = { v: d.access_token, exp: Date.now() + (d.expires_in - 60) * 1000 };
  return tok.v;
}
async function post(path, body) {
  const r = await fetch(BASE + path, { method: "POST", headers: { Authorization: "Bearer " + await token(), "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || (d.ResponseCode && d.ResponseCode !== "0")) throw new Error(d.errorMessage || d.ResponseDescription || "M-Pesa request failed");
  return d;
}
// 0712345678 / 712345678 / +254712345678 -> 254712345678
exports.phone = p => {
  p = String(p || "").replace(/\D/g, "");
  if (/^0[17]\d{8}$/.test(p)) p = "254" + p.slice(1); else if (/^[17]\d{8}$/.test(p)) p = "254" + p;
  if (!/^254[17]\d{8}$/.test(p)) throw new Error("Enter a valid Kenyan phone number");
  return p;
};
const hook = name => `${E.PUBLIC_URL}/mpesa/${name}/${E.MPESA_CALLBACK_SECRET}`;
exports.stkPush = (ph, amount, ref) => {
  const ts = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  ph = exports.phone(ph);
  return post("/mpesa/stkpush/v1/processrequest", {
    BusinessShortCode: E.MPESA_SHORTCODE, Password: Buffer.from(E.MPESA_SHORTCODE + E.MPESA_PASSKEY + ts).toString("base64"), Timestamp: ts,
    TransactionType: E.MPESA_TXN_TYPE || "CustomerPayBillOnline", Amount: Math.round(amount), PartyA: ph, PartyB: E.MPESA_SHORTCODE, PhoneNumber: ph,
    CallBackURL: hook("stk"), AccountReference: ref, TransactionDesc: "Wallet deposit" });
};
const credential = () => E.MPESA_SECURITY_CREDENTIAL || crypto.publicEncrypt(
  { key: fs.readFileSync(E.MPESA_CERT_PATH), padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(E.MPESA_INITIATOR_PASSWORD)).toString("base64");
exports.b2c = (ph, amount, ref) => post("/mpesa/b2c/v1/paymentrequest", {
  InitiatorName: E.MPESA_INITIATOR_NAME, SecurityCredential: credential(), CommandID: "BusinessPayment", Amount: Math.round(amount),
  PartyA: E.MPESA_B2C_SHORTCODE || E.MPESA_SHORTCODE, PartyB: exports.phone(ph), Remarks: "Wallet withdrawal",
  QueueTimeOutURL: hook("b2c/timeout"), ResultURL: hook("b2c/result"), Occasion: ref });
