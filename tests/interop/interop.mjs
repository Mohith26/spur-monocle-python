// Usage:
//   node interop.mjs jwe                      -> prints {pem, token, payload} made with jose (ECDH-ES + A256GCM)
//   node interop.mjs cookie-make <ip> <hex>   -> prints an MCLVALID value built like Spur's Express middleware
//   node interop.mjs cookie-check <value> <ip> <hex> -> prints true/false, validated like Spur's Express middleware
import crypto from "node:crypto";
import * as jose from "jose";

const [cmd, ...args] = process.argv.slice(2);

if (cmd === "jwe") {
  const { publicKey, privateKey } = await jose.generateKeyPair("ECDH-ES", { crv: "P-256", extractable: true });
  const payload = { vpn: true, proxied: false, anon: true, rdp: false, dch: false, cc: "NL", ip: "203.0.113.7",
    ipv6: "", ts: new Date().toISOString(), complete: true, id: "jose-1", sid: "interop", service: "NORD_VPN" };
  const token = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
    .encrypt(publicKey);
  console.log(JSON.stringify({ pem: await jose.exportPKCS8(privateKey), token, payload }));
} else if (cmd === "jwe-decrypt") {
  // args: <pkcs8 pem (base64)> <token>
  const key = await jose.importPKCS8(Buffer.from(args[0], "base64").toString(), "ECDH-ES");
  const { plaintext } = await jose.compactDecrypt(args[1], key);
  console.log(new TextDecoder().decode(plaintext));
} else if (cmd === "cookie-make") {
  const [ip, secretHex] = args;
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(secretHex, "hex"), iv);
  const enc = Buffer.concat([cipher.update(`${ip}|${expiry}`, "utf8"), cipher.final()]);
  console.log(`${iv.toString("hex")}.${enc.toString("hex")}.${cipher.getAuthTag().toString("hex")}`);
} else if (cmd === "cookie-check") {
  const [value, ip, secretHex] = args;
  const [ivHex, encHex, tagHex] = value.split(".");
  try {
    const d = crypto.createDecipheriv("aes-256-gcm", Buffer.from(secretHex, "hex"), Buffer.from(ivHex, "hex"));
    d.setAuthTag(Buffer.from(tagHex, "hex"));
    const plain = d.update(encHex, "hex", "utf8") + d.final("utf8");
    const [cookieIp, expiry] = plain.split("|");
    console.log(String(cookieIp === ip && Math.floor(Date.now() / 1000) < parseInt(expiry, 10)));
  } catch {
    console.log("false");
  }
} else {
  console.error("unknown command");
  process.exit(2);
}
