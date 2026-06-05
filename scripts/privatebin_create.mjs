// Creates a REAL password-protected paste on a PrivateBin instance and prints
// the share URL + the password, so we can smoke-test cracking end to end.
// Uses Node WebCrypto, matching PrivateBin's browser crypto.
//
// Usage: node scripts/privatebin_create.mjs [server] [password] [secret]
import { webcrypto as crypto } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

const server = process.argv[2] || 'https://privatebin.net/';
const password = process.argv[3] || '1234';
const secret = process.argv[4] || 'live smoke-test secret';

const b64 = (u8) => Buffer.from(u8).toString('base64');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8; digits[i] = carry % 58; carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (const b of bytes) { if (b === 0) out += '1'; else break; }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(16));
const salt = crypto.getRandomValues(new Uint8Array(8));
const iter = 100000, keysize = 256, tagbits = 128;

const pw = new TextEncoder().encode(password);
const kdfInput = new Uint8Array(key.length + pw.length);
kdfInput.set(key, 0); kdfInput.set(pw, key.length);
const baseKey = await crypto.subtle.importKey('raw', kdfInput, 'PBKDF2', false, ['deriveKey']);
const aesKey = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
  baseKey, { name: 'AES-GCM', length: keysize }, false, ['encrypt']);

const adata = [
  [b64(iv), b64(salt), iter, keysize, tagbits, 'aes', 'gcm', 'zlib'],
  'plaintext', 0, 0, // formatter, opendiscussion, burnafterreading=0
];
const aad = new TextEncoder().encode(JSON.stringify(adata));
const message = deflateRawSync(new TextEncoder().encode(JSON.stringify({ paste: secret })));
const ctBuf = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv, additionalData: aad, tagLength: tagbits }, aesKey, message);

const body = JSON.stringify({ v: 2, adata, ct: b64(new Uint8Array(ctBuf)), meta: { expire: '5min' } });
const res = await fetch(server, {
  method: 'POST',
  headers: { 'X-Requested-With': 'JSONHttpRequest', 'Content-Type': 'application/json' },
  body,
});
const json = await res.json();
if (json.status !== 0) { console.error('create failed:', json); process.exit(1); }

const origin = server.replace(/\/$/, '');
console.log(JSON.stringify({
  shareUrl: `${origin}/?${json.id}#${base58(key)}`,
  id: json.id,
  password,
  secret,
}, null, 2));
