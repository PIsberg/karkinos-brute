// Generates a deterministic PrivateBin v2 known-answer test vector using Node's
// WebCrypto — the SAME Web Crypto API PrivateBin's browser code uses. This is an
// INDEPENDENT oracle for tests/fixtures/privatebin_v2_gcm.json: if our Rust
// decrypts what node encrypted, the Rust matches PrivateBin's crypto.
//
// Format (PrivateBin v2, see wiki "Encryption format"):
//   paste_passphrase = paste_key(32 bytes) || utf8(password)
//   kdf_key = PBKDF2-HMAC-SHA256(paste_passphrase, salt=8B, iter, dkLen=keysize/8)
//   ct = AES-256-GCM(message, kdf_key, iv=16B, aad=utf8(JSON.stringify(adata)), tag=128b)
//   adata = [[b64(iv), b64(salt), iter, keysize, tagbits, "aes","gcm",compression],
//            formatter, opendiscussion, burnafterreading]
//
// Run: node scripts/privatebin_vector.mjs
import { webcrypto as crypto } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

const b64 = (u8) => Buffer.from(u8).toString('base64');
// Minimal base58 (Bitcoin alphabet) encode for the URL key.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (const b of bytes) { if (b === 0) out += '1'; else break; }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

async function makeVector({ key, password, plaintext, iter, compression }) {
  // Deterministic IV/salt so the fixture is stable (real pastes randomize these).
  const iv = new Uint8Array(16).map((_, i) => (i * 7 + 1) & 0xff);
  const salt = new Uint8Array(8).map((_, i) => (i * 31 + 5) & 0xff);
  const keysize = 256, tagbits = 128;

  // paste_key || password  (byte concatenation)
  const pwBytes = new TextEncoder().encode(password);
  const kdfInput = new Uint8Array(key.length + pwBytes.length);
  kdfInput.set(key, 0);
  kdfInput.set(pwBytes, key.length);

  const baseKey = await crypto.subtle.importKey('raw', kdfInput, 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: keysize },
    false,
    ['encrypt']
  );

  const adata = [
    [b64(iv), b64(salt), iter, keysize, tagbits, 'aes', 'gcm', compression],
    'plaintext', 0, 0,
  ];
  const aad = new TextEncoder().encode(JSON.stringify(adata));
  // PrivateBin v2 'zlib' compression is actually RAW deflate (no zlib header) —
  // matching pako.deflateRaw in the browser. 'none' = raw inner JSON bytes.
  const inner = new TextEncoder().encode(plaintext);
  const message = compression === 'zlib' ? deflateRawSync(inner) : inner;
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: tagbits },
    aesKey,
    message
  );

  return {
    answer: { keyBase58: base58(key), password, plaintext },
    paste: { status: 0, v: 2, adata, ct: b64(new Uint8Array(ctBuf)) },
  };
}

// 32-byte paste key, fixed for determinism.
const key = new Uint8Array(32).map((_, i) => (i * 11 + 3) & 0xff);
const vec = await makeVector({
  key,
  password: 'hunter2',
  // PrivateBin's inner message is JSON: {"paste": "<text>"}.
  plaintext: JSON.stringify({ paste: 'the privatebin secret' }),
  iter: 100000,
  compression: 'zlib',
});

console.log(JSON.stringify(vec, null, 2));
