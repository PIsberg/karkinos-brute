// Creates a REAL password-protected share on a dele.to instance and prints the
// share URL (with the AES key in the #fragment) plus a ready-to-run online crack
// command, so we can smoke-test the (online) deleto target end to end against an
// instance we control.
//
// dele.to IS zero-knowledge for the value: the secret is AES-256-GCM-encrypted in
// THIS script (client-side), and only the ciphertext + IV are sent to the server.
// The key stays in the URL fragment. The optional password is checked server-side
// against base64(password+salt). There is no REST API — creation goes through the
// `createSecureShare` Next.js server action, whose build-specific id we discover
// from the client bundle.
//
// Intended for a self-hosted instance (the upstream docker-compose stack):
//   git clone https://github.com/dele-to/dele-to && cd dele-to && docker compose up --build
//   # app on http://localhost:3000  (SALT is unset → the default salt applies)
//
// Usage: node scripts/deleto_create.mjs [server] [password] [secret] [maxViews]
//   server     default http://localhost:3000
//   password   default 1234   (short so a smoke-test crack is quick)
//   secret     default "deleto self-host smoke test"
//   maxViews   default 10     (1..100)
//
// Requires Node 18+ (global fetch + Web Crypto).

const server = (process.argv[2] || 'http://localhost:3000').replace(/\/$/, '');
const password = process.argv[3] || '1234';
const secret = process.argv[4] || 'deleto self-host smoke test';
const maxViews = Number(process.argv[5] || '10');

const b64 = (buf) => Buffer.from(buf).toString('base64');

// --- client-side encryption, matching lib/crypto.ts -------------------------
const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
  'encrypt',
  'decrypt',
]);
const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key)); // 32 bytes
const iv = crypto.getRandomValues(new Uint8Array(12));
const ctBuf = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  key,
  new TextEncoder().encode(secret),
);
const encryptedContent = b64(new Uint8Array(ctBuf)); // ciphertext ‖ 16-byte GCM tag
const ivB64 = b64(iv);
const keyB64 = b64(rawKey); // goes in the URL #fragment

// --- invoke the createSecureShare server action -----------------------------
// Server-action ids are build-specific; discover them from the create page's
// client bundle, then POST the create payload to each until one succeeds (only
// createSecureShare accepts this object shape and returns { success, id }).
async function chunkUrls() {
  const html = await (await fetch(`${server}/create`)).text();
  const urls = new Set();
  const re = /\/_next\/static\/chunks\/[^"'\\\s]+\.js/g;
  let m;
  while ((m = re.exec(html))) urls.add(server + m[0]);
  return [...urls];
}

async function actionIds() {
  const ids = new Set();
  for (const u of await chunkUrls()) {
    try {
      const text = await (await fetch(u)).text();
      for (const m of text.matchAll(/[0-9a-f]{40}/g)) ids.add(m[0]);
    } catch {
      /* ignore a chunk that fails to fetch */
    }
  }
  return [...ids];
}

const payload = JSON.stringify([
  {
    title: 'karkinos deleto smoke test',
    encryptedContent,
    iv: ivB64,
    expirationTime: '24h',
    maxViews,
    requirePassword: true,
    password,
  },
]);

let id = null;
for (const action of await actionIds()) {
  const res = await fetch(`${server}/create`, {
    method: 'POST',
    headers: {
      'Next-Action': action,
      'Content-Type': 'text/plain;charset=UTF-8',
      Origin: server,
      Accept: 'text/x-component',
    },
    body: payload,
  });
  const text = await res.text();
  const line = text.split('\n').find((l) => l.includes('"success":true') && l.includes('"id"'));
  if (line) {
    id = JSON.parse(line.slice(line.indexOf('{'))).id;
    break;
  }
}

if (!id) {
  console.error('create failed: could not find the createSecureShare action / no id returned.');
  console.error('Is the server up at', server, 'and is this a dele.to instance?');
  process.exit(1);
}

const viewUrl = `${server}/view/${id}#${keyB64}`;
console.log(JSON.stringify({ viewUrl, id, password, secret, maxViews }, null, 2));
console.log('\n# Smoke-test the online crack (localhost: no rate-limit delay needed):');
console.log(
  `bruteforcer deleto online --url "${viewUrl}" --charset digits --max ${password.length} --delay-ms 0`,
);
