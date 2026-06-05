// Creates a REAL passphrase-protected push on a PasswordPusher instance and
// prints the push token + the ready-to-run crack command, so we can smoke-test
// the (online) pwpush target end to end against a server we control.
//
// PasswordPusher is NOT zero-knowledge: there is no client-side crypto here. We
// just POST the secret + passphrase to the server's create API; the server
// encrypts at rest and validates the passphrase server-side on retrieval.
//
// Intended for a self-hosted instance (the `pglombardo/pwpush` Docker image):
//   docker run -d -p 5100:5100 pglombardo/pwpush:latest
//
// Usage: node scripts/pwpush_create.mjs [server] [passphrase] [secret]
//   server      default http://localhost:5100
//   passphrase  default 1234   (keep it short so a smoke-test crack is quick)
//   secret      default "pwpush self-host smoke test"
//
// Requires Node 18+ (global fetch).

const server = (process.argv[2] || 'http://localhost:5100').replace(/\/$/, '');
const passphrase = process.argv[3] || '1234';
const secret = process.argv[4] || 'pwpush self-host smoke test';

const body = JSON.stringify({
  password: {
    payload: secret,
    passphrase,
    // Allow plenty of views: wrong guesses do NOT burn a view (the server
    // rejects them before counting), but a correct guess does. A high cap keeps
    // the push around for repeated testing.
    expire_after_views: 100,
    expire_after_days: 1,
  },
});

const res = await fetch(`${server}/p.json`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body,
});

if (!res.ok) {
  console.error(`create failed: HTTP ${res.status}`);
  console.error(await res.text());
  process.exit(1);
}

const json = await res.json();
const token = json.url_token;
if (!token) {
  console.error('create succeeded but no url_token in response:', json);
  process.exit(1);
}

const pushUrl = `${server}/p/${token}`;
console.log(JSON.stringify({ pushUrl, token, passphrase, secret }, null, 2));
console.log('\n# Smoke-test the crack (localhost: no rate-limit delay needed):');
console.log(
  `bruteforcer pwpush crack --url ${pushUrl} --charset digits --max ${passphrase.length} --delay-ms 0`,
);
