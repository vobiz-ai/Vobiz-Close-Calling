/**
 * The SIP-endpoint fallback (VOBIZ_SIP_AUTH=endpoint): one Vobiz endpoint per
 * agent, its password rotated at each sign-in and handed to that session only.
 * server.test.js covers everything else in the default access-token mode.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 20000 + Math.floor(Math.random() * 20000);
const BASE = `http://127.0.0.1:${PORT}`;
const PUBLIC = 'https://calling.example.test';
const FETCH_LOG = path.join(os.tmpdir(), `vzcl-fetch-ep-${PORT}.jsonl`);
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vzcl-data-ep-'));
const env = {
  PATH: process.env.PATH, SYSTEMROOT: process.env.SYSTEMROOT, PORT: String(PORT), FETCH_LOG, DATA_DIR,
  PUBLIC_BASE_URL: PUBLIC, SIGNING_SECRET: 'test-signing-secret', VOBIZ_SIP_AUTH: 'endpoint',
  VOBIZ_MEDIA_HOSTS: 'media.vobiz.test', LOG_SETTLE_MS: '30', PANEL_REPORT_GRACE_MS: '150',
};

const ONE = { authId: 'MA_TEST0001', authToken: 'tok-account-one', appId: '43919358318796814' };
const TWO = { authId: 'MA_TEST0002', authToken: 'tok-account-two', appId: '52000000000000017' };

let server;
let out = '';
const fetched = () => fs.readFileSync(FETCH_LOG, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const req = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: 'manual', ...opts });
const post = (b, token) => ({ method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(b) });
const bearer = token => ({ headers: { Authorization: `Bearer ${token}` } });

function vobizPost(p, fields, authToken) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const sig = crypto.createHmac('sha256', authToken).update(`${PUBLIC}${p}.${nonce}`).digest('base64');
  return req(p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Vobiz-Signature-V3': sig, 'X-Vobiz-Signature-V3-Nonce': nonce },
    body: new URLSearchParams(fields).toString(),
  });
}

async function connectKey(apiKey) {
  const r = await req('/api/identity/apikey', post({ apiKey }));
  const c = await r.json();
  assert.equal(r.status, 200, JSON.stringify(c));
  return c.token;
}

async function vobizLogin(token, acct) {
  const r = await req('/api/login', post({ authId: acct.authId, authToken: acct.authToken }, token));
  const b = await r.json();
  assert.equal(r.status, 200, JSON.stringify(b));
  const agent = await (await req('/api/agent', bearer(token))).json();
  return { ...b, agent, sipUser: agent.sipUser.split('@')[0] };
}

before(async () => {
  fs.writeFileSync(FETCH_LOG, '');
  server = spawn(process.execPath, ['-r', path.join(__dirname, 'fetch-mock.cjs'), path.join(__dirname, '..', 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', d => { out += String(d); });
  server.stderr.on('data', d => { out += String(d); });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`backend did not start\n${out}`)), 8000);
    server.stdout.on('data', d => { if (String(d).includes('calling backend on')) { clearTimeout(t); resolve(); } });
    server.on('exit', code => reject(new Error(`backend exited ${code}\n${out}`)));
  });
});

after(() => {
  if (server) server.kill();
  fs.rmSync(FETCH_LOG, { force: true });
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
});

let ben;
let cara;

test('endpoint mode: one endpoint per agent, its rewritten username read back, a password for this session only', async () => {
  ben = await connectKey('api_TESTben0000000000000000000');
  const v = await vobizLogin(ben, ONE);
  assert.match(v.sipUser, /^cl[0-9a-f]{14}x[0-9a-f]{6}1187694299$/);
  assert.equal(v.agent.auth, 'endpoint');
  assert.match(v.agent.sipPassword, /^Vz[A-Za-z0-9]{24}$/);
  assert.ok(!fetched().some(f => f.url.includes('/JWT/Token/')), 'no access token is minted');
  assert.equal((await req('/api/sip-token', post({}, ben))).status, 400);
  const again = await vobizLogin(ben, ONE);
  assert.equal(again.sipUser, v.sipUser, 'the same endpoint is reused');
  assert.notEqual(again.agent.sipPassword, v.agent.sipPassword, 'and its password rotated');
  assert.equal(fetched().filter(f => f.url.endsWith('/Endpoint/') && f.method === 'POST').length, 1);
});

test('endpoint mode: account two binds through the {"application": <integer>} retry', async () => {
  cara = await connectKey('api_TESTcara000000000000000000');
  const v = await vobizLogin(cara, TWO);
  assert.equal(v.bound, true);
  const bodies = fetched().filter(f => f.authId === TWO.authId && f.method === 'POST' && /\/Endpoint\/\d+\/$/.test(f.url)).map(f => f.body);
  assert.ok(bodies.includes(`{"application":${TWO.appId}}`), 'integer literal, never a rounded JS number');

  // Calls from the endpoint still route to the agent.
  const x = await (await vobizPost('/vobiz/answer', { CallUUID: 'ep-out-1', From: `sip:${v.sipUser}@registrar.vobiz.ai`, To: '+919000000012' }, TWO.authToken)).text();
  assert.ok(x.includes('<Number>+919000000012</Number>'), x);
});
