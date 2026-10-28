/**
 * Boots the real backend (fetch replaced by fetch-mock.cjs, so nothing leaves
 * the machine) and drives it over HTTP: Close connect (OAuth and API key),
 * Vobiz sign-in, call webhooks, logging to Close, and the security
 * regressions earlier integrations shipped.
 *
 * Vobiz callbacks are signed with the owning account's Auth Token, exactly as
 * Vobiz signs them, and signature checking is left on ("require").
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
const CLOSE_API = 'https://api.close.com';
const FETCH_LOG = path.join(os.tmpdir(), `vzcl-fetch-${PORT}.jsonl`);
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vzcl-data-'));
const env = {
  PATH: process.env.PATH, SYSTEMROOT: process.env.SYSTEMROOT, PORT: String(PORT), FETCH_LOG, DATA_DIR,
  PUBLIC_BASE_URL: PUBLIC, SIGNING_SECRET: 'test-signing-secret',
  CLOSE_CLIENT_ID: 'close-client-test', CLOSE_CLIENT_SECRET: 'close-secret-test',
  VOBIZ_MEDIA_HOSTS: 'media.vobiz.test', LOG_SETTLE_MS: '30', PANEL_REPORT_GRACE_MS: '150',
};

const ONE = { authId: 'MA_TEST0001', authToken: 'tok-account-one', appId: '43919358318796814' };
const TWO = { authId: 'MA_TEST0002', authToken: 'tok-account-two', appId: '52000000000000017' };
const CARA_KEY = 'api_TESTcara000000000000000000';

let server;
let out = '';
const fetched = () => fs.readFileSync(FETCH_LOG, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const req = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: 'manual', ...opts });
const seenBodies = [];
async function body(r) { const t = await r.text(); seenBodies.push(t); return t; }
async function json(r) { return JSON.parse(await body(r)); }
const post = (b, token) => ({ method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(b) });
const bearer = token => ({ headers: { Authorization: `Bearer ${token}` } });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const claimsOf = jwt => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
const basicOf = key => `Basic ${Buffer.from(`${key}:`).toString('base64')}`;

async function waitFor(fn, what, ms = 3000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}\n${out.slice(-2000)}`);
    await sleep(25);
  }
}

/** A Vobiz callback, signed the way Vobiz signs: V3 over URL-without-query + "." + nonce. */
function vobizPost(p, fields, authToken) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const sig = crypto.createHmac('sha256', authToken).update(`${PUBLIC}${p}.${nonce}`).digest('base64');
  return req(p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Vobiz-Signature-V3': sig, 'X-Vobiz-Signature-V3-Nonce': nonce },
    body: new URLSearchParams(fields).toString(),
  });
}

/** Start the OAuth flow; returns the authorize URL Close would show and the cookie. */
async function startConnect() {
  const start = await req('/close/oauth/start');
  assert.equal(start.status, 302, out.slice(-1000));
  return { authorize: new URL(start.headers.get('location')), cookie: start.headers.get('set-cookie').split(';')[0] };
}

/** Plays the agent clicking Authorize on Close, then the redirect back. */
async function connect(userNo) {
  const { authorize, cookie } = await startConnect();
  const qs = new URLSearchParams({ code: `code-${userNo}.${crypto.randomBytes(4).toString('hex')}`, state: authorize.searchParams.get('state') });
  const cb = await req(`/close/oauth/callback?${qs}`, { headers: { Cookie: cookie } });
  assert.equal(cb.status, 302, out.slice(-1000));
  const link = new URLSearchParams(new URL(cb.headers.get('location'), BASE).hash.slice(1)).get('link');
  assert.ok(link, `no link code in ${cb.headers.get('location')}`);
  const claim = await req('/api/identity/claim', post({ code: link }));
  const c = await json(claim);
  assert.equal(claim.status, 200, JSON.stringify(c));
  return { token: c.token, session: c.session, link };
}

async function connectKey(apiKey) {
  const r = await req('/api/identity/apikey', post({ apiKey }));
  const c = await json(r);
  assert.equal(r.status, 200, JSON.stringify(c));
  return { token: c.token, session: c.session };
}

async function vobizLogin(token, acct = ONE) {
  const r = await req('/api/login', post({ authId: acct.authId, authToken: acct.authToken }, token));
  const b = await json(r);
  assert.equal(r.status, 200, JSON.stringify(b));
  const agent = await json(await req('/api/agent', bearer(token)));
  return { ...b, agent, sipUser: agent.sipUser.split('@')[0] };
}

/** Open the softphone event stream and collect events. */
function openStream(token) {
  const events = [];
  const ctrl = new AbortController();
  const ready = (async () => {
    const r = await fetch(`${BASE}/api/events`, { headers: { Authorization: `Bearer ${token}` }, signal: ctrl.signal });
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    (async () => {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const parts = buf.split('\n\n');
          buf = parts.pop();
          for (const p of parts) {
            const d = p.split('\n').find(l => l.startsWith('data: '));
            if (d) events.push(JSON.parse(d.slice(6)));
          }
        }
      } catch { /* aborted */ }
    })();
  })();
  return { events, ready, close: () => ctrl.abort() };
}

/** Writes to Close since a mark, optionally only to one API path (and its children). */
function clWrites(mark, pathStart) {
  return fetched().slice(mark).filter(f => f.url.startsWith(`${CLOSE_API}/api/v1/`) && ['POST', 'PUT'].includes(f.method)
    && !f.url.endsWith('/data/search/')
    && (!pathStart || new URL(f.url).pathname === `/api/v1${pathStart}` || new URL(f.url).pathname.startsWith(`/api/v1${pathStart}`)));
}
const callPosts = mark => clWrites(mark, '/activity/call/').filter(f => f.method === 'POST');

let asha; // admin of Acme, OAuth
let ben;  // member of Acme, OAuth
let cara; // admin of Globex, API key

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

// ─── boot ────────────────────────────────────────────────────────────────────
test('boot touches no Vobiz account and no Close organization', () => {
  assert.deepEqual(fetched(), []);
});

// ─── Close connect ───────────────────────────────────────────────────────────
test('the softphone learns which ways of connecting Close are offered', async () => {
  assert.deepEqual(await json(await req('/close/oauth/options')), { oauth: true, apiKey: true });
});

test('connect sends the agent to Close\'s authorize page with our client id, redirect and a state', async () => {
  const { authorize, cookie } = await startConnect();
  assert.equal(authorize.origin + authorize.pathname, 'https://app.close.com/oauth2/authorize/');
  assert.equal(authorize.searchParams.get('client_id'), 'close-client-test');
  assert.equal(authorize.searchParams.get('response_type'), 'code');
  assert.equal(authorize.searchParams.get('redirect_uri'), `${PUBLIC}/close/oauth/callback`);
  assert.match(authorize.searchParams.get('state'), /^[A-Za-z0-9_-]{32}$/);
  assert.doesNotMatch(authorize.toString(), /close-secret-test/, 'the client secret never goes to the browser');
  assert.match(cookie, /^vz_cl_oauth=/);
});

test('OAuth callback without the browser cookie is refused and exchanges nothing', async () => {
  const { authorize } = await startConnect();
  const r = await req(`/close/oauth/callback?code=code-101&state=${authorize.searchParams.get('state')}`);
  assert.equal(r.status, 400);
  assert.ok(!fetched().some(f => f.url.endsWith('/oauth2/token/')), 'no code exchange for a refused callback');
});

test('connecting Close gives a session; the code is exchanged with the client secret; the link code works once', async () => {
  asha = await connect(101);
  assert.equal(asha.session.user.name, 'Asha Rao');
  assert.equal(asha.session.user.admin, true);
  assert.equal(asha.session.user.auth, 'oauth');
  assert.equal(asha.session.workspace.name, 'Acme');
  assert.equal(asha.session.mode, null);
  const tok = fetched().filter(f => f.url === `${CLOSE_API}/oauth2/token/`).at(-1);
  const form = new URLSearchParams(tok.body);
  assert.equal(form.get('grant_type'), 'authorization_code');
  assert.equal(form.get('client_secret'), 'close-secret-test');
  assert.equal(form.get('redirect_uri'), `${PUBLIC}/close/oauth/callback`);
  const again = await req('/api/identity/claim', post({ code: asha.link }));
  assert.equal(again.status, 401);
  ben = await connect(102);
  assert.equal(ben.session.user.admin, false, 'a non-admin role is not an admin');
});

test('an agent can connect with their own Close API key; a wrong key is refused', async () => {
  const bad = await req('/api/identity/apikey', post({ apiKey: 'api_TESTnotakey00000000000000' }));
  assert.equal(bad.status, 401);
  assert.equal((await req('/api/identity/apikey', post({ apiKey: 'x' }))).status, 400);
  cara = await connectKey(CARA_KEY);
  assert.equal(cara.session.workspace.name, 'Globex');
  assert.equal(cara.session.user.auth, 'apikey');
  assert.equal(cara.session.user.admin, true);
  const me = fetched().filter(f => f.url === `${CLOSE_API}/api/v1/me/`).at(-1);
  assert.equal(me.authorization, basicOf(CARA_KEY), 'the key is the Basic user name, with no password');
});

test('stored Close refresh tokens and API keys are encrypted at rest', () => {
  const raw = fs.readFileSync(path.join(DATA_DIR, 'store.json'), 'utf8');
  assert.doesNotMatch(raw, /cl-rt-|cl-at-|api_TEST/);
  const d = JSON.parse(raw);
  assert.match(Object.values(d.users).find(x => x.userId === 'user_asha00001').refreshToken, /^v1\./);
  assert.match(Object.values(d.users).find(x => x.userId === 'user_cara00001').apiKey, /^v1\./);
});

test('settings: everyone reads them, only organization admins change them', async () => {
  const r = await json(await req('/api/settings', bearer(ben.token)));
  assert.equal(r.admin, false);
  assert.equal(r.settings.createUnknown, true);
  assert.equal(r.settings.missedTask, true);
  assert.equal((await req('/api/settings', post({ autoOpen: true }, ben.token))).status, 403);
  const save = await json(await req('/api/settings', post({ defaultCountry: 'IN', recordingTtlSeconds: 3600 }, asha.token)));
  assert.equal(save.settings.recordingTtlSeconds, 3600);
});

test('refresh on 401: an expired Close token is refreshed and the call retried', async () => {
  // Ben's first access token is rejected after /me/ by the mock.
  const r = await req('/api/lookup?number=09000000011', bearer(ben.token));
  const b = await json(r);
  assert.equal(r.status, 200, JSON.stringify(b));
  assert.equal(b.people[0].name, 'Priya Shah');
  const refreshed = fetched().find(f => f.url === `${CLOSE_API}/oauth2/token/` && String(f.body).includes('grant_type=refresh_token'));
  assert.ok(refreshed);
  assert.equal(new URLSearchParams(refreshed.body).get('client_secret'), 'close-secret-test');
});

test('caller lookup: exact number only, every phone counts, lead and status shown, organizations never cross', async () => {
  const a = await json(await req('/api/lookup?number=%2B919000000011', bearer(asha.token)));
  assert.deepEqual(a.people.map(p => p.id), ['cont_priya00001'], 'the +1 decoy with the same digits is not a match');
  assert.equal(a.people[0].company, 'Acme Traders');
  assert.equal(a.people[0].status, 'Qualified');
  assert.equal(a.people[0].url, 'https://app.close.com/lead/lead_acmetraders/');
  const add = await json(await req('/api/lookup?number=9000000012', bearer(asha.token)));
  assert.deepEqual(add.people.map(p => p.id), ['cont_ravi000001'], 'found through a second phone');
  const theirs = await json(await req('/api/lookup?number=%2B919000000011', bearer(cara.token)));
  assert.deepEqual(theirs.people.map(p => p.id), ['cont_other00001']);
  const search = fetched().filter(f => f.url === `${CLOSE_API}/api/v1/data/search/`).at(-1);
  const q = JSON.parse(search.body);
  assert.equal(q.query.queries[0].object_type, 'contact');
  assert.match(JSON.stringify(q.query), /"related_object_type":"contact_phone"/);
  assert.equal(search.authorization, basicOf(CARA_KEY), 'an API-key user searches with their key');
});

test('click-to-call by record: a contact or lead id gives its numbers; anything else is refused', async () => {
  const c = await json(await req('/api/record-phones?contact=cont_ravi000001', bearer(asha.token)));
  assert.deepEqual(c.phones.map(p => p.number), ['+917000000099', '+919000000012']);
  const l = await json(await req('/api/record-phones?lead=lead_acmetraders', bearer(asha.token)));
  assert.deepEqual(l.phones, [{ number: '+919000000011', name: 'Priya Shah' }]);
  const mark = fetched().length;
  for (const bad of ['contact=../me', 'lead=lead_x%2F..%2Fme', 'contact=https://evil.example', 'lead=']) {
    assert.equal((await req(`/api/record-phones?${bad}`, bearer(asha.token))).status, 400, bad);
  }
  assert.equal(fetched().length, mark, 'nothing was sent to Close for a malformed id');
  const other = await req('/api/record-phones?contact=cont_other00001', bearer(asha.token));
  assert.equal(other.status, 404, 'another organization\'s contact is not found');
});

// ─── Vobiz sign-in ───────────────────────────────────────────────────────────
test('Vobiz sign-in needs a Close session', async () => {
  const r = await req('/api/login', post({ authId: ONE.authId, authToken: ONE.authToken }));
  assert.equal(r.status, 401);
});

test('a wrong Vobiz token is refused with 401 and creates nothing', async () => {
  const mark = fetched().length;
  const r = await req('/api/login', post({ authId: ONE.authId, authToken: 'wrong' }, asha.token));
  assert.equal(r.status, 401);
  const calls = fetched().slice(mark);
  assert.equal(calls.length, 1, 'only the credential check');
  assert.match(calls[0].url, /\/numbers\?page=1/);
});

test('sign-in provisions one app and an access-token identity per agent, with the 17-digit app id intact', async () => {
  const mark = fetched().length;
  asha.v = await vobizLogin(asha.token, ONE);
  ben.v = await vobizLogin(ben.token, ONE);
  assert.equal(asha.v.appId, ONE.appId);
  assert.notEqual(asha.v.sipUser, ben.v.sipUser, 'two agents never share an identity');
  assert.match(asha.v.sipUser, /^cl[0-9a-f]{14}_MA_TEST0001$/, 'the identity Vobiz builds from <sub>_<Auth ID>');
  assert.equal(asha.v.agent.auth, 'jwt');
  assert.equal(asha.v.agent.sipPassword, undefined, 'no SIP password with an access token');
  assert.ok(!fetched().slice(mark).some(f => f.url.includes('/Endpoint/')), 'no SIP endpoint is created');
  const mint = fetched().slice(mark).find(f => f.url.endsWith(`/Account/${ONE.authId}/JWT/Token/`));
  assert.ok(mint, 'sign-in checks the account can issue tokens');
  assert.deepEqual(asha.v.numbers, ['+910000000001', '+910000000002'], 'inactive and voice-disabled numbers are not offered');
  const created = fetched().filter(f => f.url.endsWith('/Application/') && f.method === 'POST');
  assert.equal(created.length, 1, 'one application for the account');
  const app = JSON.parse(created[0].body);
  assert.equal(app.app_name, 'Close-Calling-Vobiz');
  assert.equal(app.answer_url, `${PUBLIC}/vobiz/answer`);
  assert.equal(app.hangup_url, `${PUBLIC}/vobiz/hangup`);
  assert.equal(app.fallback_answer_url, `${PUBLIC}/vobiz/fallback`);
});

test('account two signs in too, and its tokens name its own application', async () => {
  cara.v = await vobizLogin(cara.token, TWO);
  assert.equal(cara.v.bound, true);
  assert.match(cara.v.sipUser, /^cl[0-9a-f]{14}_MA_TEST0002$/);
  const mint = fetched().filter(f => f.url.endsWith(`/Account/${TWO.authId}/JWT/Token/`)).at(-1);
  assert.ok(mint.body.includes(`"app":"${TWO.appId}"`), '17-digit app id sent as a string, never a rounded JS number');
});

// ─── access tokens ───────────────────────────────────────────────────────────
test('a SIP access token needs a signed-in Vobiz session', async () => {
  assert.equal((await req('/api/sip-token', post({}))).status, 401);
  const fresh = await connect(102);
  const r = await req('/api/sip-token', post({}, fresh.token));
  assert.equal(r.status, 403, 'connected to Close but not signed in to Vobiz');
});

test('the softphone gets a short-lived token for its own identity, and never the Auth Token', async () => {
  const mark = fetched().length;
  const r = await req('/api/sip-token', post({}, cara.token));
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  const t = await json(r);
  assert.equal(t.sipUser, `${cara.v.sipUser}@registrar.vobiz.ai`);
  assert.doesNotMatch(JSON.stringify(t), new RegExp(TWO.authToken), 'the Auth Token stays on the server');
  const c = claimsOf(t.token);
  assert.equal(c.iss, TWO.authId);
  assert.equal(`${c.sub}_${TWO.authId}`, cara.v.sipUser, 'the token registers as the identity the backend routes');
  assert.equal(c.app, TWO.appId, 'outbound calls go to our Answer URL');
  assert.deepEqual(c.per, { voice: { incoming_allow: true, outgoing_allow: true } });
  assert.equal(c.exp - c.nbf, 3600);
  assert.equal(t.exp, c.exp);
  const mint = fetched().slice(mark).filter(f => f.url.includes('/JWT/Token/'));
  assert.equal(mint.length, 1);
  assert.equal(mint[0].authId, TWO.authId, 'minted with the agent\'s own account');
});

test('token requests are throttled per session', async () => {
  const r = await req('/api/sip-token', post({}, cara.token));
  assert.equal(r.status, 429);
});

test('signing in again ends the older session of the same agent', async () => {
  const second = await connect(101);
  const stream = openStream(asha.token);
  await stream.ready;
  await sleep(50);
  second.v = await vobizLogin(second.token, ONE);
  await waitFor(() => stream.events.find(e => e.type === 'signed-out' && e.reason === 'elsewhere'), 'signed-out event');
  stream.close();
  const old = await req('/api/session', bearer(asha.token));
  assert.equal(old.status, 401);
  assert.equal(second.v.sipUser, asha.v.sipUser, 'same agent, same identity');
  asha = second;
});

test('caller ID: only the account\'s own numbers', async () => {
  const bad = await req('/api/select-number', post({ number: '+910000000003' }, asha.token));
  assert.equal(bad.status, 400);
  const good = await json(await req('/api/select-number', post({ number: '+910000000002' }, asha.token)));
  assert.equal(good.from, '+910000000002');
  await req('/api/select-number', post({ number: '+910000000001' }, asha.token));
});

test('Enable inbound attaches the number with the app id as a string and names the previous app', async () => {
  const r = await json(await req('/api/setup-inbound', post({ number: '+910000000001' }, asha.token)));
  assert.equal(r.previousAppId, '20577609616603585');
  assert.equal(r.appId, ONE.appId);
  const att = fetched().filter(f => /\/numbers\/%2B910000000001\/application$/.test(f.url));
  assert.equal(att.at(-1).body, `{"application_id":"${ONE.appId}"}`);
});

// ─── webhooks: signatures and routing ────────────────────────────────────────
test('unsigned and wrongly signed Vobiz callbacks are refused', async () => {
  const unsigned = await req('/vobiz/answer', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'CallUUID=x&Direction=inbound&To=%2B910000000001' });
  assert.equal(unsigned.status, 403);
  // Signed with account TWO's token, about account ONE's number.
  const crossTenant = await vobizPost('/vobiz/answer', { CallUUID: 'x2', From: '+919000000999', To: '+910000000001', ParentAuthID: ONE.authId }, TWO.authToken);
  assert.equal(crossTenant.status, 403);
});

test('the fallback URL always answers with a polite message, signed or not', async () => {
  const r = await req('/vobiz/fallback', { method: 'POST' });
  const x = await body(r);
  assert.equal(r.status, 200);
  assert.match(x, /<Speak>[^<]+<\/Speak>\s*<Hangup\/>/);
});

test('outbound: the browser is the A leg; /answer dials the customer as the chosen caller ID', async () => {
  const r = await vobizPost('/vobiz/answer', {
    CallUUID: 'call-out-0', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '9000000012', Direction: 'outbound',
    'SIPHeader_X-VH-Caller-ID': '+910000000002',
  }, ONE.authToken);
  const x = await body(r);
  assert.equal(r.status, 200);
  assert.match(x, /<Record [^>]*recordSession="true"[^>]*\/>\s*<Dial /);
  assert.match(x, /<Dial callerId="\+910000000002"[^>]*callbackUrl="https:\/\/calling\.example\.test\/vobiz\/dial-events"/);
  assert.match(x, /<Number>\+919000000012<\/Number>/, 'local number normalised with the default country');
});

test('outbound: a caller ID the account does not own falls back to the selected one', async () => {
  const x = await body(await vobizPost('/vobiz/answer', {
    CallUUID: 'call-out-x', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+919000000012', 'X-VH-Caller-ID': '+910000000003',
  }, ONE.authToken));
  assert.match(x, /<Dial callerId="\+910000000001"/);
});

test('outbound: an unknown SIP user is refused, and injected XML never reaches the document', async () => {
  const r = await vobizPost('/vobiz/answer', { CallUUID: 'c-x', From: 'sip:nobody@registrar.vobiz.ai', To: '+919000000012' }, ONE.authToken);
  assert.equal(r.status, 403);
  assert.doesNotMatch(await body(r), /<Dial/);
  const inj = await body(await vobizPost('/vobiz/answer', {
    CallUUID: 'c-y', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+91900"/><Dial><Number>+15550000000</Number></Dial><x a="',
  }, ONE.authToken));
  assert.doesNotMatch(inj, /15550000000/);
  assert.match(inj, /<Hangup reason="rejected"\/>/);
});

test('inbound: ParentAuthID routes to that account and rings every signed-in agent with callerId set', async () => {
  const stream = openStream(ben.token);
  await stream.ready;
  await sleep(50);
  const x = await body(await vobizPost('/vobiz/answer', { CallUUID: 'call-in-1', From: '09000000011', To: '+910000000001', Direction: 'inbound', ParentAuthID: ONE.authId }, ONE.authToken));
  assert.match(x, /<Dial callerId="\+910000000001"[^>]*callerName="\+919000000011"/);
  assert.ok(x.includes(`<User>sip:${asha.v.sipUser}@registrar.vobiz.ai</User>`));
  assert.ok(x.includes(`<User>sip:${ben.v.sipUser}@registrar.vobiz.ai</User>`));
  assert.ok(!x.includes(cara.v.sipUser), 'another account\'s agent never rings');
  assert.match(x, /<\/Dial>\s*<Speak>/, 'a polite message if nobody answers');
  const ev = await waitFor(() => stream.events.find(e => e.type === 'incoming'), 'screen-pop event');
  assert.equal(ev.from, '+919000000011');
  stream.close();
});

test('inbound without ParentAuthID falls back to the dialled number', async () => {
  const x = await body(await vobizPost('/vobiz/answer', { CallUUID: 'call-in-np', From: '+917000000055', To: '910000000001' }, ONE.authToken));
  assert.ok(x.includes(`<User>sip:${asha.v.sipUser}@registrar.vobiz.ai</User>`));
});

// ─── logging to Close ────────────────────────────────────────────────────────
test('answered inbound call: one Close call activity on the caller\'s lead, written as the agent who answered', async () => {
  const mark = fetched().length;
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-in-1', Event: 'DialAnswer', DialBLegTo: `sip:${ben.v.sipUser}@registrar.vobiz.ai` }, ONE.authToken);
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-in-1', Event: 'DialHangup', DialBLegDuration: '252', DialBLegBillDuration: '252' }, ONE.authToken);
  await vobizPost('/vobiz/dial-status', { CallUUID: 'call-in-1', DialStatus: 'completed', DialBLegUUID: 'b-1' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-1', Event: 'Hangup', HangupCause: 'NORMAL_CLEARING', Duration: '270', ParentAuthID: ONE.authId }, ONE.authToken);
  const call = await waitFor(() => callPosts(mark)[0], 'call activity');
  const b = JSON.parse(call.body);
  assert.equal(b.lead_id, 'lead_acmetraders');
  assert.equal(b.contact_id, 'cont_priya00001');
  assert.equal(b.direction, 'inbound');
  assert.equal(b.status, 'completed');
  assert.equal(b.duration, 252, 'talk time from the B leg, not the 270 s A leg');
  assert.equal(b.phone, '+919000000011');
  assert.match(b.note, /^Agent: Ben Ng$/m);
  assert.match(b.note, /^Recording: processing/m);
  assert.equal(b.recording_url, undefined);
  assert.match(call.authorization, /^Bearer cl-at-102-/, 'written as the agent who took the call');
  assert.equal(clWrites(mark, '/lead/').length, 0, 'a known caller is not created again');
  assert.equal(clWrites(mark, '/task/').length, 0, 'answered calls get no call-back task');
  // A replayed hangup must not log twice.
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-1', Event: 'Hangup', ParentAuthID: ONE.authId }, ONE.authToken);
  await sleep(150);
  assert.equal(callPosts(mark).length, 1);
});

let recordingLink;
test('recording: the call activity gets a signed https link that plays, expires and is account-scoped', async () => {
  const mark = fetched().length;
  await vobizPost('/vobiz/recording', { CallUUID: 'call-in-1', RecordingID: 'rec-1', Event: 'RecordStop', RecordingEndReason: 'HungUp' }, ONE.authToken);
  const put = await waitFor(() => clWrites(mark, '/activity/call/').find(f => f.method === 'PUT'), 'call update');
  assert.match(put.url, /\/activity\/call\/acti_new\d+\/$/);
  const b = JSON.parse(put.body);
  assert.doesNotMatch(put.body, /tok-account/);
  assert.match(b.note, /^Agent: Ben Ng$/m, 'the rest of the note is kept');
  recordingLink = b.recording_url;
  assert.ok(b.note.includes(recordingLink));
  const u = new URL(recordingLink);
  assert.equal(u.origin, PUBLIC, 'https, as Close requires');
  const play = await req(`${u.pathname}${u.search}`);
  assert.equal(play.status, 200);
  assert.equal(await play.text(), 'AUDIO:rec-1.mp3');
  const tampered = new URL(recordingLink); tampered.searchParams.set('sig', tampered.searchParams.get('sig').replace(/.$/, c => (c === 'a' ? 'b' : 'a')));
  assert.equal((await req(`${tampered.pathname}${tampered.search}`)).status, 403);
  const otherAcct = new URL(recordingLink); otherAcct.searchParams.set('aid', TWO.authId);
  assert.equal((await req(`${otherAcct.pathname}${otherAcct.search}`)).status, 403);
  const expired = new URL(recordingLink); expired.searchParams.set('exp', '1000');
  assert.equal((await req(`${expired.pathname}${expired.search}`)).status, 403);
});

test('missed inbound call from an unknown number: one new lead, one call, one call-back task', async () => {
  await vobizPost('/vobiz/answer', { CallUUID: 'call-in-2', From: '+917000000001', To: '+910000000001', ParentAuthID: ONE.authId }, ONE.authToken);
  const mark = fetched().length;
  await vobizPost('/vobiz/dial-status', { CallUUID: 'call-in-2', DialStatus: 'no-answer' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-2', Event: 'Hangup', ParentAuthID: ONE.authId }, ONE.authToken);
  const task = await waitFor(() => clWrites(mark, '/task/')[0], 'call-back task');
  const leads = clWrites(mark, '/lead/');
  assert.equal(leads.length, 1);
  assert.deepEqual(JSON.parse(leads[0].body), { name: 'Caller +917000000001', contacts: [{ name: 'Caller +917000000001', phones: [{ phone: '+917000000001', type: 'mobile' }] }] });
  const call = JSON.parse(callPosts(mark)[0].body);
  assert.equal(call.status, 'no-answer');
  assert.equal(call.duration, 0);
  assert.match(call.lead_id, /^lead_new/);
  assert.match(call.contact_id, /^cont_new/);
  const t = JSON.parse(task.body);
  assert.equal(t._type, 'lead');
  assert.equal(t.lead_id, call.lead_id);
  assert.match(t.text, /^Call back \+917000000001 /);
  assert.match(t.date, /^\d{4}-\d{2}-\d{2}$/);
  // A second call from the same number finds that lead in Close.
  await vobizPost('/vobiz/answer', { CallUUID: 'call-in-3', From: '+917000000001', To: '+910000000001', ParentAuthID: ONE.authId }, ONE.authToken);
  const mark2 = fetched().length;
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-3', Event: 'Hangup', ParentAuthID: ONE.authId }, ONE.authToken);
  const second = await waitFor(() => callPosts(mark2)[0], 'second call');
  assert.equal(JSON.parse(second.body).lead_id, call.lead_id);
  assert.equal(clWrites(mark2, '/lead/').length, 0);
});

test('outbound after a tel: link click: Close\'s own call log is filled in, not duplicated', async () => {
  const stream = openStream(asha.token);
  await stream.ready;
  await sleep(50);
  const mark = fetched().length;
  await vobizPost('/vobiz/answer', { CallUUID: 'call-out-1', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+919000000012', 'X-VH-Ref': 'abc123' }, ONE.authToken);
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-out-1', Event: 'DialAnswer' }, ONE.authToken);
  await vobizPost('/vobiz/dial-status', { CallUUID: 'call-out-1', DialStatus: 'completed' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-out-1', Event: 'Hangup' }, ONE.authToken);
  const put = await waitFor(() => clWrites(mark, '/activity/call/').find(f => f.method === 'PUT'), 'tel: call filled in');
  assert.match(put.url, /\/activity\/call\/acti_tellink0001\/$/);
  const b = JSON.parse(put.body);
  assert.equal(b.lead_id, 'lead_ravikumar01', 'matched on a second phone');
  assert.equal(b.direction, 'outbound');
  assert.equal(b.status, 'completed');
  assert.match(put.authorization, /^Bearer cl-at-101-/);
  assert.equal(callPosts(mark).length, 0, 'no second call activity');
  const ev = await waitFor(() => stream.events.find(e => e.type === 'logged' && e.callUuid === 'call-out-1'), 'logged event');
  assert.equal(ev.leadUrl, 'https://app.close.com/lead/lead_ravikumar01/');
  stream.close();
  // The next call to the same number is a new activity: that tel: log is claimed.
  const mark2 = fetched().length;
  await vobizPost('/vobiz/answer', { CallUUID: 'call-out-1b', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+919000000012' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-out-1b', Event: 'Hangup' }, ONE.authToken);
  await waitFor(() => callPosts(mark2)[0], 'new call activity');
});

test('busy outbound call is logged with its outcome', async () => {
  const mark = fetched().length;
  await vobizPost('/vobiz/answer', { CallUUID: 'call-out-busy', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+919000000011' }, ONE.authToken);
  await vobizPost('/vobiz/dial-status', { CallUUID: 'call-out-busy', DialStatus: 'busy' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-out-busy', Event: 'Hangup' }, ONE.authToken);
  const call = JSON.parse((await waitFor(() => callPosts(mark)[0], 'busy call')).body);
  assert.equal(call.status, 'busy');
  assert.match(call.note, /^Vobiz outbound call, busy$/m);
});

test('a call that never reached /vobiz/answer is still logged from the softphone report', async () => {
  const mark = fetched().length;
  await req('/api/call-log', post({ ref: 'neverreached01', number: '+919000000012', cause: 'Busy', startedAt: Date.now() }, asha.token));
  const call = JSON.parse((await waitFor(() => callPosts(mark)[0], 'panel-reported call')).body);
  assert.equal(call.status, 'busy');
  assert.equal(call.phone, '+919000000012');
  // A report for a call the server saw is ignored.
  const mark2 = fetched().length;
  await req('/api/call-log', post({ ref: 'zzz', number: '+919000000012', cause: 'Ended' }, asha.token));
  await vobizPost('/vobiz/answer', { CallUUID: 'call-out-2', From: `sip:${asha.v.sipUser}@registrar.vobiz.ai`, To: '+919000000012', 'X-VH-Ref': 'zzz' }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-out-2', Event: 'Hangup' }, ONE.authToken);
  await sleep(400);
  assert.equal(callPosts(mark2).length, 1, 'logged once, from the server record');
});

test('the call list gives an agent their own calls with fresh recording links, never another organization\'s', async () => {
  const mine = await json(await req('/api/calls', bearer(ben.token)));
  const c = mine.calls.find(x => x.callUuid === 'call-in-1');
  assert.ok(c && c.recordingUrl, 'a fresh recording link');
  assert.equal(c.contactName, 'Priya Shah');
  assert.equal(c.leadUrl, 'https://app.close.com/lead/lead_acmetraders/');
  const play = new URL(c.recordingUrl);
  assert.equal((await req(`${play.pathname}${play.search}`)).status, 200);
  const theirs = await json(await req('/api/calls', bearer(cara.token)));
  assert.equal(theirs.calls.length, 0);
});

// ─── transfer ────────────────────────────────────────────────────────────────
test('transfer: redirects the inbound caller\'s leg to ring the other agent', async () => {
  await vobizPost('/vobiz/answer', { CallUUID: 'call-in-t', From: '+919000000012', To: '+910000000001', ParentAuthID: ONE.authId }, ONE.authToken);
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-in-t', Event: 'DialAnswer', DialBLegTo: `sip:${asha.v.sipUser}@registrar.vobiz.ai` }, ONE.authToken);
  const agents = await json(await req('/api/agents', bearer(asha.token)));
  assert.deepEqual(agents.agents.map(a => a.userId), ['user_ben000001']);
  const r = await req('/api/transfer', post({ userId: 'user_ben000001' }, asha.token));
  assert.equal(r.status, 200, await body(r));
  const t = fetched().filter(f => /\/Call\/call-in-t\/$/.test(f.url)).at(-1);
  assert.deepEqual(JSON.parse(t.body), { legs: 'aleg', aleg_url: `${PUBLIC}/vobiz/transfer-xml`, aleg_method: 'POST' });
  const x = await body(await vobizPost('/vobiz/transfer-xml', { CallUUID: 'call-in-t' }, ONE.authToken));
  assert.ok(x.includes(`<User>sip:${ben.v.sipUser}@registrar.vobiz.ai</User>`));
  assert.match(x, /callerId="\+910000000001"/);
  const mark = fetched().length;
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-in-t', Event: 'DialAnswer', DialBLegTo: `sip:${ben.v.sipUser}@registrar.vobiz.ai` }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-t', Event: 'Hangup' }, ONE.authToken);
  const call = await waitFor(() => callPosts(mark)[0], 'transferred call');
  assert.match(call.authorization, /^Bearer cl-at-102-/);
  assert.match(JSON.parse(call.body).note, /^Transferred from: Asha Rao$/m);
});

// ─── regressions from earlier reviews ────────────────────────────────────────
test('a callback signed by another Vobiz account cannot reach this account\'s numbers or calls', async () => {
  const mark = fetched().length;
  // Account TWO signs a fake inbound call to account ONE's number, naming itself.
  const withParent = await vobizPost('/vobiz/answer', { CallUUID: 'forged-1', From: '+917000000077', To: '+910000000001', ParentAuthID: TWO.authId }, TWO.authToken);
  assert.equal(withParent.status, 403);
  const noParent = await vobizPost('/vobiz/answer', { CallUUID: 'forged-2', From: '+917000000077', To: '+910000000001' }, TWO.authToken);
  assert.equal(noParent.status, 403);
  // Correctly signed by ONE, but claiming to be about TWO.
  const mismatch = await vobizPost('/vobiz/answer', { CallUUID: 'forged-3', From: '+917000000077', To: '+910000000001', ParentAuthID: TWO.authId }, ONE.authToken);
  assert.equal(mismatch.status, 403);
  // A hangup for one of ONE's real calls, signed by TWO.
  const hangup = await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-1', Event: 'Hangup', ParentAuthID: TWO.authId }, TWO.authToken);
  assert.equal(hangup.status, 403);
  await sleep(150);
  assert.equal(clWrites(mark).length, 0, 'nothing was written to Close');
});

test('there is no SIP-direct sign-in to claim someone else\'s endpoint', async () => {
  const r = await req('/api/login-sip', post({ sipUser: asha.v.sipUser, callerId: '+910000000001' }, ben.token));
  assert.equal(r.status, 404);
});

test('a replayed signed callback is refused', async () => {
  const p = '/vobiz/dial-events';
  const nonce = crypto.randomBytes(8).toString('hex');
  const sig = crypto.createHmac('sha256', ONE.authToken).update(`${PUBLIC}${p}.${nonce}`).digest('base64');
  const send = fields => req(p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Vobiz-Signature-V3': sig, 'X-Vobiz-Signature-V3-Nonce': nonce },
    body: new URLSearchParams(fields).toString(),
  });
  assert.equal((await send({ CallUUID: 'call-in-1', Event: 'DialHangup', DialBLegDuration: '252' })).status, 200);
  // Same headers, different body: the signature does not cover the body.
  assert.equal((await send({ CallUUID: 'call-in-1', Event: 'DialHangup', DialBLegDuration: '1' })).status, 403);
});

test('recording audio on a storage host never receives Vobiz credentials, even through a redirect', async () => {
  const link = callUuid => {
    const exp = Math.floor(Date.now() / 1000) + 600;
    const sig = crypto.createHmac('sha256', 'test-signing-secret').update(`rec|${ONE.authId}|${callUuid}|${exp}`).digest('hex');
    return `/recordings/${callUuid}?aid=${ONE.authId}&exp=${exp}&sig=${sig}`;
  };
  const mark = fetched().length;
  const direct = await req(link('call-ext'));
  assert.equal(direct.status, 200);
  assert.equal(await direct.text(), 'AUDIO:rec-ext.mp3');
  const viaRedirect = await req(link('call-redir'));
  assert.equal(viaRedirect.status, 200);
  assert.equal(await viaRedirect.text(), 'AUDIO:rec-redir.mp3');
  const storage = fetched().slice(mark).filter(f => f.url.startsWith('https://storage.example.test/'));
  assert.equal(storage.length, 2);
  for (const f of storage) assert.equal(f.authToken, null, `credentials sent to ${f.url}`);
  assert.ok(fetched().slice(mark).some(f => f.url.startsWith('https://media.vobiz.test/redirect/') && f.authToken === ONE.authToken), 'the trusted Vobiz media host still gets them');
});

// ─── security regressions from earlier integrations ──────────────────────────
test('no route hands out a SIP password without a session, and there is no /agent/:id', async () => {
  assert.equal((await req('/api/agent')).status, 401);
  assert.equal((await req('/agent/anyone')).status, 404);
  assert.equal((await req('/api/agent/anyone')).status, 404);
});

test('no open recording proxy', async () => {
  assert.equal((await req('/recording-file?url=https://example.com/')).status, 404);
  assert.equal((await req('/recordings/x?url=https://example.com/')).status, 403);
});

test('no CORS: a foreign origin gets no Access-Control-Allow-Origin', async () => {
  const r = await req('/api/session', { headers: { Origin: 'https://evil.example' } });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  const pre = await req('/api/login', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
  assert.equal(pre.headers.get('access-control-allow-origin'), null);
});

test('no path traversal out of the static folder', async () => {
  for (const p of ['/static/../backend/.env', '/static/..%2f..%2fbackend%2f.env', '/static/%2e%2e/backend/server.js', '/static/.env']) {
    const r = await req(p);
    const t = await r.text();
    assert.notEqual(r.status, 200, p);
    assert.doesNotMatch(t, /SIGNING_SECRET|require\(/, p);
  }
});

test('the softphone and the dial handler page are never framed and load no foreign script', async () => {
  for (const p of ['/phone', '/dial?to=tel%3A%2B919000000011', '/dial?contact=cont_priya00001']) {
    const r = await req(p);
    assert.equal(r.status, 200, p);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    const csp = r.headers.get('content-security-policy');
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /script-src 'self'(;|$)/);
    await r.text();
  }
});

test('health reveals nothing', async () => {
  assert.deepEqual(await json(await req('/health')), { ok: true });
});

test('no Vobiz Auth Token, Close token or API key ever appeared in a response body', () => {
  const all = seenBodies.join('\n');
  for (const secret of [ONE.authToken, TWO.authToken, 'cl-at-', 'cl-rt-', CARA_KEY, 'close-secret-test']) {
    assert.ok(!all.includes(secret), `${secret} leaked into a response`);
  }
});

test('nothing secret was written to the data dir in clear text, and no credential was sent to a foreign host', () => {
  const raw = fs.readFileSync(path.join(DATA_DIR, 'store.json'), 'utf8');
  for (const secret of [ONE.authToken, TWO.authToken, 'cl-at-', 'cl-rt-', CARA_KEY, 'close-secret-test']) {
    assert.ok(!raw.includes(secret), `${String(secret).slice(0, 8)} written to disk`);
  }
  for (const f of fetched()) {
    if (f.authorization && /cl-at-|^Basic /.test(f.authorization)) assert.ok(f.url.startsWith(`${CLOSE_API}/`), f.url);
    if (f.body && String(f.body).includes('close-secret-test')) assert.ok(f.url.startsWith(`${CLOSE_API}/oauth2/`), f.url);
    if (f.authToken) assert.ok(f.url.startsWith('https://api.vobiz.ai/') || f.url.startsWith('https://media.vobiz.test/'), f.url);
  }
});

test('nobody signed in for a number: polite hangup, never silence', async () => {
  assert.equal((await req('/api/logout', post({}, cara.token))).status, 200);
  const x = await body(await vobizPost('/vobiz/answer', { CallUUID: 'call-in-9', From: '+917000000002', To: '+910000000003', ParentAuthID: TWO.authId }, TWO.authToken));
  assert.doesNotMatch(x, /<Dial/);
  assert.match(x, /<Speak>[^<]+<\/Speak>\s*<Hangup\/>/);
});

test('one Vobiz account, two Close organizations: the call is logged where the answering agent works', async () => {
  // Cara (organization Globex, API key) also signs in with account ONE.
  const cara2 = await connectKey(CARA_KEY);
  cara2.v = await vobizLogin(cara2.token, ONE);
  const x = await body(await vobizPost('/vobiz/answer', { CallUUID: 'call-in-mw', From: '+919000000011', To: '+910000000001', ParentAuthID: ONE.authId }, ONE.authToken));
  assert.ok(x.includes(`<User>sip:${cara2.v.sipUser}@registrar.vobiz.ai</User>`));
  const mark = fetched().length;
  await vobizPost('/vobiz/dial-events', { CallUUID: 'call-in-mw', Event: 'DialAnswer', DialBLegTo: `sip:${cara2.v.sipUser}@registrar.vobiz.ai` }, ONE.authToken);
  await vobizPost('/vobiz/hangup', { CallUUID: 'call-in-mw', Event: 'Hangup' }, ONE.authToken);
  const call = await waitFor(() => callPosts(mark)[0], 'call for the answering organization');
  assert.equal(call.authorization, basicOf(CARA_KEY), 'written with Cara\'s own key');
  assert.equal(JSON.parse(call.body).lead_id, 'lead_othertenant', 'Globex\'s own lead, not Acme\'s');
  assert.equal((await req('/api/logout', post({}, cara2.token))).status, 200);
});

test('sub-accounts: callbacks carry the main account as ParentAuthID and are accepted; a different main account is not', async () => {
  const SUB = { authId: 'SA_TEST0003', authToken: 'tok-sub-three', parent: 'MA_TEST0009' };
  const agent = await connectKey(CARA_KEY);
  agent.v = await vobizLogin(agent.token, SUB);
  const from = `sip:${agent.v.sipUser}@registrar.vobiz.ai`;
  // Outbound from the sub-account's endpoint: the live failure that showed this.
  const res = await vobizPost('/vobiz/answer', { CallUUID: 'call-sub-out', From: from, To: '+919000000011', ParentAuthID: SUB.parent }, SUB.authToken);
  assert.equal(res.status, 200);
  assert.match(await body(res), /<Dial callerId="\+910000000009"[\s\S]*<Number>\+919000000011<\/Number>/);
  const dial = await vobizPost('/vobiz/dial-events', { CallUUID: 'call-sub-out', Event: 'DialAnswer', ParentAuthID: SUB.parent }, SUB.authToken);
  assert.equal(dial.status, 200);
  // Inbound to the sub-account's number.
  const inbound = await vobizPost('/vobiz/answer', { CallUUID: 'call-sub-in', From: '+917000000088', To: '+910000000009', ParentAuthID: SUB.parent }, SUB.authToken);
  assert.ok((await body(inbound)).includes(`<User>${from}</User>`));
  // Once a parent is seen on a signed callback, another main account is refused.
  const other = await vobizPost('/vobiz/answer', { CallUUID: 'call-sub-x', From: from, To: '+919000000011', ParentAuthID: 'MA_TEST0008' }, SUB.authToken);
  assert.equal(other.status, 403);
  // A main account is its own parent: naming any other is still refused.
  const main = await vobizPost('/vobiz/answer', { CallUUID: 'call-main-x', From: '+917000000088', To: '+910000000001', ParentAuthID: SUB.parent }, ONE.authToken);
  assert.equal(main.status, 403);
  // The sub-account's own token is the only one that verifies its callbacks.
  const wrongKey = await vobizPost('/vobiz/answer', { CallUUID: 'call-sub-y', From: from, To: '+919000000011', ParentAuthID: SUB.parent }, ONE.authToken);
  assert.equal(wrongKey.status, 403);
  assert.equal((await req('/api/logout', post({}, agent.token))).status, 200);
});

test('disconnecting an OAuth user revokes their Close refresh token', async () => {
  const temp = await connect(102);
  const mark = fetched().length;
  assert.equal((await req('/api/close/disconnect', post({ scope: 'me' }, temp.token))).status, 200);
  const rv = await waitFor(() => fetched().slice(mark).find(f => f.url === `${CLOSE_API}/oauth2/revoke/`), 'revoke');
  assert.match(new URLSearchParams(rv.body).get('token'), /^cl-rt-102-/);
  assert.equal((await req('/api/session', bearer(temp.token))).status, 401);
});

test('only an admin disconnects an organization; it signs its agents out and deletes its data', async () => {
  assert.equal((await req('/api/close/disconnect', post({ scope: 'workspace' }, asha.token))).status, 200, 'Asha is an Acme admin');
  assert.equal((await req('/api/session', bearer(asha.token))).status, 401);
  const owner = await connectKey(CARA_KEY);
  const member = await connectKey('api_TESTben0000000000000000000');
  assert.equal((await req('/api/close/disconnect', post({ scope: 'workspace' }, member.token))).status, 403, 'Ben is not an admin');
  assert.equal((await req('/api/close/disconnect', post({ scope: 'workspace' }, owner.token))).status, 200);
  const d = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'store.json'), 'utf8'));
  assert.ok(!Object.values(d.workspaces).some(w => w.name === 'Globex'));
  assert.ok(!Object.values(d.users).some(u => u.userId === 'user_cara00001'));
  assert.ok(Object.values(d.users).some(u => u.userId === 'user_ben000001'), 'the other organization\'s user is untouched');
});

// Last: it uses up this client address's API-key tries for a minute.
test('the API-key route cannot be used to hammer Close', async () => {
  let last;
  for (let i = 0; i < 12; i++) last = await req('/api/identity/apikey', post({ apiKey: 'api_TESTwrong00000000000000000' }));
  assert.equal(last.status, 429);
});
