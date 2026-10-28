// Preloaded into the backend under test (node -r). Replaces global fetch so no
// request leaves the machine, and records every attempted request to a JSONL
// file so tests can assert on what the server tried to send, and where.
//
// Vobiz: two accounts with obvious fake values. Behaviours copied from the
// real API on purpose:
//  - POST /Endpoint/ rewrites the submitted username;
//  - app ids are 17 digits and come back UNQUOTED, so a server that runs them
//    through JSON.parse/Number gets the wrong id;
//  - MA_TEST0001 binds on {"app_id":"<string>"}; MA_TEST0002 ignores that and
//    only honours {"application": <integer>}.
//  - POST /JWT/Token/ signs access-token claims, refusing a wrong iss or a
//    lifetime outside 180..86400 s.
//
// Close: two organizations, following Close's API reference:
//  - OAuth: POST /oauth2/token/ (form-encoded, with the client secret) returns
//    an access token for 3600 s, a refresh token, organization_id and user_id;
//    every refresh returns a new refresh token;
//  - API keys arrive as HTTP Basic with the key as the user name;
//  - GET /api/v1/me/ lists organizations and memberships (role_id "admin");
//  - POST /api/v1/data/search/ answers contact queries on contact_phone.phone;
//  - activities, leads, contacts and tasks have prefixed ids (acti_, lead_ ...).
// User 102's first access token is rejected after /me/, which exercises
// refresh-on-401. A call Close logged itself for a tel: link click is seeded,
// so the server can be seen filling it in instead of logging a second call.
const fs = require('node:fs');
const LOG = process.env.FETCH_LOG;

const ACCOUNTS = {
  MA_TEST0001: { token: 'tok-account-one', numbers: ['+910000000001', '+910000000002'], inactive: '+910000000005', noVoice: '+910000000006', appId: '43919358318796814', honoursAppId: true },
  MA_TEST0002: { token: 'tok-account-two', numbers: ['+910000000003'], inactive: '+910000000007', noVoice: '+910000000008', appId: '52000000000000017', honoursAppId: false },
  // A sub-account. Vobiz signs its call callbacks with its own token and sends
  // its main account (MA_TEST0009, never signed in here) as ParentAuthID.
  SA_TEST0003: { token: 'tok-sub-three', numbers: ['+910000000009'], inactive: '+910000000010', noVoice: '+910000000011', appId: '61000000000000023', honoursAppId: true },
};
const apps = { MA_TEST0001: [], MA_TEST0002: [], SA_TEST0003: [] };
const endpoints = {};
let nextEndpoint = 700001;
const recordings = {
  MA_TEST0001: [
    { recording_id: 'rec-1', call_uuid: 'call-in-1', recording_url: 'https://media.vobiz.test/rec-1.mp3' },
    // Served by a storage host that must never see the Auth Token, directly
    // and through a redirect from the Vobiz media host.
    { recording_id: 'rec-ext', call_uuid: 'call-ext', recording_url: 'https://storage.example.test/rec-ext.mp3?X-Signature=presigned' },
    { recording_id: 'rec-redir', call_uuid: 'call-redir', recording_url: 'https://media.vobiz.test/redirect/rec-redir.mp3' },
  ],
  MA_TEST0002: [{ recording_id: 'rec-2', call_uuid: 'call-two-1', recording_url: 'https://media.vobiz.test/rec-2.mp3' }],
  SA_TEST0003: [],
};

// ─── Close ───────────────────────────────────────────────────────────────────
const CLIENT = { id: 'close-client-test', secret: 'close-secret-test' };
const ORGS = {
  orga_acme0001: { name: 'Acme' },
  orga_globex001: { name: 'Globex' },
};
const USERS = {
  101: { id: 'user_asha00001', org: 'orga_acme0001', email: 'asha@acme.test', first: 'Asha', last: 'Rao', role: 'admin' },
  102: { id: 'user_ben000001', org: 'orga_acme0001', email: 'ben@acme.test', first: 'Ben', last: 'Ng', role: 'role_salesrep01' },
  201: { id: 'user_cara00001', org: 'orga_globex001', email: 'cara@globex.test', first: 'Cara', last: 'Diaz', role: 'admin' },
};
// Personal API keys (obvious fakes): Cara connects with one.
const API_KEYS = { api_TESTcara000000000000000000: 201, api_TESTben0000000000000000000: 102 };
const usedCodes = new Set();
const access = {};    // access token -> user number
const refresh = {};   // refresh token -> user number
const revokedAfterMe = new Set();
const revoked = [];
let seq = 1;
let issued102 = false;
const BOOT = new Date().toISOString();
const data = {
  orga_acme0001: {
    leads: [
      { id: 'lead_acmetraders', display_name: 'Acme Traders', status_label: 'Qualified' },
      { id: 'lead_ravikumar01', display_name: 'Ravi Kumar', status_label: 'Potential' },
      { id: 'lead_decoy00001', display_name: 'Decoy Inc', status_label: 'Potential' },
    ],
    contacts: [
      { id: 'cont_priya00001', lead_id: 'lead_acmetraders', name: 'Priya Shah', title: 'Buyer', phones: [{ phone: '+919000000011', type: 'office' }] },
      { id: 'cont_ravi000001', lead_id: 'lead_ravikumar01', name: 'Ravi Kumar', title: '', phones: [{ phone: '+917000000099', type: 'office' }, { phone: '+919000000012', type: 'mobile' }] },
      // Shares the last ten digits with Priya's number but not the country code.
      { id: 'cont_decoy00001', lead_id: 'lead_decoy00001', name: 'Decoy Person', title: '', phones: [{ phone: '+1 (900) 000-0011', type: 'office' }] },
    ],
    calls: [
      // What Close itself logs when Asha clicks Ravi's mobile with "Call using tel: links".
      { id: 'acti_tellink0001', lead_id: 'lead_ravikumar01', user_id: 'user_asha00001', phone: '+919000000012', duration: 0, direction: 'outbound', date_created: BOOT },
    ],
    tasks: [],
  },
  orga_globex001: {
    leads: [{ id: 'lead_othertenant', display_name: 'Other Tenant', status_label: 'Potential' }],
    contacts: [{ id: 'cont_other00001', lead_id: 'lead_othertenant', name: 'Other Tenant', title: '', phones: [{ phone: '+919000000011', type: 'office' }] }],
    calls: [], tasks: [],
  },
};

function issue(userNo) {
  const n = seq++;
  const at = `cl-at-${userNo}-${n}`;
  const rt = `cl-rt-${userNo}-${n}`;
  access[at] = userNo;
  refresh[rt] = userNo;
  if (userNo === 102 && !issued102) { issued102 = true; revokedAfterMe.add(at); }
  return { access_token: at, token_type: 'Bearer', expires_in: 3600, refresh_token: rt, scope: 'all.full_access offline_access', organization_id: USERS[userNo].org, user_id: USERS[userNo].id };
}

const digits = s => String(s || '').replace(/\D/g, '');

/** The phone values a search asks for, from exact_value and phrase conditions. */
function searchValues(q, out = []) {
  if (!q || typeof q !== 'object') return out;
  if (q.type === 'field_condition' && q.field && q.field.field_name === 'phone') out.push(q.condition);
  for (const k of ['queries']) for (const x of q[k] || []) searchValues(x, out);
  if (q.related_query) searchValues(q.related_query, out);
  return out;
}

async function close(url, method, h, body) {
  const json = (o, status = 200, extra = {}) => new Response(o === null ? null : JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...extra } });
  const u = new URL(url);
  const p = u.pathname;
  if (p === '/oauth2/token/' && method === 'POST') {
    const b = new URLSearchParams(String(body));
    if (b.get('client_id') !== CLIENT.id || b.get('client_secret') !== CLIENT.secret) return json({ error: 'invalid_client' }, 401);
    if (b.get('grant_type') === 'authorization_code') {
      // The test plays the browser at the authorize page: the code is
      // "code-<user>.<random>", one use only.
      const cm = String(b.get('code')).match(/^code-(\d+)(?:\.[0-9a-f]+)?$/);
      if (!cm || usedCodes.has(b.get('code')) || !USERS[cm[1]]) return json({ error: 'invalid_grant' }, 400);
      usedCodes.add(b.get('code'));
      if (b.get('redirect_uri') !== 'https://calling.example.test/close/oauth/callback') return json({ error: 'invalid_grant' }, 400);
      return json(issue(Number(cm[1])));
    }
    if (b.get('grant_type') === 'refresh_token') {
      const userNo = refresh[b.get('refresh_token')];
      if (!userNo) return json({ error: 'invalid_grant' }, 400);
      delete refresh[b.get('refresh_token')];
      return json(issue(userNo));
    }
    return json({ error: 'unsupported_grant_type' }, 400);
  }
  if (p === '/oauth2/revoke/' && method === 'POST') {
    const b = new URLSearchParams(String(body));
    if (b.get('client_secret') === CLIENT.secret) { revoked.push(b.get('token')); delete refresh[b.get('token')]; }
    return json({});
  }

  const auth = String(h.Authorization || '');
  let userNo = null;
  let bearer = '';
  if (auth.startsWith('Bearer ')) { bearer = auth.slice(7); userNo = access[bearer]; }
  if (auth.startsWith('Basic ')) {
    const [key, pass] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
    if (pass === '') userNo = API_KEYS[key];
  }
  if (!userNo) return json({ error: 'Unauthorized' }, 401);
  const user = USERS[userNo];

  if (p === '/api/v1/me/' && method === 'GET') {
    return json({
      id: user.id, email: user.email, first_name: user.first, last_name: user.last,
      organizations: [{ id: user.org, name: ORGS[user.org].name }],
      memberships: [{ id: `memb_${userNo}`, organization_id: user.org, user_id: user.id, role_id: user.role }],
    });
  }
  if (revokedAfterMe.has(bearer)) { revokedAfterMe.delete(bearer); delete access[bearer]; return json({ error: 'Unauthorized' }, 401); }

  const d = data[user.org];
  const b = body ? JSON.parse(body) : null;
  if (p === '/api/v1/data/search/' && method === 'POST') {
    const conds = searchValues(b.query);
    const hits = d.contacts.filter(c => c.phones.some(ph => conds.some(cd =>
      (cd.mode === 'exact_value' && ph.phone === cd.value) || (cd.mode === 'phrase' && digits(ph.phone).includes(digits(cd.value))))));
    return json({ data: hits.map(c => ({ ...c, display_name: c.name, __object_type: 'contact' })), cursor: null });
  }
  let m = p.match(/^\/api\/v1\/lead\/([^/]+)\/$/);
  if (m && method === 'GET') {
    const lead = d.leads.find(l => l.id === m[1]);
    return lead ? json(lead) : json({ error: 'Not found' }, 404);
  }
  if (p === '/api/v1/lead/' && method === 'POST') {
    const lead = { id: `lead_new${String(seq++).padStart(6, '0')}`, display_name: b.name, status_label: 'Potential' };
    d.leads.push(lead);
    const contacts = (b.contacts || []).map(c => ({ id: `cont_new${String(seq++).padStart(6, '0')}`, lead_id: lead.id, name: c.name, title: '', phones: c.phones || [] }));
    d.contacts.push(...contacts);
    return json({ ...lead, contacts, created_by: user.id });
  }
  m = p.match(/^\/api\/v1\/contact\/([^/]+)\/$/);
  if (m && method === 'GET') {
    const c = d.contacts.find(x => x.id === m[1]);
    return c ? json(c) : json({ error: 'Not found' }, 404);
  }
  if (p === '/api/v1/contact/' && method === 'GET') return json({ data: d.contacts.filter(c => c.lead_id === u.searchParams.get('lead_id')), has_more: false });
  if (p === '/api/v1/activity/call/' && method === 'POST') {
    if (!d.leads.some(l => l.id === b.lead_id)) return json({ 'field-errors': { lead_id: 'Unknown lead' } }, 400);
    const call = { id: `acti_new${String(seq++).padStart(6, '0')}`, ...b, user_id: user.id, created_by: user.id, source: 'External', date_created: new Date().toISOString() };
    d.calls.push(call);
    return json(call);
  }
  if (p === '/api/v1/activity/call/' && method === 'GET') {
    const since = u.searchParams.get('date_created__gte');
    const list = d.calls.filter(c => (!u.searchParams.get('lead_id') || c.lead_id === u.searchParams.get('lead_id'))
      && (!u.searchParams.get('user_id') || c.user_id === u.searchParams.get('user_id')) && (!since || c.date_created >= since));
    return json({ data: list, has_more: false });
  }
  m = p.match(/^\/api\/v1\/activity\/call\/([^/]+)\/$/);
  if (m && method === 'PUT') {
    const call = d.calls.find(c => c.id === m[1]);
    if (!call) return json({ error: 'Not found' }, 404);
    Object.assign(call, b);
    return json(call);
  }
  if (p === '/api/v1/task/' && method === 'POST') {
    const task = { id: `task_new${String(seq++).padStart(6, '0')}`, ...b, created_by: user.id };
    d.tasks.push(task);
    return json(task);
  }
  return json({ unexpected: url }, 404);
}

global.fetch = async (url, opts = {}) => {
  url = String(url);
  const h = opts.headers || {};
  const method = opts.method || 'GET';
  fs.appendFileSync(LOG, JSON.stringify({
    url, method,
    authorization: h.Authorization || null, authId: h['X-Auth-ID'] || null, authToken: h['X-Auth-Token'] || null,
    body: opts.body || null,
  }) + '\n');
  const json = (o, status = 200, extra = {}) => new Response(o === null ? null : JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...extra } });
  const raw = (t, status = 200) => new Response(t, { status, headers: { 'content-type': 'application/json' } });

  if (url.startsWith('https://storage.example.test/')) {
    return new Response(`AUDIO:${new URL(url).pathname.split('/').pop()}`, { status: 200, headers: { 'content-type': 'audio/mpeg' } });
  }
  if (url.startsWith('https://media.vobiz.test/')) {
    const acct = Object.entries(ACCOUNTS).find(([id, a]) => id === h['X-Auth-ID'] && a.token === h['X-Auth-Token']);
    if (!acct) return json({ error: 'unauthorized' }, 401);
    if (url.includes('/redirect/')) return new Response(null, { status: 302, headers: { location: `https://storage.example.test/${url.split('/').pop()}` } });
    return new Response(`AUDIO:${url.split('/').pop()}`, { status: 200, headers: { 'content-type': 'audio/mpeg' } });
  }

  if (url.startsWith('https://api.close.com/')) return close(url, method, h, opts.body);

  if (!url.startsWith('https://api.vobiz.ai/')) return json({ unexpected: url }, 599);
  const m = url.match(/^https:\/\/api\.vobiz\.ai\/api\/v1\/Account\/([^/]+)(\/.*)$/);
  if (!m) return json({}, 404);
  const authId = decodeURIComponent(m[1]);
  const p = m[2];
  const acct = ACCOUNTS[authId];
  if (!acct || h['X-Auth-ID'] !== authId || h['X-Auth-Token'] !== acct.token) return json({ error: 'authentication failed' }, 401);

  if (p.startsWith('/numbers?')) {
    // Two per page whatever per_page says, so the server must really paginate.
    const all = [
      ...acct.numbers.map((e164, i) => ({ e164, status: 'active', voice_enabled: true, application_id: i === 0 ? '20577609616603585' : '' })),
      { e164: acct.inactive, status: 'released', voice_enabled: true },
      { e164: acct.noVoice, status: 'active', voice_enabled: false },
    ];
    const page = Number(new URLSearchParams(p.split('?')[1]).get('page') || 1);
    return json({ items: all.slice((page - 1) * 2, page * 2), page, per_page: 2, total: all.length });
  }
  if (/^\/numbers\/[^/]+\/application$/.test(p) && method === 'POST') return json({ message: 'Number attached to application' });
  if (p.startsWith('/Application/') && method === 'GET') {
    const body = '{"objects":[' + apps[authId].map(a => `{"app_id":${a.app_id},"app_name":"${a.app_name}","answer_url":"${a.answer_url}"}`).join(',') + ']}';
    return raw(body);
  }
  if (p === '/Application/' && method === 'POST') {
    const b = JSON.parse(opts.body);
    apps[authId].push({ app_id: acct.appId, app_name: b.app_name, answer_url: b.answer_url, hangup_url: b.hangup_url });
    return raw(`{"api_id":"x","app_id":${acct.appId},"message":"created"}`, 201);
  }
  if (p.startsWith('/Endpoint/?') && method === 'GET') {
    const alias = new URLSearchParams(p.split('?')[1]).get('alias__exact');
    const list = Object.entries(endpoints).filter(([, e]) => e.authId === authId && (!alias || e.alias === alias));
    return json({ objects: list.map(([id, e]) => ({ endpoint_id: id, username: e.username, alias: e.alias })) });
  }
  if (p === '/Endpoint/' && method === 'POST') {
    const b = JSON.parse(opts.body);
    if (!/^[A-Za-z0-9]+$/.test(b.username)) return json({ error: 'invalid request parameters' }, 400);
    const id = String(nextEndpoint++);
    endpoints[id] = { authId, username: `${b.username}1187694299`, alias: b.alias, password: b.password, app: null };
    return json({ message: 'created', endpoint_id: id }, 201);
  }
  const ep = p.match(/^\/Endpoint\/(\d+)\/$/);
  if (ep) {
    const e = endpoints[ep[1]];
    if (!e || e.authId !== authId) return new Response('', { status: 404 });
    if (method === 'GET') {
      const appPart = e.app ? `{"app_id":${e.app},"app_name":"Close-Calling-Vobiz"}` : 'null';
      return raw(`{"endpoint_id":"${ep[1]}","username":"${e.username}","application":${appPart}}`);
    }
    const text = String(opts.body);
    const b = JSON.parse(text);
    if (b.password) e.password = b.password;
    const appLit = text.match(/"application"\s*:\s*(\d+)/);
    const appIdLit = text.match(/"app_id"\s*:\s*"(\d+)"/);
    if (appLit) e.app = appLit[1];
    if (appIdLit && acct.honoursAppId) e.app = appIdLit[1];
    return new Response('', { status: 202 });
  }
  if (p === '/JWT/Token/' && method === 'POST') {
    // Signs the claims it is sent, HS256 with the Auth Token, after the checks
    // the registrar would otherwise fail on.
    const c = JSON.parse(opts.body);
    const ttl = c.exp - c.nbf;
    if (c.iss !== authId || !c.sub || !(ttl >= 180 && ttl <= 86400) || !c.per || !c.per.voice) return json({ error: 'invalid claims' }, 400);
    const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
    const input = `${b64({ alg: 'HS256', typ: 'JWT', cty: 'auris;v=1' })}.${b64(c)}`;
    const sig = require('node:crypto').createHmac('sha256', acct.token).update(input).digest('base64url');
    return json({ api_id: 'x', token: `${input}.${sig}` });
  }
  if (/^\/Call\/[^/]+\/$/.test(p) && method === 'POST') return json({ message: 'call transferred' }, 202);
  if (p.startsWith('/Recording/?call_uuid=')) {
    return json({ objects: [{ recording_id: 'other', call_uuid: 'someone-else', recording_url: 'https://media.vobiz.test/other.mp3' }, ...recordings[authId]] });
  }
  const rec = p.match(/^\/Recording\/([^/?]+)\/$/);
  if (rec) {
    const found = recordings[authId].find(r => r.recording_id === rec[1]);
    return found ? json(found) : json({ error: 'not found' }, 404);
  }
  return json({}, 404);
};
