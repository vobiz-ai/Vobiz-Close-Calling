/**
 * Routes the softphone tab calls, and the Close connect flow.
 *
 * Order of sign-in: the agent connects Close first (that is who they are, and
 * whose name calls are logged under), with OAuth or their own Close API key,
 * then signs in to Vobiz with an account (Auth ID + Auth Token).
 *
 * Every route under /api is behind a Bearer session token, except the two that
 * create one. No route returns a SIP password or access token, a list of accounts, or a list
 * of endpoints without one.
 */
const express = require('express');
const crypto = require('node:crypto');
const config = require('./config');
const store = require('./store');
const v = require('./vobiz');
const cl = require('./close');
const logger = require('./call-logger');
const events = require('./events');
const { state, liveSessions, sessionExpired } = require('./state');
const { log, toE164, isE164, randomToken, safeEqual } = require('./util');

const AUTH_ID_RE = /^[A-Za-z0-9_]{4,64}$/;

// ─── sessions ────────────────────────────────────────────────────────────────

function sessionFrom(req) {
  const h = String(req.headers.authorization || '');
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const s = state.sessions.get(token);
  if (!s) return null;
  if (sessionExpired(s)) { state.sessions.delete(token); return null; }
  return { token, s };
}

function requireIdentity(req, res, next) {
  const found = sessionFrom(req);
  if (!found) return res.status(401).json({ error: 'Not signed in', code: 'signed_out' });
  req.token = found.token;
  req.sess = found.s;
  next();
}

function requireVobiz(req, res, next) {
  requireIdentity(req, res, () => {
    if (req.sess.mode !== 'account') return res.status(403).json({ error: 'Sign in with your Vobiz account to use this.', code: 'needs_account' });
    if (!state.accounts.get(req.sess.authId)) return res.status(401).json({ error: 'Session expired. Sign in again.', code: 'signed_out' });
    next();
  });
}

function requireAdmin(req, res, next) {
  requireIdentity(req, res, () => {
    const u = cl.getUser(req.sess.wsKey, req.sess.userId);
    if (!u || !u.admin) return res.status(403).json({ error: 'Only a Close organization admin can change this.' });
    next();
  });
}

// Alphanumeric, because it becomes part of a Vobiz SIP username.
const agentKeyOf = (wsKey, userId) => `cl${crypto.createHash('sha256').update(`${wsKey}|${userId}`).digest('hex').slice(0, 14)}`;

/** End a session: its stream, its SIP routing entry. */
function endSession(token, reason) {
  const s = state.sessions.get(token);
  if (!s) return;
  events.pushToSession(token, { type: 'signed-out', reason });
  events.closeSession(token);
  state.sessions.delete(token);
  if (s.sipUser && !liveSessions().some(([, o]) => o.sipUser === s.sipUser)) {
    state.sipUsers.delete(s.sipUser);
  }
}

function publicSession(s) {
  const ws = cl.getWorkspace(s.wsKey) || {};
  const user = cl.getUser(s.wsKey, s.userId) || {};
  const account = s.authId && state.accounts.get(s.authId);
  return {
    user: { name: s.name, id: s.userId, admin: !!user.admin, auth: user.auth || null },
    workspace: { name: ws.name || 'Close', appUrl: config.CLOSE_APP_URL },
    mode: s.mode || null,
    authId: s.authId || null,
    numbers: s.numbers || [],
    numberApps: account ? Object.fromEntries((s.numbers || []).map(n => [n, (account.numberApps || {})[n] || null])) : {},
    appId: (account && account.appId) || null,
    from: s.from || null,
    sipUser: s.sipUser || null,
    settings: {
      autoOpen: !!(ws.settings && ws.settings.autoOpen),
      defaultCountry: (ws.settings && ws.settings.defaultCountry) || config.DEFAULT_COUNTRY,
    },
  };
}

function newSession(user) {
  const token = randomToken(32);
  state.sessions.set(token, {
    wsKey: user.wsKey, userId: user.userId, name: user.name,
    agentKey: agentKeyOf(user.wsKey, user.userId), createdAt: Date.now(), mode: null,
  });
  return { token, session: publicSession(state.sessions.get(token)) };
}

// ─── Close OAuth ─────────────────────────────────────────────────────────────

const oauth = express.Router();
const COOKIE = 'vz_cl_oauth';

function readCookie(req, name) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

const apiKeysAllowed = () => config.CLOSE_ALLOW_API_KEYS || !cl.oauthEnabled();

/** Which ways of connecting Close this deployment offers. Public: no secrets. */
oauth.get('/options', (req, res) => res.json({ oauth: cl.oauthEnabled(), apiKey: apiKeysAllowed() }));

oauth.get('/start', (req, res) => {
  if (!config.PUBLIC_BASE_URL) return res.status(500).type('text/plain').send('This server has no PUBLIC_BASE_URL, so Close cannot send you back here. Ask your administrator.');
  if (!cl.oauthEnabled()) return res.status(404).type('text/plain').send('This calling service has no Close OAuth app. Connect with your Close API key instead.');
  const st = randomToken(24);
  state.oauthStates.set(st, { exp: Date.now() + 10 * 60 * 1000 });
  // The cookie binds the callback to the browser that started it.
  res.cookie(COOKIE, st, { httpOnly: true, secure: config.PUBLIC_BASE_URL.startsWith('https://'), sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/close/oauth' });
  return res.redirect(302, cl.authorizeUrl(st));
});

oauth.get('/callback', async (req, res) => {
  const st = String(req.query.state || '');
  const code = String(req.query.code || '');
  const entry = st && state.oauthStates.get(st);
  const cookie = readCookie(req, COOKIE);
  res.clearCookie(COOKIE, { path: '/close/oauth' });
  if (!entry || entry.exp < Date.now() || !cookie || !safeEqual(cookie, st)) {
    return res.status(400).type('text/plain').send('This Close sign-in link is not valid any more. Go back to the softphone and click "Connect Close" again.');
  }
  state.oauthStates.delete(st);
  if (!code) return res.redirect(302, '/phone#error=denied');
  try {
    const tokens = await cl.exchangeCode(code);
    const me = await cl.getMe(`Bearer ${tokens.access_token}`, tokens.organization_id ? String(tokens.organization_id) : null);
    if (tokens.user_id && String(tokens.user_id) !== me.userId) throw new Error('the token\'s user and /me/ disagree');
    const user = cl.saveUser(me, { kind: 'oauth', tokens });
    log(`Close connected (OAuth): user ${user.userId} of ${user.wsKey}${user.admin ? ' (admin)' : ''}`);
    if (!tokens.refresh_token) log(`! Close sent no refresh token: give the OAuth app the offline_access scope, or ${user.userId} must reconnect every hour`);
    const link = randomToken(24);
    state.linkCodes.set(link, { wsKey: user.wsKey, userId: user.userId, exp: Date.now() + 2 * 60 * 1000 });
    // A fragment is never sent to any server or written to access logs.
    return res.redirect(302, `/phone#link=${encodeURIComponent(link)}`);
  } catch (err) {
    log(`x Close connect failed: ${err.message}`);
    return res.redirect(302, '/phone#error=connect');
  }
});

// ─── softphone API ───────────────────────────────────────────────────────────

const api = express.Router();
api.use(express.json({ limit: '32kb' }));

/** Trade the one-time link code from the OAuth redirect for a session. */
api.post('/identity/claim', (req, res) => {
  const code = String((req.body && req.body.code) || '');
  const entry = code && state.linkCodes.get(code);
  if (!entry || entry.exp < Date.now()) return res.status(401).json({ error: 'That link has expired. Connect Close again.' });
  state.linkCodes.delete(code);
  const user = cl.getUser(entry.wsKey, entry.userId);
  if (!user) return res.status(401).json({ error: 'Connect Close again.' });
  res.json(newSession(user));
});

/**
 * Connect with the agent's own Close API key (Settings > Developer > API Keys).
 * The key is checked with Close, stored encrypted, and never sent back. Calls
 * are then written as the key's owner, which is the agent.
 */
const API_KEY_RE = /^[A-Za-z0-9._-]{16,200}$/;
// The one route that reaches Close without a session: at most 10 tries a
// minute per client address, so it cannot be used to hammer Close.
const keyTries = new Map();
function tooManyKeyTries(ip) {
  const now = Date.now();
  for (const [k, t] of keyTries) if (t.reset < now) keyTries.delete(k);
  const t = keyTries.get(ip) || { n: 0, reset: now + 60 * 1000 };
  t.n += 1;
  keyTries.set(ip, t);
  return t.n > 10;
}
api.post('/identity/apikey', async (req, res) => {
  if (!apiKeysAllowed()) return res.status(403).json({ error: 'This calling service connects Close with OAuth only.' });
  if (tooManyKeyTries(String(req.socket.remoteAddress || ''))) return res.status(429).json({ error: 'Too many tries. Wait a minute.' });
  const apiKey = String((req.body && req.body.apiKey) || '').trim();
  if (!API_KEY_RE.test(apiKey)) return res.status(400).json({ error: 'Paste your Close API key.' });
  try {
    const me = await cl.getMe(cl.basic(apiKey), null);
    const user = cl.saveUser(me, { kind: 'apikey', apiKey });
    log(`Close connected (API key): user ${user.userId} of ${user.wsKey}${user.admin ? ' (admin)' : ''}`);
    res.json(newSession(user));
  } catch (err) {
    log(`x Close API key refused: ${err.message}`);
    if (err.status === 401) return res.status(401).json({ error: 'Close did not accept that API key. Copy it again from Close: Settings, Developer, API Keys.' });
    res.status(502).json({ error: 'Could not check the key with Close. Try again.' });
  }
});

api.get('/session', requireIdentity, (req, res) => res.json(publicSession(req.sess)));

api.post('/login', requireIdentity, async (req, res) => {
  const { authId, authToken } = req.body || {};
  if (!AUTH_ID_RE.test(String(authId || '')) || typeof authToken !== 'string' || !authToken) {
    return res.status(400).json({ error: 'Enter your Vobiz Auth ID and Auth Token.' });
  }
  if (!config.PUBLIC_BASE_URL.startsWith('https://')) {
    return res.status(500).json({ error: 'This server has no public https PUBLIC_BASE_URL, so Vobiz could not reach it. Ask your administrator.' });
  }
  const candidate = { authId: String(authId), authToken };
  const list = await v.fetchAccountNumbers(candidate);
  if (!list.all) {
    log(`login refused for ${authId}: Vobiz returned ${list.status} checking the credentials`);
    return res.status(401).json({ error: 'Vobiz did not accept that Auth ID and Auth Token. Copy both from the Vobiz Console and try again.' });
  }
  const account = state.accounts.get(candidate.authId) || { authId: candidate.authId };
  account.authToken = authToken;
  account.numbers = list.all;
  account.callerIds = list.callerIds;
  account.numberApps = list.apps;
  state.accounts.set(account.authId, account);

  const s = req.sess;
  const appId = await v.ensureApplication(account);
  if (!appId) return res.status(502).json({ error: 'Could not find or create the calling application in your Vobiz account.' });

  let sip;
  let bound = true;
  if (config.VOBIZ_SIP_AUTH === 'jwt') {
    // No endpoint: the identity comes from the token's sub. One mint now, so
    // an account that cannot issue tokens fails here and not at registration.
    const minted = await v.mintAccessToken(account, { sub: s.agentKey, appId, ttl: config.VOBIZ_JWT_TTL_SECONDS });
    if (!minted) return res.status(502).json({ error: 'Vobiz would not issue an access token for this account. Try again, or ask your administrator.' });
    sip = { sipAuth: 'jwt', sipUser: v.jwtSipUser(s.agentKey, account.authId), sipPassword: null, endpointId: null };
  } else {
    const ep = await v.ensureEndpoint(account, s.agentKey);
    if (!ep) return res.status(502).json({ error: 'Could not set up your SIP endpoint in your Vobiz account.' });
    bound = await v.bindEndpoint(account, ep.endpointId, appId);
    if (!bound) log(`! ${account.authId}: endpoint ${ep.endpointId} is not bound to ${appId}; outbound calls may not reach /vobiz/answer`);
    sip = { sipAuth: 'endpoint', sipUser: ep.username, sipPassword: ep.password, endpointId: ep.endpointId };
  }

  // One tab per agent: with an endpoint the password just rotated, so another
  // session holds a dead one, and with a token two tabs would both ring. End
  // it: that tab shows "signed in elsewhere" instead of looking ready.
  for (const [t, o] of liveSessions()) {
    if (t !== req.token && o.agentKey === s.agentKey && o.mode) endSession(t, 'elsewhere');
  }
  const d = store.load();
  const links = d.accountLinks[account.authId] || [];
  if (!links.includes(s.wsKey)) { d.accountLinks[account.authId] = [...links, s.wsKey]; store.saveNow(); }

  const numbers = list.callerIds;
  const from = numbers.includes(s.lastCallerId) ? s.lastCallerId : (numbers[0] || '');
  Object.assign(s, { mode: 'account', authId: account.authId, numbers, from, ...sip });
  state.sipUsers.set(sip.sipUser, { authId: account.authId, agentKey: s.agentKey, wsKey: s.wsKey, userId: s.userId, name: s.name, callerId: from });
  log(`login ok: ${account.authId} / ${s.agentKey} as ${sip.sipUser} (${sip.sipAuth}), ${numbers.length} caller ID(s)`);
  res.json({ ...publicSession(s), bound });
});

/**
 * A fresh access token for this tab's SIP identity. The softphone calls it to
 * register and again shortly before each token expires. Only the token goes
 * out; the Auth Token that signed it stays in memory here.
 */
api.post('/sip-token', requireVobiz, async (req, res) => {
  const s = req.sess;
  res.set('Cache-Control', 'no-store');
  if (s.sipAuth !== 'jwt') return res.status(400).json({ error: 'This sign-in uses a SIP password, not an access token.' });
  // Renewal is about once an hour; this only stops a loop from hammering Vobiz.
  if (s.lastMintAt && Date.now() - s.lastMintAt < 5000) return res.status(429).json({ error: 'Too many token requests. Wait a few seconds.' });
  s.lastMintAt = Date.now();
  const account = state.accounts.get(s.authId);
  const minted = await v.mintAccessToken(account, { sub: s.agentKey, appId: account.appId, ttl: config.VOBIZ_JWT_TTL_SECONDS });
  if (!minted) return res.status(502).json({ error: 'Vobiz would not issue an access token. Try again.' });
  res.json({ token: minted.token, exp: minted.exp, sipUser: `${s.sipUser}@${config.VOBIZ_REGISTRAR}` });
});

// There is no "SIP direct" sign-in (an existing endpoint's username and
// password, no account credentials). With no Auth Token the backend cannot
// verify Vobiz callbacks about those calls, and cannot prove the agent owns
// the endpoint, so anyone could claim an endpoint and have its calls logged
// into their organization. Agents sign in with their Vobiz account.

api.post('/logout', requireIdentity, (req, res) => {
  endSession(req.token, 'logout');
  res.json({ ok: true });
});

/**
 * The SIP identity this tab registers as, and how: "jwt" (fetch a token from
 * /sip-token) or "endpoint" (with the password minted at this sign-in).
 * Behind the session on purpose: there is no /agent/:id route.
 */
api.get('/agent', requireVobiz, (req, res) => {
  const s = req.sess;
  res.set('Cache-Control', 'no-store');
  res.json({
    sipUser: `${s.sipUser}@${config.VOBIZ_REGISTRAR}`, auth: s.sipAuth,
    ...(s.sipAuth === 'endpoint' ? { sipPassword: s.sipPassword } : {}),
    registrarUrl: `wss://${config.VOBIZ_REGISTRAR}:5063/`, displayName: s.name,
  });
});

api.get('/numbers', requireVobiz, (req, res) => res.json(publicSession(req.sess)));

api.post('/select-number', requireVobiz, (req, res) => {
  const number = String((req.body && req.body.number) || '');
  const s = req.sess;
  if (!s.numbers.includes(number)) return res.status(400).json({ error: 'That number is not one of your Vobiz numbers.' });
  s.from = number;
  s.lastCallerId = number;
  const who = state.sipUsers.get(s.sipUser);
  if (who) who.callerId = number;
  res.json({ from: number });
});

/** "Enable inbound calls": moves the number onto this application. Explicit only. */
api.post('/setup-inbound', requireVobiz, async (req, res) => {
  const s = req.sess;
  const account = state.accounts.get(s.authId);
  const number = String((req.body && req.body.number) || s.from || '');
  if (!s.numbers.includes(number)) return res.status(400).json({ error: 'Pick one of your Vobiz numbers first.' });
  const appId = await v.ensureApplication(account);
  if (!appId) return res.status(502).json({ error: 'Could not find or create the calling application.' });
  const previousAppId = (account.numberApps || {})[number] || null;
  const r = await v.attachNumber(account, number, appId);
  log(`${account.authId}: attach ${number} to ${appId} (was ${previousAppId || 'none'}): HTTP ${r.status}`);
  if (!v.ok(r)) return res.status(502).json({ error: `Vobiz returned ${r.status} attaching ${number}.` });
  account.numberApps = { ...(account.numberApps || {}), [number]: appId };
  res.json({ ok: true, number, appId, previousAppId });
});

const closeErr = (res, err) => res.status(err.code === 'not_connected' ? 401 : 502)
  .json({ error: err.message, code: err.code === 'not_connected' ? 'close_reconnect' : err.code });

/** A Close contact as the softphone shows it, with its lead's name and status. */
async function cardFor(s, contact, leads) {
  let lead = leads.get(contact.lead_id);
  if (lead === undefined) {
    try { lead = await cl.getLead(s.wsKey, s.userId, contact.lead_id); } catch { lead = null; }
    leads.set(contact.lead_id, lead);
  }
  const leadName = lead && lead.display_name ? String(lead.display_name) : '';
  return {
    id: String(contact.id), leadId: String(contact.lead_id), name: cl.contactName(contact) || leadName,
    company: leadName || null, status: lead && lead.status_label ? String(lead.status_label) : '',
    jobTitle: contact.title || '', url: cl.leadUrl(contact.lead_id),
  };
}

/** The lead's last calls through this softphone, for the ringing card. */
function recentFor(s, leadId) {
  if (!leadId) return [];
  return Object.entries(store.load().calls)
    .filter(([, c]) => c.wsKey === s.wsKey && c.leadId === leadId && c.activityId)
    .sort((a, b) => (b[1].startedAt || 0) - (a[1].startedAt || 0)).slice(0, 3)
    .map(([callUuid, c]) => ({ callUuid, direction: c.direction, outcome: c.outcome, talkSeconds: c.talkSeconds, startedAt: c.startedAt }));
}

/** Caller lookup for the ringing card and the in-call contact card. */
api.get('/lookup', requireIdentity, async (req, res) => {
  const s = req.sess;
  const country = cl.countryFor(s.wsKey);
  const e164 = toE164(req.query.number, country);
  if (!isE164(e164)) return res.status(400).json({ error: 'Not a phone number' });
  try {
    const contacts = (await cl.findContactsByPhone(s.wsKey, s.userId, e164, country)).slice(0, 3);
    const leads = new Map();
    const people = [];
    for (const c of contacts) people.push(await cardFor(s, c, leads));
    res.json({ number: e164, people, recent: recentFor(s, people[0] && people[0].leadId) });
  } catch (err) { closeErr(res, err); }
});

/**
 * The numbers on one Close contact or lead, for a click-to-call that names a
 * record (a Close Integration Link) instead of a number. Ids must look like
 * Close's own before they go into a request path.
 */
api.get('/record-phones', requireIdentity, async (req, res) => {
  const s = req.sess;
  const contactId = String(req.query.contact || '');
  const leadId = String(req.query.lead || '');
  if (!cl.isCloseId(contactId, 'cont') && !cl.isCloseId(leadId, 'lead')) return res.status(400).json({ error: 'Not a Close contact or lead id' });
  const country = cl.countryFor(s.wsKey);
  const fields = '_fields=id,lead_id,name,display_name,title,phones';
  try {
    const list = cl.isCloseId(contactId, 'cont')
      ? [await cl.api(s.wsKey, s.userId, 'GET', `/contact/${contactId}/?${fields}`)]
      : (((await cl.api(s.wsKey, s.userId, 'GET', `/contact/?lead_id=${leadId}&${fields}`)) || {}).data || []);
    const phones = [];
    for (const c of list) {
      for (const n of cl.phonesOf(c, country)) if (!phones.some(p => p.number === n)) phones.push({ number: n, name: cl.contactName(c) });
    }
    res.json({ phones: phones.slice(0, 10) });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'That Close record was not found in your organization.' });
    closeErr(res, err);
  }
});

/** Calls this agent handled, newest first, with fresh recording links. */
api.get('/calls', requireIdentity, (req, res) => {
  const s = req.sess;
  const settings = logger.settingsFor(s.wsKey);
  const d = store.load();
  const calls = Object.entries(d.calls)
    .filter(([, c]) => c.wsKey === s.wsKey && c.userId === s.userId && c.logged)
    .sort((a, b) => (b[1].startedAt || 0) - (a[1].startedAt || 0)).slice(0, 20)
    .map(([callUuid, c]) => ({
      callUuid, direction: c.direction, outcome: c.outcome, talkSeconds: c.talkSeconds, remote: c.remote, startedAt: c.startedAt,
      contactName: c.contactName || '', leadUrl: cl.leadUrl(c.leadId),
      recordingUrl: c.recordingId && c.authId ? logger.recordingLink(c.authId, callUuid, settings.recordingTtlSeconds) : null,
    }));
  res.json({ calls });
});

api.get('/events', requireIdentity, (req, res) => events.attach(req.token, res));

/**
 * The softphone's report of an outbound call. Calls that reached /vobiz/answer
 * are logged from the server's own record; this only covers an INVITE that
 * never got there (JsSIP "failed" before Vobiz ran our XML), so no call is
 * ever silently dropped.
 */
const CAUSE_OUTCOME = { Busy: 'busy', Canceled: 'cancelled', 'No Answer': 'no-answer', 'Request Timeout': 'no-answer', Rejected: 'declined' };
api.post('/call-log', requireIdentity, (req, res) => {
  const s = req.sess;
  const b = req.body || {};
  const ref = String(b.ref || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);
  const number = toE164(b.number, cl.countryFor(s.wsKey));
  if (!ref || !isE164(number)) return res.status(400).json({ error: 'ref and number are required' });
  const prior = state.refs.get(ref) || {};
  state.refs.set(ref, { ...prior, report: { cause: String(b.cause || '') }, at: prior.at || Date.now() });
  res.json({ ok: true });
  const t = setTimeout(() => {
    const r = state.refs.get(ref);
    if (!r || r.callUuid || r.panelLogged) return;
    r.panelLogged = true;
    const startedAt = Number(b.startedAt) || Date.now();
    logger.logCall({
      callUuid: `panel-${ref}`, authId: s.authId || null, wsKey: s.wsKey, userId: s.userId, agentName: s.name,
      direction: 'outbound', outcome: CAUSE_OUTCOME[b.cause] || 'failed', talkSeconds: 0, remote: number, did: s.from || '',
      startedAt, endedAt: Date.now(), recordingId: null, hangupCause: String(b.cause || ''),
    });
  }, config.PANEL_REPORT_GRACE_MS);
  if (t.unref) t.unref();
});

/** Other agents of this organization and Vobiz account who can take a transfer. */
api.get('/agents', requireVobiz, (req, res) => {
  const s = req.sess;
  const seen = new Set();
  const agents = [];
  for (const [, o] of liveSessions()) {
    if (o.wsKey !== s.wsKey || o.authId !== s.authId || o.mode !== 'account' || o.userId === s.userId || seen.has(o.userId)) continue;
    seen.add(o.userId);
    agents.push({ userId: o.userId, name: o.name });
  }
  res.json({ agents });
});

/** Blind transfer of an inbound caller to another signed-in agent. */
api.post('/transfer', requireVobiz, async (req, res) => {
  const s = req.sess;
  const target = String((req.body && req.body.userId) || '');
  const call = [...state.calls.values()].find(c => c.agentSipUser === s.sipUser && c.answeredAt && !c.endedAt);
  if (!call) return res.status(404).json({ error: 'No answered call to transfer.' });
  if (call.direction !== 'inbound') return res.status(400).json({ error: 'Transfer is available on inbound calls.' });
  const t = liveSessions().map(([, o]) => o).find(o => o.wsKey === s.wsKey && o.authId === s.authId && o.userId === target && o.mode === 'account' && o.sipUser);
  if (!t) return res.status(404).json({ error: 'That agent is not signed in.' });
  const account = state.accounts.get(s.authId);
  state.transfers.set(call.callUuid, { authId: s.authId, targetSipUser: t.sipUser, callerId: call.did, callerName: call.remote, exp: Date.now() + 60 * 1000 });
  const r = await v.transferLeg(account, call.callUuid, 'aleg', `${config.PUBLIC_BASE_URL}/vobiz/transfer-xml`);
  log(`transfer ${call.callUuid} from ${s.agentKey} to ${t.agentKey}: HTTP ${r.status}`);
  if (!v.ok(r)) { state.transfers.delete(call.callUuid); return res.status(502).json({ error: `Vobiz returned ${r.status} for the transfer.` }); }
  events.pushToUser(t.wsKey, t.userId, { type: 'transfer-incoming', callUuid: call.callUuid, from: call.remote, fromAgent: s.name });
  res.json({ ok: true });
});

// ─── settings (per Close organization) ───────────────────────────────────────

api.get('/settings', requireIdentity, (req, res) => {
  const s = req.sess;
  const ws = cl.getWorkspace(s.wsKey) || {};
  const u = cl.getUser(s.wsKey, s.userId) || {};
  res.json({ admin: !!u.admin, workspace: ws.name || 'Close', settings: logger.settingsFor(s.wsKey) });
});

api.post('/settings', requireAdmin, (req, res) => {
  const ws = cl.getWorkspace(req.sess.wsKey);
  if (!ws) return res.status(404).json({ error: 'Connect Close again.' });
  const b = req.body || {};
  const next = { ...cl.defaultSettings(), ...(ws.settings || {}) };
  if (b.defaultCountry !== undefined && /^[A-Z]{2}$/.test(String(b.defaultCountry))) next.defaultCountry = String(b.defaultCountry);
  if (b.createUnknown !== undefined) next.createUnknown = !!b.createUnknown;
  if (b.missedTask !== undefined) next.missedTask = !!b.missedTask;
  if (b.autoOpen !== undefined) next.autoOpen = !!b.autoOpen;
  if (b.recordingTtlSeconds !== undefined) next.recordingTtlSeconds = Math.min(7 * 86400, Math.max(300, Number(b.recordingTtlSeconds) || config.RECORDING_LINK_TTL_SECONDS));
  ws.settings = next;
  store.saveNow();
  res.json({ settings: next });
});

/** Disconnect: "me" forgets this user's credential; "workspace" (admins) forgets the whole organization's data. */
api.post('/close/disconnect', requireIdentity, (req, res) => {
  const s = req.sess;
  const scope = (req.body && req.body.scope) === 'workspace' ? 'workspace' : 'me';
  const u = cl.getUser(s.wsKey, s.userId);
  if (scope === 'workspace' && !(u && u.admin)) return res.status(403).json({ error: 'Only a Close organization admin can disconnect the whole organization.' });
  for (const [t, o] of liveSessions()) {
    if (o.wsKey === s.wsKey && (scope === 'workspace' || o.userId === s.userId)) endSession(t, 'disconnected');
  }
  if (scope === 'workspace') cl.disconnectWorkspace(s.wsKey); else cl.disconnectUser(s.wsKey, s.userId);
  log(`Close disconnected: ${scope} ${s.wsKey}${scope === 'me' ? `/${s.userId}` : ''}`);
  res.json({ ok: true });
});

module.exports = { api, oauth, requireIdentity };
