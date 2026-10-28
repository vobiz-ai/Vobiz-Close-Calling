/**
 * Vobiz REST, as one account at a time, plus the provisioning each sign-in
 * does inside that account: one application, and per agent either an access
 * token (JWT) or one SIP endpoint.
 */
const crypto = require('node:crypto');
const config = require('./config');
const store = require('./store');
const { log, toE164 } = require('./util');

const APP_NAME = 'Close-Calling-Vobiz';
const ID_RE = /^\d+$/;

// Vobiz app ids are 17 digits, above Number.MAX_SAFE_INTEGER. JSON.parse turns
// an unquoted one into a different number, so id fields are quoted in the raw
// text BEFORE parsing, and every id stays a string from then on.
function parseVobizJson(raw) {
  const quoted = String(raw).replace(/"(app_id|application_id|endpoint_id|application|id)"\s*:\s*(\d+)/g, '"$1":"$2"');
  try { return JSON.parse(quoted); } catch { return raw; }
}

/**
 * One REST call. A string body is sent verbatim, so an id can be spliced in as
 * an integer literal without ever being a JS number; an object is JSON-encoded.
 */
// Every request gets a deadline: a hung request would otherwise hold a call
// in flight forever, so it is never queued or retried.
const timedFetch = (url, opts = {}) => fetch(url, { ...opts, signal: AbortSignal.timeout(15000) });

async function vobiz(account, method, apiPath, rawBody) {
  const url = `${config.VOBIZ_API_BASE}/Account/${encodeURIComponent(account.authId)}${apiPath}`;
  const body = rawBody === undefined ? undefined : (typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody));
  try {
    const res = await timedFetch(url, {
      method,
      headers: {
        'X-Auth-ID': account.authId,
        'X-Auth-Token': account.authToken,
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body !== undefined ? { body } : {}),
    });
    const raw = await res.text();
    return { status: res.status, body: parseVobizJson(raw), raw };
  } catch (err) {
    return { status: 0, body: { error: err.message }, raw: '' };
  }
}

const listOf = r => (r && r.body && (r.body.objects || r.body.items)) || [];
const ok = r => r.status >= 200 && r.status < 300;

/**
 * Every number on the account, paged until `total` are loaded. The first page
 * doubles as the credential check: a non-2xx is returned as { status } only.
 * `callerIds` are the ones usable as a caller ID: active and voice-enabled.
 */
async function fetchAccountNumbers(account) {
  const items = [];
  let status = 0;
  for (let page = 1; page <= 50; page++) {
    const r = await vobiz(account, 'GET', `/numbers?page=${page}&per_page=100`);
    status = r.status;
    if (!ok(r)) return { status };
    const batch = listOf(r);
    items.push(...batch);
    const total = Number(r.body && r.body.total);
    if (!batch.length || (Number.isFinite(total) ? items.length >= total : batch.length < 100)) break;
  }
  const all = [];
  const callerIds = [];
  const apps = {};
  for (const n of items) {
    const e164 = toE164(n.e164 || n.number || n.phone_number || '', 'XX');
    if (!e164) continue;
    all.push(e164);
    if (n.application_id) apps[e164] = String(n.application_id);
    const active = n.status === undefined || n.status === 'active';
    if (active && n.voice_enabled !== false && !callerIds.includes(e164)) callerIds.push(e164);
  }
  return { status, all, callerIds, apps };
}

const answerUrl = () => `${config.PUBLIC_BASE_URL}/vobiz/answer`;

/**
 * Find this integration's application, or create it. Matched on answer_url
 * only, so an application someone else built is never repointed.
 */
async function ensureApplication(account) {
  if (account.appId) return account.appId;
  for (let offset = 0; offset < 1000; offset += 100) {
    const page = await vobiz(account, 'GET', `/Application/?limit=100&offset=${offset}`);
    if (!ok(page)) break;
    const items = listOf(page);
    const hit = items.find(a => a.answer_url === answerUrl());
    if (hit && ID_RE.test(String(hit.app_id || ''))) {
      account.appId = String(hit.app_id);
      return account.appId;
    }
    if (items.length < 100) break;
  }
  const created = await vobiz(account, 'POST', '/Application/', {
    app_name: APP_NAME,
    answer_url: answerUrl(), answer_method: 'POST',
    // Set explicitly: it defaults to answer_url otherwise.
    hangup_url: `${config.PUBLIC_BASE_URL}/vobiz/hangup`, hangup_method: 'POST',
    fallback_answer_url: `${config.PUBLIC_BASE_URL}/vobiz/fallback`,
  });
  const appId = created.body && created.body.app_id ? String(created.body.app_id) : '';
  if (!ok(created) || !ID_RE.test(appId)) {
    log(`x ${account.authId}: could not create the Vobiz application (HTTP ${created.status})`);
    return null;
  }
  log(`${account.authId}: created application ${appId} -> ${answerUrl()}`);
  account.appId = appId;
  return appId;
}

const randomSipPassword = () => `Vz${crypto.randomBytes(18).toString('base64url').replace(/[-_]/g, 'a')}`;

/**
 * One endpoint per (authId, agentKey), created on first sign-in and reused.
 * Every sign-in rotates its SIP password; the new one goes to that browser
 * session only and is never written down.
 */
async function ensureEndpoint(account, agentKey) {
  const d = store.load();
  const key = `${account.authId}:${agentKey}`;
  const password = randomSipPassword();
  const known = d.endpoints[key];

  if (known && known.endpointId) {
    const got = await vobiz(account, 'GET', `/Endpoint/${encodeURIComponent(known.endpointId)}/`);
    if (ok(got)) {
      const reset = await vobiz(account, 'POST', `/Endpoint/${encodeURIComponent(known.endpointId)}/`, { password });
      if (!ok(reset)) {
        log(`x ${account.authId}: could not reset the SIP password for endpoint ${known.endpointId} (HTTP ${reset.status})`);
        return null;
      }
      const username = (got.body && got.body.username) || known.username;
      if (username !== known.username) { d.endpoints[key] = { endpointId: known.endpointId, username }; store.saveNow(); }
      return { endpointId: String(known.endpointId), username, password };
    }
    log(`${account.authId}: stored endpoint ${known.endpointId} for ${agentKey} is gone (HTTP ${got.status}); creating a new one`);
  }

  // The alias names this agent exactly, so an endpoint survives a lost data
  // dir: it is found again by alias instead of being created twice.
  const alias = `Close-${agentKey}-${crypto.createHash('sha256').update(agentKey).digest('hex').slice(0, 8)}`;
  if (!known) {
    const list = await vobiz(account, 'GET', `/Endpoint/?limit=100&alias__exact=${encodeURIComponent(alias)}`);
    const hit = listOf(list).find(e => e.alias === alias && e.endpoint_id);
    if (hit) {
      const id = String(hit.endpoint_id);
      const reset = await vobiz(account, 'POST', `/Endpoint/${encodeURIComponent(id)}/`, { password });
      if (ok(reset) && hit.username) {
        d.endpoints[key] = { endpointId: id, username: String(hit.username) };
        store.saveNow();
        return { endpointId: id, username: String(hit.username), password };
      }
    }
  }

  // Usernames must be alphanumeric. Vobiz rewrites the submitted one, so the
  // stored one is always read back.
  const submitted = `${agentKey}x${crypto.randomBytes(3).toString('hex')}`;
  const created = await vobiz(account, 'POST', '/Endpoint/', { username: submitted, password, alias });
  const endpointId = created.body && created.body.endpoint_id ? String(created.body.endpoint_id) : '';
  if (!ok(created) || !endpointId) {
    log(`x ${account.authId}: endpoint creation failed (HTTP ${created.status})`);
    return null;
  }
  const readBack = await vobiz(account, 'GET', `/Endpoint/${encodeURIComponent(endpointId)}/`);
  const username = (readBack.body && readBack.body.username) || '';
  if (!username) {
    log(`x ${account.authId}: could not read back the username of endpoint ${endpointId}`);
    return null;
  }
  if (username !== submitted) log(`${account.authId}: Vobiz stored endpoint username "${username}" (submitted "${submitted}")`);
  d.endpoints[key] = { endpointId, username };
  store.saveNow();
  return { endpointId, username, password };
}

// The application id bound to an endpoint, read from the raw text so a
// 17-digit id never passes through a JS number.
function boundAppId(raw) {
  const m = String(raw || '').match(/"application"\s*:\s*\{[^}]*?"app_id"\s*:\s*"?(\d+)"?/)
    || String(raw || '').match(/"app_id"\s*:\s*"?(\d+)"?/);
  return m ? m[1] : '';
}

/**
 * Bind endpoint to application: first {"app_id":"<id>"} as a string, verify
 * with a GET, then retry once with {"application": <integer literal>}.
 */
async function bindEndpoint(account, endpointId, appId) {
  if (!ID_RE.test(String(appId))) return false;
  const epPath = `/Endpoint/${encodeURIComponent(endpointId)}/`;
  await vobiz(account, 'POST', epPath, '{"app_id":"' + appId + '"}');
  let check = await vobiz(account, 'GET', epPath);
  if (boundAppId(check.raw) === String(appId)) return true;
  await vobiz(account, 'POST', epPath, '{"application":' + appId + '}');
  check = await vobiz(account, 'GET', epPath);
  const bound = boundAppId(check.raw) === String(appId);
  log(`${account.authId}: endpoint ${endpointId} ${bound ? 'bound' : 'NOT bound'} to application ${appId} after the "application" retry`);
  return bound;
}

/**
 * The registrar identity an access token with this `sub` registers as. Vobiz
 * builds it from the claims, so it is known without asking.
 */
const jwtSipUser = (sub, authId) => `${sub}_${authId}`;

/**
 * Mint an access token (JWT) for one agent: Vobiz signs the claims with the
 * account's Auth Token, so the token is all the browser ever holds. `app`
 * sends this identity's outbound calls to our application's Answer URL.
 * Returns { token, exp } or null.
 */
async function mintAccessToken(account, { sub, appId, ttl }) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: account.authId,
    sub,
    nbf: now,
    exp: now + ttl,
    per: { voice: { incoming_allow: true, outgoing_allow: true } },
    ...(appId ? { app: String(appId) } : {}),
  };
  const r = await vobiz(account, 'POST', '/JWT/Token/', claims);
  const token = r.body && typeof r.body.token === 'string' ? r.body.token : '';
  if (!ok(r) || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) {
    log(`x ${account.authId}: could not mint an access token for ${sub} (HTTP ${r.status})`);
    return null;
  }
  return { token, exp: claims.exp };
}

/** Attach a number to the application. Moves it off whatever it was on. */
async function attachNumber(account, e164, appId) {
  const enc = `%2B${String(e164).replace(/\D/g, '')}`;
  return vobiz(account, 'POST', `/numbers/${enc}/application`, '{"application_id":"' + appId + '"}');
}

/** Redirect a live call leg to new XML. legs: "aleg" | "bleg". */
async function transferLeg(account, callUuid, legs, url) {
  const body = legs === 'bleg'
    ? { legs: 'bleg', bleg_url: url, bleg_method: 'POST' }
    : { legs: 'aleg', aleg_url: url, aleg_method: 'POST' };
  return vobiz(account, 'POST', `/Call/${encodeURIComponent(callUuid)}/`, body);
}

/** The audio URL of a recording, from Vobiz's own Recording API only. */
async function recordingSource(account, { recordingId, callUuid }) {
  if (recordingId) {
    const meta = await vobiz(account, 'GET', `/Recording/${encodeURIComponent(recordingId)}/`);
    const src = meta.body && (meta.body.recording_url || meta.body.url || meta.body.file);
    if (ok(meta) && src) return src;
  }
  if (callUuid) {
    // Only accept a recording whose call_uuid actually matches; if the filter
    // is ignored upstream the first item would be someone else's call.
    const list = await vobiz(account, 'GET', `/Recording/?call_uuid=${encodeURIComponent(callUuid)}`);
    const match = listOf(list).find(o => o.call_uuid === callUuid);
    if (match) return match.recording_url || match.url || match.file || null;
  }
  return null;
}

/** May this host be sent the account's Auth ID and Token? */
function mediaHostTrusted(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === new URL(config.VOBIZ_API_BASE).hostname.toLowerCase()) return true;
  return config.VOBIZ_MEDIA_HOSTS.some(p => (p.startsWith('*.') ? h.endsWith(p.slice(1)) : h === p));
}

/**
 * Fetch recording audio. Redirects are followed by hand so every hop is
 * checked: https only, and credentials only to trusted Vobiz hosts, never to
 * a storage or CDN host a redirect or the Recording API points at.
 */
async function fetchRecordingAudio(account, src) {
  let url = src;
  for (let hop = 0; hop < 4; hop++) {
    let u;
    try { u = new URL(url); } catch { return { status: 0, error: 'bad url' }; }
    if (u.protocol !== 'https:') return { status: 0, error: 'not https' };
    const headers = mediaHostTrusted(u.hostname) ? { 'X-Auth-ID': account.authId, 'X-Auth-Token': account.authToken } : {};
    const res = await fetch(u.toString(), { headers, redirect: 'manual', signal: AbortSignal.timeout(30000) });
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      url = new URL(res.headers.get('location'), u).toString();
      continue;
    }
    return { status: res.status, res };
  }
  return { status: 0, error: 'too many redirects' };
}

module.exports = {
  fetchRecordingAudio, mediaHostTrusted,
  vobiz, ok, listOf, parseVobizJson, fetchAccountNumbers, ensureApplication, ensureEndpoint,
  bindEndpoint, boundAppId, attachNumber, transferLeg, recordingSource, answerUrl, APP_NAME,
  jwtSipUser, mintAccessToken,
};
