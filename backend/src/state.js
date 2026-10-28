/**
 * In-memory state. Everything here is lost on restart by design: it holds the
 * Vobiz Auth Tokens, SIP passwords and Close access tokens, none of which may
 * be written to disk. After a restart agents sign in again.
 */
const config = require('./config');

const state = {
  // authId -> { authId, authToken, numbers, callerIds, numberApps, appId }
  accounts: new Map(),
  // session token -> softphone session (see routes-phone.js)
  sessions: new Map(),
  // SIP username -> { authId, agentKey, wsKey, userId, name, callerId }
  sipUsers: new Map(),
  // A-leg CallUUID -> live call record
  calls: new Map(),
  // client call ref (X-VH-Ref) -> { callUuid, report }
  refs: new Map(),
  // OAuth state -> { exp }
  oauthStates: new Map(),
  // one-time link code -> { wsKey, userId, exp }
  linkCodes: new Map(),
  // call leg UUID being transferred -> { targetSipUser, callerId, exp }
  transfers: new Map(),
  // "<wsKey>:<userId>" -> { accessToken, exp }   Close OAuth access tokens
  closeAccess: new Map(),
  // session token -> Set of open event-stream responses
  streams: new Map(),
};

function sessionExpired(s) {
  return Date.now() - s.createdAt > config.SESSION_TTL_MS;
}

function liveSessions() {
  const out = [];
  for (const [token, s] of state.sessions) {
    if (sessionExpired(s)) { state.sessions.delete(token); continue; }
    out.push([token, s]);
  }
  return out;
}

/** Drop expired one-shot entries. Called on a timer. */
function sweep() {
  const now = Date.now();
  for (const m of [state.oauthStates, state.linkCodes, state.transfers]) {
    for (const [k, v] of m) if (v.exp && v.exp < now) m.delete(k);
  }
  for (const [ref, r] of state.refs) if (r.at && now - r.at > 6 * 3600 * 1000) state.refs.delete(ref);
  for (const [uuid, c] of state.calls) if (c.logged && now - (c.endedAt || c.startedAt) > 3600 * 1000) state.calls.delete(uuid);
  liveSessions();
}

module.exports = { state, liveSessions, sessionExpired, sweep };
