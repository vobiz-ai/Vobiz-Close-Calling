/**
 * Server-sent events to softphone tabs. The softphone reads the stream with
 * fetch() and an Authorization header (EventSource cannot send one), so the
 * session token never appears in a URL.
 */
const { state, liveSessions } = require('./state');

function attach(token, res) {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write(': connected\n\n');
  let set = state.streams.get(token);
  if (!set) { set = new Set(); state.streams.set(token, set); }
  set.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  res.on('close', () => {
    clearInterval(ping);
    set.delete(res);
    if (!set.size) state.streams.delete(token);
  });
}

function pushToSession(token, event) {
  const set = state.streams.get(token);
  if (!set || !set.size) return 0;
  const line = `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
  for (const res of set) res.write(line);
  return set.size;
}

/** Push to every live softphone session of one Close user. Returns how many tabs got it. */
function pushToUser(wsKey, userId, event) {
  let n = 0;
  for (const [token, s] of liveSessions()) {
    if (s.wsKey === String(wsKey) && s.userId === String(userId)) n += pushToSession(token, event);
  }
  return n;
}

function closeSession(token) {
  const set = state.streams.get(token);
  if (!set) return;
  for (const res of set) { try { res.end(); } catch { /* ignore */ } }
  state.streams.delete(token);
}

module.exports = { attach, pushToSession, pushToUser, closeSession };
