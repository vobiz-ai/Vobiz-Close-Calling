/**
 * Webhooks Vobiz calls, plus signed recording playback.
 *
 * Outbound: the agent's browser is the A leg. It sends the INVITE itself and
 * /vobiz/answer replies with <Dial><Number> for the customer.
 * Inbound: a PSTN caller reaches a DID and /vobiz/answer rings every signed-in
 * agent of that account with <Dial><User>.
 *
 * Never originate with REST and bridge the browser in afterwards: the customer
 * answers, hears ringback, and gets "agent could not be reached".
 */
const { Readable } = require('node:stream');
const express = require('express');
const config = require('./config');
const store = require('./store');
const cl = require('./close');
const v = require('./vobiz');
const logger = require('./call-logger');
const events = require('./events');
const { makeVerifier } = require('./vobiz-signature');
const { state, liveSessions } = require('./state');
const { log, xmlEscape, toE164, isE164, digitsOf, safeEqual, hmacHex } = require('./util');

const router = express.Router();
router.use(express.urlencoded({ extended: false, limit: '64kb' }));

const XML_HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n';
const politeHangup = text => `${XML_HEAD}<Response>\n  <Speak>${xmlEscape(text)}</Speak>\n  <Hangup/>\n</Response>`;
const params = req => ({ ...req.query, ...req.body });
const url = p => xmlEscape(`${config.PUBLIC_BASE_URL}${p}`);

const verify = makeVerifier({ mode: config.VOBIZ_WEBHOOK_SIGNATURES, publicBaseUrl: () => config.PUBLIC_BASE_URL });

function accountForNumber(to) {
  const want = digitsOf(to);
  if (!want) return null;
  for (const acct of state.accounts.values()) {
    if ((acct.numbers || []).some(n => digitsOf(n) === want)) return acct;
  }
  return null;
}

/**
 * The one Vobiz account a callback is about, worked out from server state
 * only: the call this backend already knows, the agent's SIP user, or the
 * dialled number. Never from ParentAuthID or any other field the sender
 * chose: otherwise anyone with their own Vobiz account could sign a callback
 * that names someone else's number and write into their CRM.
 */
function expectedAccountId(p) {
  const callUuid = String(p.CallUUID || '');
  const live = state.calls.get(callUuid);
  if (live) return live.authId || null;
  const t = state.transfers.get(callUuid);
  if (t) return t.authId || null;
  const stored = callUuid && store.load().calls[callUuid];
  if (stored && stored.authId) return stored.authId;
  const sipUser = (String(p.From || '').match(/^sip:([^@]+)@/) || [])[1];
  const who = sipUser && state.sipUsers.get(sipUser);
  if (who) return who.authId;
  const byNumber = accountForNumber(p.To);
  return byNumber ? byNumber.authId : null;
}

/**
 * Whether a callback's ParentAuthID fits the account it is about. A main
 * account (MA_) is its own parent. A sub-account (SA_) reports its main
 * account, which this backend never signs in with: any MA_ id is accepted
 * until the first correctly signed callback pins it, then only that one.
 */
function parentFits(acct, authId, parent) {
  if (parent === authId) return true;
  if (!/^SA_/.test(authId) || !/^MA_[A-Za-z0-9]+$/.test(parent)) return false;
  return !acct || !acct.parentAuthId || acct.parentAuthId === parent;
}

/**
 * Verified with that account's token alone (Vobiz signs a sub-account's call
 * callbacks with the sub-account's own token). A ParentAuthID that does not
 * fit the account is refused. Unknown account means no token, which the
 * verifier treats as a failed check.
 */
function requireSignature(req, res, next) {
  const p = params(req);
  const authId = expectedAccountId(p);
  const acct = authId && state.accounts.get(authId);
  const parent = p.ParentAuthID ? String(p.ParentAuthID) : '';
  const forbid = () => res.status(403).type('text/plain').send('Forbidden: invalid or missing webhook signature');
  if (authId && parent && !parentFits(acct, authId, parent)) {
    log(`[signature] ParentAuthID ${parent} does not own this call (expected ${authId}${acct && acct.parentAuthId ? ` under ${acct.parentAuthId}` : ''}); rejected`);
    return forbid();
  }
  const tokens = acct && acct.authToken ? [acct.authToken] : [];
  if (!verify(req, req.path === '/' ? req.baseUrl : `${req.baseUrl}${req.path}`, tokens)) return forbid();
  if (acct && parent && parent !== authId && !acct.parentAuthId) {
    acct.parentAuthId = parent;
    log(`${authId}: sub-account of ${parent}`);
  }
  req.vobizAuthId = authId;
  next();
}

function workspaceForAccount(authId, ringing) {
  const fromSession = ringing.map(s => s.wsKey).find(Boolean);
  if (fromSession) return fromSession;
  const linked = store.load().accountLinks[authId] || [];
  return linked[0] || null;
}

function recordXml() {
  // Self-closing <Record> as a sibling BEFORE <Dial>, never nested inside it.
  // recordSession="true" captures the bridged audio, attributed to this A leg.
  return `<Record fileFormat="mp3" recordSession="true" maxLength="14400" playBeep="false" redirect="false" callbackUrl="${url('/vobiz/recording')}" callbackMethod="POST"/>`;
}

// action + redirect="false" stop Vobiz re-fetching the answer URL when <Dial>
// ends; callbackUrl gives DialAnswer, which is when talk time starts.
const dialAttrs = callerId =>
  `callerId="${xmlEscape(callerId)}" timeout="30" timeLimit="14400" action="${url('/vobiz/dial-status')}" method="POST" redirect="false" callbackUrl="${url('/vobiz/dial-events')}" callbackMethod="POST"`;

function header(p, name) {
  return String(p[name] || p[`SIPHeader_${name}`] || '').trim();
}

function handleAnswer(req, res) {
  const p = params(req);
  res.set('Content-Type', 'text/xml');
  if ((p.Event || '') === 'Hangup') { handleHangup(req, null); return res.send(`${XML_HEAD}<Response></Response>`); }

  const callUuid = String(p.CallUUID || '');
  const from = String(p.From || '');
  const to = String(p.To || '');
  const isFromBrowser = from.startsWith('sip:') || String(p.RouteType || '').toLowerCase() === 'sip';
  log(`ANSWER call=${callUuid || '-'} from=${from || '-'} to=${to || '-'} ${isFromBrowser ? 'outbound' : 'inbound'}`);

  if (isFromBrowser) return answerOutbound(p, callUuid, from, to, res);
  return answerInbound(p, callUuid, from, to, res, req.vobizAuthId);
}

function answerOutbound(p, callUuid, from, to, res) {
  const sipUser = (from.match(/^sip:([^@]+)@/) || [])[1] || '';
  // The caller ID arrives as X-VH-Caller-ID, sometimes prefixed SIPHeader_.
  const headerCallerId = toE164(header(p, 'X-VH-Caller-ID'), 'XX');
  const ref = header(p, 'X-VH-Ref').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);
  let who = state.sipUsers.get(sipUser);
  if (who) {
    const acct = state.accounts.get(who.authId);
    // Account sign-in: only one of that account's own numbers.
    if (headerCallerId && acct && (acct.numbers || []).some(n => digitsOf(n) === digitsOf(headerCallerId))) {
      who = { ...who, callerId: headerCallerId };
    }
  }
  if (!who) {
    log(`  x outbound from unknown SIP user "${sipUser}"; hanging up`);
    return res.send(`${XML_HEAD}<Response><Hangup reason="rejected"/></Response>`);
  }
  const country = cl.countryFor(who.wsKey);
  const destination = toE164(to, country);
  const callerId = toE164(who.callerId, 'XX');
  if (!isE164(destination) || !isE164(callerId)) {
    log(`  x refusing to dial: destination="${to}" callerId="${who.callerId}"`);
    return res.send(`${XML_HEAD}<Response><Hangup reason="rejected"/></Response>`);
  }

  const r = ref ? state.refs.get(ref) : null;
  const call = {
    callUuid, authId: who.authId, wsKey: who.wsKey, userId: who.userId, agentName: who.name,
    direction: 'outbound', remote: destination, did: callerId, agentSipUser: sipUser, startedAt: Date.now(),
    ref: ref || null,
  };
  state.calls.set(callUuid, call);
  if (ref) state.refs.set(ref, { ...(r || {}), callUuid, at: Date.now() });

  return res.send(
    `${XML_HEAD}<Response>\n  ${call.authId ? recordXml() : ''}\n` +
    `  <Dial ${dialAttrs(callerId)}>\n    <Number>${xmlEscape(destination)}</Number>\n  </Dial>\n</Response>`
  );
}

function answerInbound(p, callUuid, from, to, res, authId) {
  // The account is the one requireSignature verified: the owner of the
  // dialled number among signed-in accounts. ParentAuthID was only checked
  // against it, never used to pick it.
  const acct = (authId && state.accounts.get(authId)) || null;
  const sessions = liveSessions().map(([, s]) => s).filter(s => s.mode === 'account' && s.sipUser);
  const did = toE164(to, config.DEFAULT_COUNTRY);
  const agents = acct ? sessions.filter(s => s.authId === acct.authId) : [];
  const wsKey = acct ? workspaceForAccount(acct.authId, agents) : null;
  const country = cl.countryFor(wsKey);
  const remote = toE164(from, country) || from;

  const call = {
    callUuid, authId: acct ? acct.authId : null, wsKey, direction: 'inbound', remote, did,
    agentSipUsers: agents.map(a => a.sipUser), startedAt: Date.now(),
  };
  state.calls.set(callUuid, call);

  if (!agents.length) {
    call.noAgents = true;
    log(`  x inbound to ${did}: ${acct ? `no agent of ${acct.authId} is signed in` : 'no signed-in account owns this number'}; polite hangup`);
    return res.send(politeHangup('Sorry, no one is available to take your call. Please try again later.'));
  }

  // Screen pop: the softphone looks the caller up before it answers.
  const seen = new Set();
  for (const a of agents) {
    const k = `${a.wsKey}:${a.userId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    events.pushToUser(a.wsKey, a.userId, { type: 'incoming', callUuid, from: remote, to: did });
  }

  // callerId must be a number this account owns, or the B leg is never created.
  // The real caller goes in callerName, which the browser sees as display name.
  const users = [...new Set(agents.map(a => a.sipUser))].map(u => `    <User>${xmlEscape(`sip:${u}@${config.VOBIZ_REGISTRAR}`)}</User>`).join('\n');
  log(`  -> inbound from ${remote} to ${acct.authId}, ringing ${agents.length} agent(s)`);
  return res.send(
    `${XML_HEAD}<Response>\n  ${recordXml()}\n` +
    `  <Dial ${dialAttrs(did)} callerName="${xmlEscape(remote)}">\n${users}\n  </Dial>\n` +
    `  <Speak>${xmlEscape('Sorry, no one can take your call right now. We will call you back.')}</Speak>\n  <Hangup/>\n</Response>`
  );
}

/** The agent whose endpoint answered, only if they belong to the call's own Vobiz account. */
function agentForBLeg(to, authId) {
  const sipUser = (String(to || '').match(/^(?:sip:)?([^@]+)@/) || [])[1] || '';
  const agent = state.sipUsers.get(sipUser);
  return agent && agent.authId === authId ? agent : null;
}

/** <Dial callbackUrl>: DialAnswer starts talk time; DialHangup carries B-leg seconds. */
function handleDialEvents(req, res) {
  const p = params(req);
  const call = state.calls.get(String(p.CallUUID || ''));
  const ev = String(p.Event || p.DialAction || '');
  if (call) {
    if (/answer/i.test(ev)) {
      if (!call.answeredAt) call.answeredAt = Date.now();
      if (call.direction === 'inbound') {
        const agent = agentForBLeg(p.DialBLegTo, call.authId);
        if (agent) {
          if (call.transferPending && call.agentName && call.agentName !== agent.name) call.transferredFrom = call.agentName;
          // One Vobiz account can serve several Close organizations: log the
          // call in the answering agent's own organization, as them.
          call.wsKey = agent.wsKey;
          call.userId = agent.userId; call.agentName = agent.name; call.agentSipUser = (String(p.DialBLegTo).match(/^(?:sip:)?([^@]+)@/) || [])[1];
        }
      }
      call.transferPending = false;
    }
    if (/hangup/i.test(ev) && !call.transferred) {
      // Actual seconds first; the billed figure may be rounded up to a pulse.
      const secs = Number(p.DialBLegDuration || p.DialBLegBillDuration);
      if (Number.isFinite(secs) && secs >= 0 && call.answeredAt) call.talkSeconds = secs;
    }
  }
  res.status(200).end();
}

/** <Dial action>: the final result of one dial. DialBLegUUID empty = no B leg was ever created. */
function handleDialStatus(req, res) {
  const p = params(req);
  const call = state.calls.get(String(p.CallUUID || ''));
  log(`DIAL RESULT call=${p.CallUUID || '-'} status=${p.DialStatus || '-'} cause=${p.DialHangupCause || '-'} bleg=${p.DialBLegUUID || '(none)'}`);
  if (call) {
    if (!(call.answeredAt && p.DialStatus !== 'completed')) call.dialStatus = String(p.DialStatus || '');
    call.bLegUuid = p.DialBLegUUID || call.bLegUuid || null;
    call.hangupCause = p.DialHangupCause || call.hangupCause || '';
  }
  // A transferred call whose second dial finished: nothing more to execute.
  res.set('Content-Type', 'text/xml').send(`${XML_HEAD}<Response></Response>`);
}

/** The A leg ended. Give late dial callbacks a moment, then write to Close once. */
function handleHangup(req, res) {
  const p = params(req);
  const callUuid = String(p.CallUUID || '');
  const call = state.calls.get(callUuid);
  if (call && !call.endedAt) {
    call.endedAt = Date.now();
    call.hangupCause = call.hangupCause || String(p.HangupCause || '');
    log(`HANGUP call=${callUuid} cause=${p.HangupCause || '-'} duration=${p.Duration || '-'}`);
    const t = setTimeout(() => {
      call.logged = true;
      logger.logCall(logger.snapshot(call)).catch(err => log(`x logCall: ${err.message}`));
    }, config.LOG_SETTLE_MS);
    if (t.unref) t.unref();
  }
  if (res) res.status(200).end();
}

/** <Record callbackUrl>: the file is ready. */
async function handleRecording(req, res) {
  const p = params(req);
  const callUuid = String(p.CallUUID || '');
  const recordingId = String(p.RecordingID || p.RecordingId || '');
  res.status(200).end();
  if (!callUuid || !recordingId) return;
  log(`RECORDING call=${callUuid} id=${recordingId} reason=${p.RecordingEndReason || '-'}`);
  const call = state.calls.get(callUuid);
  if (call) call.recordingId = recordingId;
  // Kept on disk whether or not the call is logged yet: the live record is
  // swept an hour after the call, and a retried log must still find it.
  const stored = store.load().calls[callUuid];
  if (!stored && !call) return;
  const authId = (stored && stored.authId) || (call && call.authId) || req.vobizAuthId;
  const saved = store.putCall(callUuid, { recordingId, authId, ...(stored ? {} : { wsKey: call.wsKey }) });
  if (saved.activityId && !saved.recordingNoted) await logger.addRecording(callUuid, recordingId);
}

/** XML for a transferred caller: ring the target agent. */
function handleTransferXml(req, res) {
  const p = params(req);
  const callUuid = String(p.CallUUID || '');
  const t = state.transfers.get(callUuid);
  res.set('Content-Type', 'text/xml');
  if (!t) return res.send(politeHangup('Sorry, the transfer could not be completed.'));
  state.transfers.delete(callUuid);
  const call = state.calls.get(callUuid);
  if (call) { call.transferPending = true; call.transferred = true; call.talkSeconds = undefined; }
  log(`TRANSFER call=${callUuid} -> ${t.targetSipUser}`);
  return res.send(
    `${XML_HEAD}<Response>\n` +
    `  <Dial ${dialAttrs(t.callerId)} callerName="${xmlEscape(t.callerName || '')}">\n    <User>${xmlEscape(`sip:${t.targetSipUser}@${config.VOBIZ_REGISTRAR}`)}</User>\n  </Dial>\n` +
    `  <Speak>${xmlEscape('Sorry, no one can take your call right now. We will call you back.')}</Speak>\n  <Hangup/>\n</Response>`
  );
}

for (const [p, h] of [['/answer', handleAnswer], ['/dial-events', handleDialEvents], ['/dial-status', handleDialStatus],
  ['/hangup', handleHangup], ['/recording', handleRecording], ['/transfer-xml', handleTransferXml]]) {
  router.post(p, requireSignature, h);
  router.get(p, requireSignature, h);
}

// Fallback fires only when /answer failed. It has no side effects and reveals
// nothing, so it is not signature-gated: a caller must never hear silence.
const fallback = (req, res) => res.type('text/xml').send(politeHangup('Sorry, we cannot take your call right now. Please try again shortly.'));
router.post('/fallback', fallback);
router.get('/fallback', fallback);

// ─── signed recording playback ───────────────────────────────────────────────
// An <audio> element or a link in a Close activity cannot send a header, so
// the proof travels in the URL: an HMAC over the account, the call and the
// expiry. Never the Auth Token. The audio URL always comes from Vobiz's own
// Recording API, never from the request, so this is not a proxy.
const recordings = express.Router();
recordings.get('/:callUuid', async (req, res) => {
  const callUuid = String(req.params.callUuid || '');
  const authId = String(req.query.aid || '');
  const exp = String(req.query.exp || '');
  const sig = String(req.query.sig || '');
  const fresh = /^\d+$/.test(exp) && Number(exp) >= Math.floor(Date.now() / 1000);
  if (!authId || !fresh || !sig || !safeEqual(sig, hmacHex(config.SIGNING_SECRET, `rec|${authId}|${callUuid}|${exp}`))) {
    return res.status(403).type('text/plain').send('This recording link is invalid or has expired. Open the call list in the softphone for a fresh link.');
  }
  const account = state.accounts.get(authId);
  if (!account || !account.authToken) {
    return res.status(409).type('text/plain').send('The calling service restarted since this link was made. Ask someone on this Vobiz account to sign in to the softphone, then open the link again.');
  }
  const stored = store.load().calls[callUuid];
  const live = state.calls.get(callUuid);
  if ((stored && stored.authId && stored.authId !== authId) || (live && live.authId && live.authId !== authId)) {
    return res.status(403).type('text/plain').send('This recording link is invalid.');
  }
  const recordingId = (live && live.recordingId) || (stored && stored.recordingId) || null;
  const src = await v.recordingSource(account, { recordingId, callUuid });
  if (!src) return res.status(404).type('text/plain').send('The recording is still processing, or this call was not recorded.');
  try {
    const got = await v.fetchRecordingAudio(account, src);
    const audio = got.res;
    if (!audio || !audio.ok || !audio.body) return res.status(502).type('text/plain').send(`Vobiz returned ${got.status || got.error} for the recording audio.`);
    res.set({ 'Content-Type': audio.headers.get('content-type') || 'audio/mpeg', 'Content-Disposition': 'inline; filename="recording.mp3"', 'Cache-Control': 'private, no-store' });
    if (audio.headers.get('content-length')) res.set('Content-Length', audio.headers.get('content-length'));
    // Streamed, never held whole in memory (a recording can be hours long).
    const stream = Readable.fromWeb(audio.body);
    stream.on('error', err => { log('recording stream failed:', err.message); res.destroy(err); });
    return stream.pipe(res);
  } catch (err) {
    log('recording stream failed:', err.message);
    return res.status(502).type('text/plain').send('Could not stream that recording.');
  }
});

module.exports = { router, recordings, accountForNumber };
