/**
 * Every call, whatever its outcome, becomes exactly one Close Call activity on
 * the caller's lead and contact, so it shows on the lead's timeline with its
 * direction, status, talk time and note. A missed inbound call also gets a
 * "Call back" task. The recording link is added to the same activity when
 * Vobiz says the file is ready.
 *
 * Writes that fail are kept in the store and retried for 24 hours.
 */
const config = require('./config');
const store = require('./store');
const cl = require('./close');
const events = require('./events');
const { state } = require('./state');
const { log, formatDuration, hmacHex } = require('./util');

const RETRY_FOR_MS = 24 * 3600 * 1000;

/**
 * answered | missed | no-answer | busy | cancelled | declined | failed
 *
 * DialStatus from <Dial action>: completed | busy | failed | cancel | timeout | no-answer.
 * Inbound: anything unanswered is a missed call the team should return.
 */
function outcomeOf(call) {
  if (call.outcome) return call.outcome;
  const inbound = call.direction === 'inbound';
  const ds = String(call.dialStatus || '').toLowerCase();
  if (call.answeredAt || ds === 'completed') return 'answered';
  if (inbound) return 'missed';
  if (ds === 'busy') return 'busy';
  if (ds === 'no-answer' || ds === 'timeout') return 'no-answer';
  if (ds === 'cancel') return 'cancelled';
  return 'failed';
}

// Close's call status values: created | in-progress | completed | cancel |
// no-answer | busy | failed | timeout.
const CLOSE_STATUS = { answered: 'completed', missed: 'no-answer', 'no-answer': 'no-answer', busy: 'busy', cancelled: 'cancel', declined: 'busy', failed: 'failed' };

/** Talk seconds, measured from the answer, never from the INVITE. */
function talkSecondsOf(call) {
  if (Number.isFinite(call.talkSeconds) && call.talkSeconds >= 0) return call.talkSeconds;
  if (call.answeredAt && call.endedAt && call.endedAt > call.answeredAt) return Math.round((call.endedAt - call.answeredAt) / 1000);
  return 0;
}

function settingsFor(wsKey) {
  const ws = cl.getWorkspace(wsKey);
  return { ...cl.defaultSettings(), ...((ws && ws.settings) || {}) };
}

function recordingLink(authId, callUuid, ttlSeconds) {
  const exp = Math.floor(Date.now() / 1000) + Math.max(60, Number(ttlSeconds) || config.RECORDING_LINK_TTL_SECONDS);
  const sig = hmacHex(config.SIGNING_SECRET, `rec|${authId}|${callUuid}|${exp}`);
  return `${config.PUBLIC_BASE_URL}/recordings/${encodeURIComponent(callUuid)}?aid=${encodeURIComponent(authId)}&exp=${exp}&sig=${sig}`;
}

/** A plain snapshot of a live call, safe to store for retries. */
function snapshot(call) {
  return {
    callUuid: call.callUuid, authId: call.authId, wsKey: call.wsKey, userId: call.userId || null,
    agentName: call.agentName || '', direction: call.direction, outcome: outcomeOf(call), talkSeconds: talkSecondsOf(call),
    remote: call.remote, did: call.did, startedAt: call.startedAt, endedAt: call.endedAt || Date.now(),
    recordingId: call.recordingId || null, transferredFrom: call.transferredFrom || null,
    hangupCause: call.hangupCause || '',
  };
}

const OUTCOME_LABEL = {
  answered: 'answered', missed: 'missed', 'no-answer': 'no answer', busy: 'busy', cancelled: 'cancelled', declined: 'declined', failed: 'failed',
};

/**
 * The activity's note, as plain text: Close escapes HTML in `note` and turns
 * newlines into line breaks, so nothing a caller or agent name contains can
 * become markup.
 */
function noteText(s, recording) {
  const when = new Date(s.startedAt || Date.now()).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = [
    `Vobiz ${s.direction} call, ${OUTCOME_LABEL[s.outcome] || s.outcome}`,
    `Agent: ${s.agentName || 'none'}`,
    `Talk time: ${formatDuration(s.talkSeconds)}`,
    `Customer number: ${s.remote}`,
    `Vobiz number: ${s.did}`,
    `Started: ${when}`,
    `Call UUID: ${s.callUuid}`,
  ];
  if (s.transferredFrom) lines.splice(2, 0, `Transferred from: ${s.transferredFrom}`);
  if (recording) lines.push(`Recording: ${recording} (the link expires; the softphone's Recent calls has a fresh one)`);
  else lines.push(`Recording: ${s.outcome === 'answered' && s.authId ? 'processing, added here when ready' : 'none'}`);
  return lines.join('\n');
}

/** The fields of the Close Call activity for one call. */
function callFields(s, rec, recording) {
  const f = {
    lead_id: rec.leadId,
    direction: s.direction === 'inbound' ? 'inbound' : 'outbound',
    status: CLOSE_STATUS[s.outcome] || 'completed',
    duration: Math.max(0, Math.round(s.talkSeconds || 0)),
    phone: s.remote,
    note: noteText(s, recording),
    activity_at: new Date(s.startedAt || Date.now()).toISOString(),
  };
  if (rec.contactId) f.contact_id = rec.contactId;
  if (recording) f.recording_url = recording;
  return f;
}

function queuePending(s, err) {
  const d = store.load();
  const existing = d.pending.find(p => p.callUuid === s.callUuid);
  const attempts = existing ? existing.attempts + 1 : 1;
  const entry = { callUuid: s.callUuid, wsKey: s.wsKey, snapshot: s, attempts, firstAt: existing ? existing.firstAt : Date.now(), nextAt: Date.now() + Math.min(3600, 30 * 2 ** attempts) * 1000, lastError: String(err && err.message || err) };
  d.pending = d.pending.filter(p => p.callUuid !== s.callUuid);
  if (Date.now() - entry.firstAt < RETRY_FOR_MS) d.pending.push(entry);
  else log(`x giving up on logging call ${s.callUuid} after 24h: ${entry.lastError}`);
  store.saveNow();
}

const inFlight = new Set();

/** Close activity ids already used by one of our calls, so none is filled in twice. */
function claimedActivities() {
  return new Set(Object.values(store.load().calls).map(c => c.activityId).filter(Boolean));
}

/**
 * Write one call to Close. Idempotent per CallUUID, and resumable: every id is
 * stored the moment Close returns it (lead, contact, call activity, task), so
 * a retry after a failure part-way only does the steps still missing and never
 * creates a second lead, call or task.
 */
async function logCall(s) {
  if (!s || !s.callUuid) return null;
  const existing = store.load().calls[s.callUuid];
  if (existing && existing.logged) return existing;
  if (inFlight.has(s.callUuid)) return null;
  if (!s.wsKey) { log(`call ${s.callUuid}: no Close organization is linked to this Vobiz account; not logged`); return null; }
  const settings = settingsFor(s.wsKey);
  const writer = cl.writerFor(s.wsKey, s.userId);
  if (!writer) {
    queuePending(s, 'no connected Close user');
    events.pushToUser(s.wsKey, s.userId, { type: 'log-error', callUuid: s.callUuid, message: 'Reconnect Close so calls can be logged. This one is kept and retried.' });
    return null;
  }

  inFlight.add(s.callUuid);
  const save = fields => store.putCall(s.callUuid, { wsKey: s.wsKey, authId: s.authId, userId: s.userId, ...fields });
  try {
    let rec = store.load().calls[s.callUuid] || {};
    const live = state.calls.get(s.callUuid);
    // The recording may have been reported before, or while, this runs; the
    // snapshot was taken at hangup and may not know it yet.
    const recordingId = s.recordingId || rec.recordingId || (live && live.recordingId) || null;
    const snap = { ...s, recordingId };
    const country = settings.defaultCountry;

    if (!rec.leadId && !rec.leadChecked && s.remote) {
      const contacts = await cl.findContactsByPhone(s.wsKey, writer, s.remote, country);
      let found = { leadId: null, contactId: null, name: '' };
      if (contacts[0]) found = { leadId: contacts[0].lead_id, contactId: contacts[0].id, name: cl.contactName(contacts[0]) };
      else if (settings.createUnknown) found = await cl.createLead(s.wsKey, writer, s.remote);
      rec = save({ leadId: found.leadId, contactId: found.contactId, contactName: found.name, leadChecked: true, recordingId });
    }
    if (!rec.leadId) {
      // Close keeps every activity on a lead, so with "create a lead for
      // unknown numbers" off there is nowhere to put this call.
      log(`call ${s.callUuid}: ${s.remote} matches no Close contact and creating leads is off; not logged`);
      save({ logged: true, skipped: 'no-lead', direction: s.direction, outcome: s.outcome, talkSeconds: s.talkSeconds, remote: s.remote, did: s.did, startedAt: s.startedAt, endedAt: s.endedAt, snapshot: snap });
      events.pushToUser(s.wsKey, s.userId, { type: 'logged', callUuid: s.callUuid, skipped: true, outcome: s.outcome });
      return store.load().calls[s.callUuid];
    }

    const recordingUrl = recordingId && s.authId ? recordingLink(s.authId, s.callUuid, settings.recordingTtlSeconds) : null;
    if (!rec.activityId) {
      const fields = callFields(snap, rec, recordingUrl);
      let activityId = null;
      if (s.direction === 'outbound' && writer === s.userId) {
        try {
          activityId = await cl.findTelLinkCall(s.wsKey, writer, { leadId: rec.leadId, phone: s.remote, startedAt: s.startedAt, claimed: claimedActivities() });
        } catch (err) { log(`x looking for Close's own tel: call log failed: ${err.message}`); }
      }
      if (activityId) {
        await cl.updateCall(s.wsKey, writer, activityId, fields);
        rec = save({ activityId, filledTelLink: true, recordingId, recordingNoted: !!recordingUrl, snapshot: snap });
      } else {
        activityId = await cl.createCall(s.wsKey, writer, fields);
        rec = save({ activityId, recordingId, recordingNoted: !!recordingUrl, snapshot: snap });
      }
    }

    if (s.direction === 'inbound' && s.outcome === 'missed' && settings.missedTask && !rec.taskDone) {
      try {
        if (!rec.taskId) {
          const taskId = await cl.createTask(s.wsKey, writer, {
            leadId: rec.leadId, contactId: rec.contactId,
            text: `Call back ${s.remote} (missed call to ${s.did} at ${new Date(s.startedAt || Date.now()).toISOString().replace('T', ' ').slice(0, 16)} UTC)`,
            date: new Date().toISOString().slice(0, 10),
          });
          rec = save({ taskId });
        }
        rec = save({ taskDone: true });
      } catch (err) {
        // The call activity is the record of the call; a task that fails is not retried.
        log(`x call-back task for ${s.callUuid} failed: ${err.message}`);
        rec = save({ taskDone: true });
      }
    }

    const saved = save({
      logged: true, direction: s.direction, outcome: s.outcome, talkSeconds: s.talkSeconds, agentName: s.agentName,
      remote: s.remote, did: s.did, startedAt: s.startedAt, endedAt: s.endedAt, recordingId, snapshot: snap,
    });
    store.load().pending = store.load().pending.filter(p => p.callUuid !== s.callUuid);
    store.saveNow();
    log(`call ${s.callUuid} logged to Close activity ${saved.activityId} (${s.direction}, ${s.outcome})`);
    events.pushToUser(s.wsKey, s.userId, { type: 'logged', callUuid: s.callUuid, activityId: saved.activityId, leadUrl: cl.leadUrl(saved.leadId), contactName: saved.contactName || '', outcome: s.outcome });

    // A recording that arrived while this was being written.
    const lateRecording = saved.recordingId || (live && live.recordingId);
    if (!saved.recordingNoted && lateRecording) await addRecording(s.callUuid, lateRecording);
    return store.load().calls[s.callUuid];
  } catch (err) {
    log(`x could not log call ${s.callUuid} to Close: ${err.message}`);
    queuePending(s, err);
    events.pushToUser(s.wsKey, s.userId, { type: 'log-error', callUuid: s.callUuid, message: 'Could not write this call to Close yet. It will be retried.' });
    return null;
  } finally {
    inFlight.delete(s.callUuid);
  }
}

/** The recording callback: put the link on the call's activity, once. */
async function addRecording(callUuid, recordingId) {
  const d = store.load();
  const rec = d.calls[callUuid];
  if (!rec || !rec.activityId || rec.recordingNoted || !rec.authId) return false;
  rec.recordingId = recordingId;
  const settings = settingsFor(rec.wsKey);
  const writer = cl.writerFor(rec.wsKey, rec.userId);
  if (!writer) return false;
  const url = recordingLink(rec.authId, callUuid, settings.recordingTtlSeconds);
  const snap = { ...(rec.snapshot || {}), recordingId };
  try {
    await cl.updateCall(rec.wsKey, writer, rec.activityId, { recording_url: url, note: noteText(snap, url) });
    rec.recordingNoted = true;
    store.saveNow();
    return true;
  } catch (err) {
    // The softphone's call list can always mint a fresh link, so this is not
    // retried forever.
    log(`x recording link for ${callUuid} failed: ${err.message}`);
    return false;
  }
}

async function retryPending() {
  const d = store.load();
  const due = d.pending.filter(p => p.nextAt <= Date.now());
  for (const p of due) await logCall(p.snapshot);
}

module.exports = { logCall, snapshot, outcomeOf, talkSecondsOf, addRecording, retryPending, recordingLink, noteText, callFields, settingsFor, CLOSE_STATUS };
