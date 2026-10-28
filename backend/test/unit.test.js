/**
 * Unit tests for the pieces that are easy to get subtly wrong: phone numbers,
 * Close phones and ids, the call activity's fields, Vobiz signatures, and the
 * retry of a Close write that failed.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vzcl-unit-'));
process.env.PUBLIC_BASE_URL = 'https://calling.example.test';
process.env.SIGNING_SECRET = 'unit-secret';

const { toE164 } = require('../src/util');
const cl = require('../src/close');
const logger = require('../src/call-logger');
const store = require('../src/store');
const { checkSignature } = require('../src/vobiz-signature');

test('toE164 handles trunk prefixes, bare national numbers, 00 and SIP URIs', () => {
  assert.equal(toE164('09000000011', 'IN'), '+919000000011');
  assert.equal(toE164('9000000011', 'IN'), '+919000000011');
  assert.equal(toE164('+91 90000 00011', 'IN'), '+919000000011');
  assert.equal(toE164('0091 9000000011', 'IN'), '+919000000011');
  assert.equal(toE164('sip:+919000000011@registrar.vobiz.ai', 'IN'), '+919000000011');
  assert.equal(toE164('(555) 010-0000', 'US'), '+15550100000');
  assert.equal(toE164('12', 'IN'), '');
});

test('phonesOf reads every phone on a Close contact, formatted or not', () => {
  const contact = { phones: [{ phone: '+91 90000 00011' }, { phone: '+1 555 010 0000' }, { phone: '90000 00013' }, { phone: '07000000001' }, { phone: '' }, null] };
  assert.deepEqual(cl.phonesOf(contact, 'IN'), ['+919000000011', '+15550100000', '+919000000013', '+917000000001'], 'no country code: the default country');
  assert.deepEqual(cl.phonesOf({ phones: null }, 'IN'), []);
});

test('only well-formed Close ids are accepted, so none can steer a request path', () => {
  assert.equal(cl.isCloseId('lead_abc123XYZ', 'lead'), true);
  assert.equal(cl.isCloseId('cont_abc123', 'lead'), false, 'wrong prefix');
  for (const bad of ['lead_../me', 'lead_x/y', 'lead_', '../lead_x', 'lead_x?y=1', '', null]) assert.equal(cl.isCloseId(bad, 'lead'), false, String(bad));
  assert.equal(cl.leadUrl('lead_abc123'), 'https://app.close.com/lead/lead_abc123/');
  assert.equal(cl.leadUrl('javascript:alert(1)'), null);
});

test('the call activity: Close status values, talk seconds, plain-text note', () => {
  const s = {
    direction: 'inbound', outcome: 'missed', agentName: '<b>x</b>', talkSeconds: 0,
    remote: '+919000000011', did: '+910000000001', startedAt: 1000, callUuid: 'u-1', authId: 'MA_TEST0001',
  };
  const f = logger.callFields(s, { leadId: 'lead_a', contactId: 'cont_a' }, null);
  assert.deepEqual(Object.keys(f).sort(), ['activity_at', 'contact_id', 'direction', 'duration', 'lead_id', 'note', 'phone', 'status']);
  assert.equal(f.status, 'no-answer');
  assert.equal(f.direction, 'inbound');
  assert.equal(f.activity_at, '1970-01-01T00:00:01.000Z');
  assert.ok(!('note_html' in f), 'never HTML: Close escapes the plain note itself');
  const answered = logger.callFields({ ...s, outcome: 'answered', talkSeconds: 61.4 }, { leadId: 'lead_a' }, 'https://calling.example.test/recordings/u-1?x');
  assert.equal(answered.status, 'completed');
  assert.equal(answered.duration, 61);
  assert.equal(answered.recording_url, 'https://calling.example.test/recordings/u-1?x');
  assert.equal(answered.contact_id, undefined);
  for (const [outcome, status] of Object.entries({ busy: 'busy', 'no-answer': 'no-answer', cancelled: 'cancel', declined: 'busy', failed: 'failed' })) {
    assert.equal(logger.callFields({ ...s, direction: 'outbound', outcome }, { leadId: 'lead_a' }, null).status, status, outcome);
  }
});

test('Vobiz signature: V3 over URL + "." + nonce, V2 without the dot, never the body', () => {
  const url = 'https://calling.example.test/vobiz/answer';
  const v3 = crypto.createHmac('sha256', 'tok').update(`${url}.n1`).digest('base64');
  const v2 = crypto.createHmac('sha256', 'tok').update(`${url}n2`).digest('base64');
  assert.equal(checkSignature({ 'x-vobiz-signature-v3': v3, 'x-vobiz-signature-v3-nonce': 'n1' }, ['tok'], url), 'valid');
  assert.equal(checkSignature({ 'x-vobiz-signature-v2': v2, 'x-vobiz-signature-v2-nonce': 'n2' }, ['tok'], url), 'valid');
  assert.equal(checkSignature({ 'x-vobiz-signature-v3': v3, 'x-vobiz-signature-v3-nonce': 'n1' }, ['other'], url), 'invalid');
  assert.equal(checkSignature({}, ['tok'], url), 'absent');
});

/** A fake Close for the logger tests below: counts requests, fails on demand. */
function fakeClose(fail, { known = true } = {}) {
  const seen = [];
  let n = 0;
  global.fetch = async (url, opts = {}) => {
    const p = new URL(url).pathname;
    const key = `${opts.method || 'GET'} ${p}`;
    seen.push({ key, body: opts.body ? JSON.parse(opts.body) : null, auth: (opts.headers || {}).Authorization });
    const ok = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
    if (fail[key] > 0) { fail[key]--; return ok({ error: 'boom' }, 503); }
    if (key === 'POST /api/v1/data/search/') return ok({ data: known ? [{ id: 'cont_known', lead_id: 'lead_known', name: 'Known Caller', phones: [{ phone: '+919000000099' }] }] : [] });
    if (key === 'POST /api/v1/lead/') return ok({ id: 'lead_made', contacts: [{ id: 'cont_made' }] });
    if (key === 'POST /api/v1/activity/call/') return ok({ id: `acti_${++n}` });
    if (key === 'GET /api/v1/activity/call/') return ok({ data: [] });
    if (key.startsWith('PUT /api/v1/activity/call/')) return ok({ id: 'acti_x' });
    if (key === 'POST /api/v1/task/') return ok({ id: 'task_1' });
    return ok({}, 404);
  };
  return seen;
}

function unitOrg(name) {
  const wsKey = cl.wsKeyOf(`orga_${name}`);
  const d = store.load();
  d.workspaces[wsKey] = { wsKey, organizationId: `orga_${name}`, name, settings: cl.defaultSettings() };
  d.users[`${wsKey}:user_u1`] = { wsKey, userId: 'user_u1', name: 'Unit Agent', admin: true, auth: 'apikey', apiKey: store.encrypt('api_TESTunit00000000000000000'), broken: false };
  return wsKey;
}

test('a Close write that fails is queued, then written once by the retry; the lead made on the first try is reused', async () => {
  const wsKey = unitOrg('retry');
  const seen = fakeClose({ 'POST /api/v1/activity/call/': 1 }, { known: false });
  const snap = {
    callUuid: 'unit-call-1', authId: null, wsKey, userId: 'user_u1', agentName: 'Unit Agent', direction: 'inbound', outcome: 'missed',
    talkSeconds: 0, remote: '+917000000009', did: '+910000000001', startedAt: Date.now(), endedAt: Date.now(),
  };
  assert.equal(await logger.logCall(snap), null);
  assert.equal(store.load().pending.length, 1);
  assert.match(store.load().pending[0].lastError, /HTTP 503/);
  store.load().pending[0].nextAt = 0;
  await logger.retryPending();
  assert.equal(store.load().pending.length, 0);
  assert.equal(store.load().calls['unit-call-1'].activityId, 'acti_1');
  assert.equal(seen.filter(s => s.key === 'POST /api/v1/lead/').length, 1, 'the lead made on the first try is reused, not created twice');
  assert.equal(seen.filter(s => s.key === 'POST /api/v1/task/').length, 1);
  assert.equal(seen.find(s => s.key === 'POST /api/v1/task/').body.lead_id, 'lead_made');
  assert.equal(await logger.logCall(snap), store.load().calls['unit-call-1'], 'a logged call is never written again');
  assert.equal(seen.filter(s => s.key === 'POST /api/v1/activity/call/').length, 2, 'one failure, one success');
  assert.ok(seen.every(s => s.auth === `Basic ${Buffer.from('api_TESTunit00000000000000000:').toString('base64')}`), 'every request as the agent\'s own key');
});

test('a failed call-back task is not retried and never duplicates the call', async () => {
  const wsKey = unitOrg('task');
  const seen = fakeClose({ 'POST /api/v1/task/': 1 });
  const snap = {
    callUuid: 'unit-task-1', authId: null, wsKey, userId: 'user_u1', agentName: '', direction: 'inbound', outcome: 'missed',
    talkSeconds: 0, remote: '+919000000099', did: '+910000000001', startedAt: Date.now(), endedAt: Date.now(),
  };
  const saved = await logger.logCall(snap);
  assert.equal(saved.logged, true);
  assert.equal(saved.leadId, 'lead_known');
  assert.equal(seen.filter(s => s.key === 'POST /api/v1/activity/call/').length, 1);
});

test('a log written after the recording arrived keeps the recording', async () => {
  const wsKey = unitOrg('rec');
  const seen = fakeClose({});
  // What /vobiz/recording stores when the file is ready before the call is logged.
  store.putCall('unit-rec-1', { recordingId: 'rec-early', authId: 'MA_TEST0001', wsKey });
  const snap = {
    callUuid: 'unit-rec-1', authId: 'MA_TEST0001', wsKey, userId: 'user_u1', agentName: 'Unit Agent', direction: 'inbound', outcome: 'answered',
    talkSeconds: 30, remote: '+919000000099', did: '+910000000001', startedAt: Date.now(), endedAt: Date.now(), recordingId: null,
  };
  const saved = await logger.logCall(snap);
  assert.equal(saved.recordingId, 'rec-early', 'not overwritten with the snapshot\'s null');
  assert.equal(saved.recordingNoted, true);
  const call = seen.find(s => s.key === 'POST /api/v1/activity/call/').body;
  assert.match(call.recording_url, /^https:\/\/calling\.example\.test\/recordings\/unit-rec-1\?aid=MA_TEST0001&/);
  assert.equal(seen.filter(s => s.key.startsWith('PUT')).length, 0, 'the link went in with the call, no extra update');
});

test('unknown number with "create a lead" off: nothing is written, nothing is retried', async () => {
  const wsKey = unitOrg('nolead');
  store.load().workspaces[wsKey].settings.createUnknown = false;
  const seen = fakeClose({}, { known: false });
  const saved = await logger.logCall({
    callUuid: 'unit-nolead-1', authId: null, wsKey, userId: 'user_u1', agentName: '', direction: 'outbound', outcome: 'answered',
    talkSeconds: 5, remote: '+917000000008', did: '+910000000001', startedAt: Date.now(), endedAt: Date.now(),
  });
  assert.equal(saved.skipped, 'no-lead');
  assert.deepEqual(seen.map(s => s.key), ['POST /api/v1/data/search/']);
  assert.ok(!store.load().pending.some(p => p.callUuid === 'unit-nolead-1'));
});

test('the verifier accepts a nonce once per URL', () => {
  const { makeVerifier } = require('../src/vobiz-signature');
  const verify = makeVerifier({ mode: 'require', publicBaseUrl: 'https://calling.example.test' });
  const sign = (p, nonce) => crypto.createHmac('sha256', 'tok').update(`https://calling.example.test${p}.${nonce}`).digest('base64');
  const reqFor = (p, nonce) => ({ headers: { 'x-vobiz-signature-v3': sign(p, nonce), 'x-vobiz-signature-v3-nonce': nonce } });
  assert.equal(verify(reqFor('/vobiz/answer', 'n-1'), '/vobiz/answer', ['tok']), true);
  assert.equal(verify(reqFor('/vobiz/answer', 'n-1'), '/vobiz/answer', ['tok']), false, 'replay');
  assert.equal(verify(reqFor('/vobiz/hangup', 'n-1'), '/vobiz/hangup', ['tok']), true, 'same nonce on another URL is another signature');
});
