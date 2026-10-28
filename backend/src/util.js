const crypto = require('node:crypto');

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

/** Everything interpolated into VobizXML or HTML goes through this. */
function xmlEscape(s) {
  return String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
}
const htmlEscape = xmlEscape;

const COUNTRY_CODES = { IN: '91', US: '1', CA: '1', GB: '44', AE: '971', SG: '65', AU: '61', DE: '49', FR: '33' };
// National number lengths, for turning a trunk-prefixed local number into E.164.
const NATIONAL_LENGTHS = { IN: 10, US: 10, CA: 10, GB: 10, AE: 9, SG: 8, AU: 9, DE: 11, FR: 9 };

/**
 * Normalise a phone number to E.164. Returns '' if it is not a plain number.
 *   "+91 90000 00011" -> "+919000000011"
 *   "09000000011"     -> "+919000000011"  (default country IN)
 *   "9000000011"      -> "+919000000011"  (a bare national number)
 *   "919000000011"    -> "+919000000011"
 */
function toE164(raw, country = 'IN') {
  let s = String(raw || '').trim();
  if (!s) return '';
  s = s.replace(/^sip:/i, '').split('@')[0];
  if (s.startsWith('00')) s = `+${s.slice(2)}`;
  const plus = s.startsWith('+');
  const digits = s.replace(/\D/g, '');
  if (digits.length < 6 || digits.length > 15) return '';
  if (plus) return `+${digits}`;
  const cc = COUNTRY_CODES[country] || '';
  const nat = NATIONAL_LENGTHS[country] || 0;
  if (cc && nat) {
    if (digits.startsWith('0') && digits.length === nat + 1) return `+${cc}${digits.slice(1)}`;
    if (digits.length === nat) return `+${cc}${digits}`;
  }
  return `+${digits}`;
}

const E164_RE = /^\+\d{8,15}$/;
const isE164 = s => E164_RE.test(String(s || ''));
const digitsOf = n => String(n || '').replace(/\D/g, '');

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function hmacHex(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/** "4m 12s", "38s", "1h 2m" */
function formatDuration(totalSeconds) {
  const s = Math.max(0, Math.round(Number(totalSeconds) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

module.exports = { log, xmlEscape, htmlEscape, toE164, isE164, digitsOf, randomToken, safeEqual, hmacHex, formatDuration, sleep };
