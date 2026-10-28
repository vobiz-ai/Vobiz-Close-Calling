/**
 * Deployment settings. Nothing account-specific lives here: no Vobiz Auth ID,
 * token, number, endpoint or application id, and no Close API key. Agents
 * sign in from the softphone. The Close OAuth app's client id and secret are
 * the integration's own credentials and do belong here.
 */
const crypto = require('node:crypto');
const path = require('node:path');

const env = process.env;
const strip = s => String(s || '').replace(/\/+$/, '');

const SIGNING_SECRET = env.SIGNING_SECRET || '';
const signingSecret = SIGNING_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Key for encrypting Close refresh tokens and API keys at rest. TOKEN_ENC_KEY
 * is 32 bytes as 64 hex characters or base64.
 * Without it the key is derived from SIGNING_SECRET, which is fine for
 * development but couples two secrets; production should set both.
 */
function encKey() {
  const raw = env.TOKEN_ENC_KEY || '';
  if (/^[0-9a-f]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (raw) {
    const b = Buffer.from(raw, 'base64');
    if (b.length === 32) return b;
    throw new Error('TOKEN_ENC_KEY must be 32 bytes, as 64 hex characters or base64');
  }
  return crypto.createHash('sha256').update(`enc|${signingSecret}`).digest();
}

const config = {
  PORT: Number(env.PORT || 8098),
  PUBLIC_BASE_URL: strip(env.PUBLIC_BASE_URL || env.PUBLIC_BASE),
  SIGNING_SECRET: signingSecret,
  SIGNING_SECRET_IS_EPHEMERAL: !SIGNING_SECRET,
  ENC_KEY: encKey(),
  DATA_DIR: env.DATA_DIR || path.join(__dirname, '..', 'data'),

  VOBIZ_API_BASE: strip(env.VOBIZ_API_BASE || 'https://api.vobiz.ai/api/v1'),
  VOBIZ_REGISTRAR: env.VOBIZ_REGISTRAR || 'registrar.vobiz.ai',
  // How the softphone registers. "jwt" (default): a short-lived access token
  // minted per agent, no SIP endpoint or password. "endpoint": one SIP
  // endpoint per agent with a password rotated at each sign-in.
  VOBIZ_SIP_AUTH: (env.VOBIZ_SIP_AUTH || 'jwt').toLowerCase() === 'endpoint' ? 'endpoint' : 'jwt',
  // Access-token lifetime. Vobiz accepts 180 s to 24 h; the softphone renews
  // the token a minute before it expires.
  VOBIZ_JWT_TTL_SECONDS: Math.min(86400, Math.max(180, Number(env.VOBIZ_JWT_TTL_SECONDS) || 3600)),
  // Hosts that may receive the Vobiz Auth ID and Token when recording audio is
  // fetched. A leading "*." matches subdomains. Any other host (a presigned
  // storage URL, say) is fetched without credentials.
  VOBIZ_MEDIA_HOSTS: String(env.VOBIZ_MEDIA_HOSTS || '*.vobiz.ai').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
  // require (default) | verify | off. See vobiz-signature.js.
  VOBIZ_WEBHOOK_SIGNATURES: (env.VOBIZ_WEBHOOK_SIGNATURES || 'require').toLowerCase(),

  // The Close OAuth app (Settings > Developer > OAuth Apps). Without both,
  // agents connect with their own Close API key instead.
  CLOSE_CLIENT_ID: env.CLOSE_CLIENT_ID || '',
  CLOSE_CLIENT_SECRET: env.CLOSE_CLIENT_SECRET || '',
  // false hides "Connect with an API key" when OAuth is set up.
  CLOSE_ALLOW_API_KEYS: !/^(false|0|no|off)$/i.test(env.CLOSE_ALLOW_API_KEYS || 'true'),
  // Fixed: Close is one hosted service. Tokens are only ever sent here.
  CLOSE_API_BASE: 'https://api.close.com',
  CLOSE_APP_URL: 'https://app.close.com',

  DEFAULT_COUNTRY: (env.DEFAULT_COUNTRY || 'IN').toUpperCase(),
  RECORDING_LINK_TTL_SECONDS: Number(env.RECORDING_LINK_TTL_SECONDS || 900),
  SESSION_TTL_MS: 12 * 60 * 60 * 1000,
  // Wait this long after the A leg hangs up before writing to Close, so the
  // dial result and dial events (which may arrive later) are in.
  LOG_SETTLE_MS: Number(env.LOG_SETTLE_MS || 3000),
  // How long the softphone's report of a call that never reached /vobiz/answer
  // waits for a server record before it is logged on its own.
  PANEL_REPORT_GRACE_MS: Number(env.PANEL_REPORT_GRACE_MS || 8000),
};

module.exports = config;
