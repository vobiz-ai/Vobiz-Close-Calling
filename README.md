# Vobiz Calling for Close

Agents take and place phone calls from their own Vobiz numbers in the browser, next to Close. Every call is logged in Close as a Call activity on the caller's lead.

- **Know who is calling.** An incoming call shows the contact's name, title, lead and lead status before the agent answers.
- **Call in one click.** Clicking a phone number in Close brings it to the softphone, ready to call.
- **Every call logged.** Answered, missed, busy and failed calls become Close Call activities with direction, status, talk time and agent. An unknown number becomes a new lead. A missed call also gets a "Call back" task.
- **Recordings where you work.** A signed, expiring recording link is set as the call's recording in Close.

Close has no panel where another calling service can hold a live call, so the softphone runs in its own browser tab. It is the same panel as the other Vobiz CRM integrations (Twenty, Help Scout, Zendesk, ClickUp).

## How it fits together

| Part | Where it runs | What it does |
| --- | --- | --- |
| Softphone | `/phone`, a tab the agent keeps open | JsSIP over WSS to `registrar.vobiz.ai`, sign-in, ringing card, call controls, settings, recent calls |
| Click-to-call handler | `/dial`, opened by the browser for `tel:` links or by a Close Integration Link | Hands the number (or Close contact or lead) to the open softphone tab |
| Backend | One Node.js process | Close OAuth or API key, Vobiz sign-in, Vobiz webhooks, Close writes, signed recording playback |

Audio goes straight from the browser to Vobiz. The backend only signs agents in, answers Vobiz with VobizXML, and writes to Close. See [docs/architecture.md](docs/architecture.md).

## What it writes to Close

| Event | Close record |
| --- | --- |
| Any call ends | One **Call activity** (`POST /api/v1/activity/call/`) on the caller's lead and contact: direction, status (`completed`, `no-answer`, `busy`, `cancel`, `failed`), duration in talk seconds, phone, and a note with agent, Vobiz number and call UUID |
| Number matches no contact | A new **lead** named `Caller +91XXXXXXXXXX`, with one contact holding that number (can be turned off) |
| Missed inbound call | A **task** `Call back +91XXXXXXXXXX …` on the lead, due today (can be turned off) |
| Recording is ready | The same Call activity gets `recording_url` (a signed https link), so Close's player plays it |
| Outbound call after clicking a number in Close | Close itself logs a call (with no duration) when a `tel:` link is clicked. The backend finds that call and fills it in instead of logging a second one |

Calls are written as the agent who handled the call, so Close shows them as that agent's. A call nobody answered is written as a connected admin of that organization.

Callers are matched on every phone of every contact, on the full number including the country code.

## Requirements

- Node.js 20 or later (CI uses 24).
- A public HTTPS URL for the backend. Vobiz must reach `/vobiz/answer`, Close redirects agents back to `/close/oauth/callback`, and the browser needs a secure context for the microphone. For development, use a tunnel such as `cloudflared`.
- A Vobiz account with at least one active, voice-enabled number.
- A Close organization. To connect with OAuth, a Close OAuth app (any Close user can create one). Without it, each agent connects with their own Close API key.

## Set up the backend

1. Install dependencies:

   ```bash
   npm ci --prefix backend
   ```

2. Copy the environment template and fill it in:

   ```bash
   cp backend/.env.example backend/.env
   ```

   `backend/.env` holds deployment settings only: the public URL, the Close OAuth app's client id and secret, and two random secrets. It never holds a Vobiz Auth ID, Auth Token, number, SIP credential or a Close API key.

   | Variable | Required | Meaning |
   | --- | --- | --- |
   | `PUBLIC_BASE_URL` | yes | The public `https://` URL of this backend |
   | `SIGNING_SECRET` | yes | 32+ random bytes; signs recording links |
   | `TOKEN_ENC_KEY` | yes | 32 random bytes as 64 hex characters; encrypts stored Close refresh tokens and API keys |
   | `CLOSE_CLIENT_ID`, `CLOSE_CLIENT_SECRET` | for OAuth | The Close OAuth app. Without both, agents connect with API keys |
   | `CLOSE_ALLOW_API_KEYS` | no | Default `true`. With OAuth set up, `false` hides the API-key option |
   | `PORT` | no | Default `8098` |
   | `DATA_DIR` | no | Default `backend/data`; endpoint ids, organizations and encrypted credentials (mode 0600) |
   | `DEFAULT_COUNTRY` | no | Default `IN`; for numbers without a country code. Each organization can override it |
   | `RECORDING_LINK_TTL_SECONDS` | no | Default `900` |
   | `VOBIZ_WEBHOOK_SIGNATURES` | no | `require` (default), `verify` or `off`. Keep `require` in production |
   | `VOBIZ_MEDIA_HOSTS` | no | Default `*.vobiz.ai`. Hosts that may receive the Vobiz Auth ID and Token when recording audio is fetched |
   | `VOBIZ_SIP_AUTH` | no | `jwt` (default): the softphone registers with a short-lived access token. `endpoint`: one SIP endpoint per agent with a password |
   | `VOBIZ_JWT_TTL_SECONDS` | no | Default `3600` (180 to 86400). Access-token lifetime; the softphone renews a minute before expiry |

   Generate each secret with:

   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

3. Start it:

   ```bash
   npm start
   ```

4. Run exactly one instance. Sessions and Vobiz Auth Tokens live in memory, so after a restart agents sign in again.

### Create the Close OAuth app (recommended)

1. In Close, open **Settings → Developer → OAuth Apps** and create an app named "Vobiz Calling".
2. Redirect URL: `<PUBLIC_BASE_URL>/close/oauth/callback`.
3. Give it the `offline_access` scope. Without it Close issues no refresh token, and agents must reconnect every hour.
4. Copy the Client ID and Client Secret into `CLOSE_CLIENT_ID` and `CLOSE_CLIENT_SECRET`, and restart.

Without an OAuth app, the softphone offers only "Connect with API key". Each agent creates their own key under **Settings → Developer → API Keys**. Close attributes everything written with a key to the key's owner, so agents must not share one key.

## Each agent

1. Open `<PUBLIC_BASE_URL>/phone` in its own tab and pin it. Closing the tab stops calls ringing.
2. Click **Connect Close** and approve, or paste your own Close API key. Calls are logged under your name.
3. Sign in to Vobiz with your Auth ID and Auth Token from the Vobiz Console. The backend checks them with Vobiz, finds or creates its calling application in your account, and gives you your own calling identity. The softphone registers with a short-lived access token (JWT) that the backend asks Vobiz to sign for you and renews before it expires. The Auth Token stays in server memory and is never sent to the browser.
4. Pick a caller ID. To receive calls on a number, click **Enable inbound calls**. The softphone names the application the number is on now and asks before moving it.
5. Optional, for click-to-call: in Close, click any phone number and choose **Call using tel: links (Use another calling app)**. Then click **Use this softphone for phone links** in the softphone and allow it in the browser. Close and the softphone must be open in the same browser profile.

### Optional: a "Call with Vobiz" Integration Link

A Close admin can add an Integration Link (**Settings → Integration Links**) of type Contact or Lead that opens:

```text
https://calling.example.com/dial?contact={{ contact.id }}
https://calling.example.com/dial?lead={{ lead.id }}
```

The softphone then offers that record's numbers. Close's help pages show `{{ lead.display_name }}`-style variables; check in your organization that `contact.id` and `lead.id` render before rolling the link out (see "Not yet proven").

## Using it

- **Incoming call:** the softphone rings and shows the caller's name, title, lead, status and last calls. Click **Accept** (or press Enter). With "Open the caller's lead in Close on answer" on in Settings, the lead opens in a new tab.
- **Outgoing call:** type a number in the softphone, or click a phone number in Close. The softphone always shows the number and waits for you to click **Call**, because any website can open a `tel:` link.
- **During a call:** Mute, Hold, Keypad (DTMF), and Transfer (inbound calls, to another signed-in agent).
- **After a call:** the Call activity appears on the lead's timeline. **Recent calls** in the softphone has **Play** (a freshly signed recording link) and **Open** (the lead in Close).

## Settings

A Close organization admin (built-in Admin role) can change these in the softphone's Settings. Everyone else can read them.

| Setting | Default |
| --- | --- |
| Default country | `DEFAULT_COUNTRY` |
| Create a lead for unknown numbers | On. Off: calls from unknown numbers are not logged, because Close keeps every call on a lead |
| Create a "Call back" task for missed calls | On |
| Open the caller's lead in Close on answer | Off |
| Recording link lifetime | 15 minutes (5 minutes to 7 days). Close's player stops working when the link expires |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "Close did not accept that API key" | Copy the key again from **Settings → Developer → API Keys**. The key is the user name only; there is no password. |
| Agents must reconnect Close every hour | Give the OAuth app the `offline_access` scope. The backend logs a warning when Close sends no refresh token. |
| "Signed in elsewhere" | You signed in in another tab or browser. Use that one, or sign in again here. |
| Clicking a number in Close opens Close's own dialer | In Close, choose **Call using tel: links**. |
| Clicking a number says no softphone is open | Open `<PUBLIC_BASE_URL>/phone` in the same browser profile, sign in, and wait for **Ready**. |
| No ringing on inbound calls | Click **Enable inbound calls** for the number, and check at least one agent is signed in. |
| "Vobiz would not issue an access token" | The account could not mint a JWT (`POST /Account/<Auth ID>/JWT/Token/`). Retry; if it persists, set `VOBIZ_SIP_AUTH=endpoint` to fall back to per-agent SIP endpoints. |
| "Registration failed" right after signing in | With access tokens, check the clock on the backend host: a token's `nbf` and `exp` are checked by the registrar. |
| Registration works but outbound calls fail at once | Check `<PUBLIC_BASE_URL>/vobiz/answer` is reachable from the internet and returns XML. Endpoint `sip_registered` is not a reliable health check. |
| Calls are not logged | The softphone says "Reconnect Close": connect again. Failed writes are retried for 24 hours. |
| The recording in Close will not play | The link expired. Use **Play** in the softphone's Recent calls, or raise the link lifetime in Settings. |

## Limitations

- No "SIP direct" sign-in (an existing endpoint's SIP username and password). Without the account's Auth Token the backend cannot verify Vobiz's signed callbacks for those calls, or prove the agent owns the endpoint. Agents sign in with their Vobiz account.
- The softphone is a separate tab. Close has no embeddable calling panel for third-party telephony.
- Click-to-call works through the browser's `tel:` handler: the softphone tab must be open in the same browser profile as Close, and the agent confirms each call.
- Recording links expire. Close stores the URL, not the audio, so its player stops working after the configured lifetime.
- With "Create a lead for unknown numbers" off, calls from unknown numbers are not logged anywhere in Close.
- An API key belongs to one Close organization. A user who belongs to several organizations and connects with an API key is placed in the first organization Close lists for them. Use OAuth for those users.
- Admin rights come from Close's built-in Admin role. Custom roles with admin permissions are treated as non-admins.
- After a backend restart, agents sign in again, and recording links cannot play until someone on that Vobiz account signs in.
- If nobody is signed in when the backend restarts, inbound calls are refused politely and not logged.
- Transfer is blind and works on inbound calls only.
- Recording playback streams the file but does not support seeking (HTTP Range).

## Not yet proven on a live call

These are built and tested against a mock that follows Close's API reference, and need one live check each before they are called verified:

- Outbound and inbound audio, answer, hang-up, mute, hold, DTMF and transfer with a real Vobiz account.
- Access-token renewal: that re-registering with a renewed token keeps the tab registered past the first token's expiry. (Verified live on a sub-account: the registrar accepts `X-Vobiz-Jwt` from JsSIP on REGISTER and outbound INVITEs, the `app` claim routes outbound calls to `/vobiz/answer`, and `<Dial><User>` rings the `<sub>_<Auth ID>` identity.)
- In `VOBIZ_SIP_AUTH=endpoint` mode, whether `{"app_id":"<id>"}` binds the endpoint (the backend verifies and falls back), whether `ParentAuthID` on inbound calls matches the number's owner, and in which form `X-VH-*` headers reach `/vobiz/answer` (both are accepted).
- Close OAuth with a real OAuth app: that the token response carries `organization_id` and `user_id`, and that refresh works with `offline_access`.
- Contact lookup through `POST /api/v1/data/search/` on `contact_phone.phone` with `exact_value` and `phrase` matching, against numbers stored in different formats.
- That Close's own call log from a `tel:` link click is found and filled in (same user, lead and phone, no duration), and that Close plays our signed `recording_url`.
- Integration Link variables `{{ contact.id }}` and `{{ lead.id }}`.

## Development

```bash
npm test                # backend behaviour and security regressions (no network)
npm run lint            # syntax-check every .js, parse every .json
npm run check:secrets   # no credentials or real numbers in the tree
npm run tunnel          # cloudflared quick tunnel to port 8098
```

The tests boot the real server with `fetch` replaced by `backend/test/fetch-mock.cjs`, which simulates two Vobiz accounts and two Close organizations: OAuth with a client secret and rotating refresh tokens, API keys over HTTP Basic, `/me/` with roles, Advanced Filtering search on contact phones, and leads, contacts, call activities and tasks with Close-style ids. Vobiz callbacks in the tests are signed the way Vobiz signs them, with signature checks on.

## Security

- No route returns a SIP password or an access token, or lists accounts or endpoints, without a session token.
- An access token is minted only for the session's own identity (`sub` is a hash of the Close organization and user), lasts an hour by default, and is the only Vobiz credential the browser ever holds. Token requests are throttled per session.
- Vobiz Auth Tokens and Close access tokens live in memory only. Close refresh tokens and API keys are stored encrypted (AES-256-GCM) in `DATA_DIR`, mode 0600, and are never sent back to the browser.
- Close credentials are only ever sent to `api.close.com`. The OAuth client secret never reaches the browser.
- The OAuth flow uses a state bound to the browser by an HttpOnly cookie, and hands the session to the page as a one-time code in the URL fragment.
- Close ids from the browser (Integration Links) must match Close's own id format before they are put in a request path.
- The API-key connect route, the only one that reaches Close without a session, is limited to 10 tries a minute per client.
- Vobiz callbacks are verified with the token of the one account they belong to, worked out from server state, never from `ParentAuthID` or another field the sender chose. A used signature nonce is refused.
- Recording audio is fetched with redirects checked hop by hop; the Vobiz credentials go only to `VOBIZ_MEDIA_HOSTS`.
- Recording links are HMAC-signed over the account, the call and the expiry. They never carry credentials, and the backend only fetches audio URLs that Vobiz's own Recording API returns.
- No CORS headers are sent: every browser request comes from pages this server serves. Pages cannot be framed.
