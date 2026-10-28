# Architecture

## Parts

```
 Agent's browser                              Backend (one instance)                       Vobiz
 ┌───────────────────────────┐  HTTPS +       ┌──────────────────────────────┐  REST       ┌───────────┐
 │ Softphone tab (/phone)    │ ─ Bearer ────▶ │ /api/*  sessions, sign-in     │ ──────────▶ │ API       │
 │  JsSIP, caller ID, ring   │ ◀── SSE ────── │ /vobiz/* answer, dial, hangup │ ◀────────── │ webhooks  │
 │        ▲ BroadcastChannel │                │ /recordings/* signed playback │             └─────┬─────┘
 │ /dial (tel: handler,      │                │ /close/oauth/* connect        │                   │
 │        Integration Links) │                └──────────────┬───────────────┘                   │
 ├───────────────────────────┤                 OAuth or API key (as the agent)                   │
 │ Close web app             │                               ▼                                   │
 │  "Call using tel: links"  │                          api.close.com                            │
 └─────────────┬─────────────┘                                                                   │
               │            SIP over WSS + media (never through the backend)                     │
               └───────────────────────── wss://registrar.vobiz.ai:5063/ ────────────────────────┘
```

The backend is the Twenty integration's design (`Vobiz-Twenty-CRM`, itself from `Vobiz-Helpscout-Calling`) with the CRM side replaced: the Vobiz modules (`vobiz.js`, `vobiz-signature.js`, `routes-vobiz.js`) are the same code with the CRM ids renamed, and `close.js` replaces `twenty.js`. In the shared code `wsKey` names the CRM tenant, which here is a Close organization.

## Sign-in

1. **Connect Close**, one of two ways:
   - **OAuth** (when `CLOSE_CLIENT_ID` and `CLOSE_CLIENT_SECRET` are set). `/close/oauth/start` sets a short-lived HttpOnly cookie and redirects to `https://app.close.com/oauth2/authorize/` with the client id, redirect URL and state. The callback checks the cookie against `state`, exchanges the code at `https://api.close.com/oauth2/token/` with the client secret, and reads the user with `GET /api/v1/me/`. The organization comes from the token response's `organization_id`. It stores the refresh token encrypted and redirects to `/phone#link=<one-time code>`, which the page trades for a session token.
   - **API key.** `POST /api/identity/apikey` checks the agent's own key with `GET /api/v1/me/` (HTTP Basic, the key as the user name), stores it encrypted and returns a session token. The organization is the first one `/me/` lists.
2. **Sign in to Vobiz.** The agent's key is a hash of the organization and user. The backend verifies the Auth ID and token with `GET /numbers` and finds or creates its application (matched on `answer_url`). Then, by `VOBIZ_SIP_AUTH`:
   - **`jwt` (default): access tokens.** No endpoint is created. The agent's SIP identity is `<agent key>_<Auth ID>`, which Vobiz derives from a token's `sub` and `iss`. Sign-in mints one token to prove the account can issue them. The softphone then calls `POST /api/sip-token` for each token: the backend sends the claims (`iss` Auth ID, `sub` agent key, `nbf`, `exp`, `app` our application id, `per.voice` incoming and outgoing allowed) to `POST /Account/<Auth ID>/JWT/Token/`, and Vobiz signs them with the Auth Token. JsSIP registers with no password and the token in an `X-Vobiz-Jwt` header, sends the same header on every outbound INVITE, and fetches a new token a minute before `exp` and registers again. The `app` claim is what routes the agent's outbound calls to `/vobiz/answer`.
   - **`endpoint`: one SIP endpoint per agent.** The backend finds or creates the endpoint, reads the rewritten username back, rotates its password, and binds it with `{"app_id":"<id>"}` then verifies, falling back to `{"application": <integer>}`. `GET /api/agent` hands that password to the session that signed in.

There is no SIP-direct sign-in: without an account's Auth Token, callbacks about those calls could not be verified and endpoint ownership could not be proven.

An organization is keyed by its Close `organization_id`. A user is an admin when their membership's `role_id` is Close's built-in `admin`.

## Calls

**Outbound.** The browser calls `sip:<number>@registrar.vobiz.ai` with `X-VH-Caller-ID` and `X-VH-Ref` headers (and `X-Vobiz-Jwt` when signed in with an access token). `/vobiz/answer` maps the SIP user to the agent, checks the caller ID belongs to that account, and returns `<Record>` then `<Dial callerId><Number>`.

**Which account a callback is about.** Every Vobiz callback is tied to one account from server state only: the call record for its `CallUUID`, else the agent's SIP user in `From`, else the signed-in account that owns the dialled `To` number. It is verified with that account's token alone, a `ParentAuthID` naming another account is refused, and each signature nonce is accepted once per URL.

**Inbound.** `/vobiz/answer` uses that account (the owner of the dialled number) and rings every signed-in agent of that account with `<Dial callerId="<DID>" callerName="<caller>"><User>…`. It pushes an `incoming` event to those agents' tabs. If nobody is signed in, it speaks a polite message and hangs up.

**Talk time** starts at `DialAnswer` on `/vobiz/dial-events`, and uses the B-leg duration from `DialHangup` when present. On an inbound `DialAnswer` the call moves to the answering agent's own organization, since one Vobiz account can serve several. `/vobiz/hangup` waits `LOG_SETTLE_MS` for late dial callbacks, then logs the call once.

**Transfer** (inbound only) redirects the caller's leg with the Transfer Call API to `/vobiz/transfer-xml`, which rings the target agent's endpoint. The target is stored server side by CallUUID, never in the query string.

**Click-to-call.** With **Call using tel: links** chosen in Close, a phone number click opens a `tel:` link. The softphone registers `/dial?to=%s` as the browser's `tel:` handler. A Close Integration Link can open `/dial?contact=<id>` or `/dial?lead=<id>` instead. `/dial` posts the number or record on a same-origin `BroadcastChannel`; the first signed-in, registered softphone tab answers and shows a confirm banner (with a number picker for a record, from `GET /api/record-phones`). Nothing dials without the agent's click.

## Logging to Close

One Call activity per call, written as the agent who handled it when they are connected, else as a connected admin of that organization, else any connected user:

- The contact is found with `POST /api/v1/data/search/`: contacts with a related `contact_phone` whose `phone` is the E.164 number (`exact_value`) or contains its last digits (`phrase`). Every hit is then compared on the full E.164 number. With none, a lead with one contact is created (`POST /api/v1/lead/`, `Caller +91…`), unless Settings turn that off. The lead and contact ids are stored before the call is written, so a retry never creates a second lead.
- `POST /api/v1/activity/call/` with `lead_id`, `contact_id`, `direction`, `status`, `duration` (talk seconds), `phone`, `activity_at` and a plain-text `note`. Close escapes HTML in `note`, so nothing a caller or agent name contains becomes markup.
- **Close's own tel: call log.** Close logs a call (no duration) when an agent clicks a `tel:` link. Before writing an outbound call as that agent, the backend lists their recent calls on the lead (`GET /api/v1/activity/call/?lead_id&user_id&date_created__gte`) and, if one has the same number, no duration and is not already used by another of our calls, fills it in with `PUT` instead of creating a second.
- A missed inbound call adds `POST /api/v1/task/` (`_type: lead`, due today). A task that fails is not retried; the call activity is the record of the call.
- `RecordStop` stores the recording id with the call at once, then sets `recording_url` (and the note) on the activity with `PUT /api/v1/activity/call/{id}/`. A call written after the recording arrived carries the link from the start.
- Each step's result is stored as soon as Close returns it, so a retry only does what is missing. Every request has a 15-second deadline.
- 401 refreshes an OAuth token and retries once (one refresh in flight per user); an API key that gets 401 marks the user as needing to reconnect. 429 waits `rate_reset` or `Retry-After` (at most 10 s) and retries once. Failed writes are kept and retried for 24 hours.
- The softphone reports JsSIP `failed` and `ended` sessions. A report whose call never reached `/vobiz/answer` is logged on its own after a grace period, so no call is dropped.

## What lives where

| Data | Where | Lifetime |
| --- | --- | --- |
| Vobiz Auth Token | Memory, keyed by Auth ID | Until restart |
| Access token (JWT) | The agent's browser tab, memory only | `VOBIZ_JWT_TTL_SECONDS` (default 1 hour), renewed before expiry |
| SIP password (`endpoint` mode) | Memory, in the agent's session | Rotated each sign-in |
| Close access token (OAuth) | Memory | About an hour, refreshed on demand |
| Close refresh token (OAuth) | `DATA_DIR/store.json`, AES-256-GCM | Replaced on every refresh; revoked on disconnect |
| Close API key | `DATA_DIR/store.json`, AES-256-GCM | Until the agent disconnects |
| Endpoint ids, organizations, call records | `DATA_DIR/store.json` | Calls capped at 5000 |
