# JWT Authentication — AppSec Case Study

A security review and remediation of my earlier Node.js authentication project. The case follows the full loop: reproduce a failure, identify the trust boundary, change the implementation, and preserve the result in regression tests.

**[Read the case study →](docs/APPSEC-CASE-STUDY.md)** · [Regression tests](tests/security.test.js) · [Baseline evidence](docs/evidence/baseline-results.json)

## What changed

| Before | After |
| --- | --- |
| Any authenticated user could fetch everyone's password hashes and activation links | `/users` removed; `/me` returns only the caller's public DTO |
| Three-character passwords and effective bcrypt cost 4 | Minimum 15 characters, maximum 72 UTF-8 bytes, cost 12; legacy hashes upgraded on login |
| Registration issued a session before email verification | One-use, hashed, expiring email activation; no session until verification |
| Two simultaneous refreshes could both succeed | Atomic rotation, random JWT IDs, and session-family revocation on replay |
| Refresh tokens appeared in JSON and database records | Cookie-only delivery and SHA-256 digests in MongoDB |
| Weak browser/session controls and distinct login errors | Exact Origin checks, hardened cookies, bounded inputs, generic credential errors, and throttling |
| Tracked cookies/dependencies and 17 vulnerable-package entries | Sensitive runtime artifacts removed; dependencies updated; security checks in CI |

This is a learning project with an explicit threat model, not a claim of production certification. See the [limitations](docs/APPSEC-CASE-STUDY.md#limitations-and-tradeoffs).

## Run locally

Requires Node.js 22+ and a local MongoDB instance. Use an SMTP catcher on port 1025 for development email.

```sh
npm ci --ignore-scripts
cp .env.example .env
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Run the last command **twice** and put the independent values in `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` in `.env`. Check the database, API, frontend, and SMTP settings, then run:

```sh
npm start
```

Activation links are delivered to SMTP, never written to application logs. Registration returns `503` if the SMTP transport fails; it removes the newly created pending account so the request can be retried. A successful registration returns a generic `202`, including for an existing address.

## API contract

Every POST requires `Origin` to equal `CLIENT_URL`, including scripts and API clients. This is a deliberate browser API contract. Browsers set this header themselves. Send JSON for credential requests and use `credentials: 'include'` for session requests.

| Method | Route | Result |
| --- | --- | --- |
| POST | `/api/registration` | `{email, password}` → generic `202`, email activation, no tokens |
| GET | `/api/activate/:token` | One-use, 24-hour link → `303` to `CLIENT_URL` |
| POST | `/api/resend-activation` | `{email}` → generic `202`; one-minute per-account cooldown |
| POST | `/api/login` | Verified account → `{accessToken, user}` + refresh cookie |
| POST | `/api/refresh` | Refresh cookie → rotated cookie + `{accessToken, user}` |
| POST | `/api/logout` | Revoke current session, clear cookie → `204` |
| GET | `/api/me` | `Authorization: Bearer <accessToken>` → `{id, email, isActivated}` |

**Breaking changes:** `/api/users` is removed; GET refresh returns `405`; registration no longer logs in; refresh tokens are no longer in JSON; cookie path is `/api`. Frontends should hold access tokens in memory and serialize refresh requests. A duplicate refresh is treated as replay and signs out the entire current session.

Access JWTs expire after 15 minutes. Refresh sessions have an absolute 30-day lifetime. One active session is supported per user: a new login replaces the previous session. Access checks also verify that the session is active in MongoDB, so logout and replay revocation invalidate access immediately.

## Existing database

For an existing installation, back up the database and stop the old server before switching versions. With `.env` pointing at that database, run this maintenance operation **once** before starting the new server:

```sh
npm run migrate:sessions
npm start
```

The migration deliberately signs out every user and invalidates pending activation links. It preserves accounts, password hashes, and activation status, and normalizes email case/whitespace. It aborts before changing data if legacy addresses would collide after normalization; resolve those accounts before retrying. Pending users can request a fresh email through `/api/resend-activation`. It also clears duplicate legacy session records before the new unique index is created. The migration has been tested against a temporary database; it has not been run on a deployed database.

## Verify the case

```sh
npm test
npm run reproduce:baseline
npm audit --audit-level=moderate
```

Tests use real Express HTTP requests and a disposable MongoDB 8.2.6, with synthetic users and a captured email transport. The first test run downloads MongoDB from the official distribution server; subsequent runs use the local binary cache. No existing database or real SMTP account is used.

`reproduce:baseline` extracts application source from commit `aaa1394` into a temporary directory and demonstrates the original failures. It uses the current patched dependencies and substitutes `crypto.randomUUID()` for legacy `uuid.v4()`. It does not install or execute the old vendored dependency tree, expose real tokens, or contact a deployed service. Run it from a full clone containing the baseline commit.

## Deployment boundaries

- In production, both public URLs must use HTTPS. Use a same-site frontend/API deployment: refresh cookies use `SameSite=Strict`.
- The app keeps `trust proxy` disabled. If deployed behind a reverse proxy, configure an explicit trusted proxy policy and retest IP attribution before relying on per-client limits.
- Rate limits use a process-local store. Multiple instances require shared storage and an account-aware abuse strategy.
- Do not log activation URLs, passwords, access tokens, refresh cookies, or raw database/SMTP errors. Repository history still contains historical token material; removing it from the working tree does not erase history.

## Layout

`app.js` constructs the HTTP application; `server.js` connects MongoDB and starts it. Controllers define the response boundary, services handle account/session logic, and models keep sensitive fields hidden by default. The [case study](docs/APPSEC-CASE-STUDY.md) connects each finding to its remediation and tests.
