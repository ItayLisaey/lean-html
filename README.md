# lean-html

One server, a handful of dependencies, zero sessions. Protect static HTML/CSS/JS files behind your organization's Microsoft Entra ID sign-in.

## Setup

1. [Register an app](https://entra.microsoft.com) in your Azure Entra tenant
2. Copy `.env.example` to `.env` and fill in your values
3. Drop your static files in `public/`

```
pnpm install
pnpm dev
```

## How it works

There is no sign-in page in the app. Unauthenticated visitors get redirected to your org's Microsoft sign-in. After authentication, the server exchanges the authorization code for an id_token, sets an HMAC-signed cookie, and serves the static files.

No sessions, no database, no MSAL SDK.

## Taking it further

- **CSRF protection** — add a `state` parameter to the OAuth flow to prevent request forgery
- **Token refresh** — exchange for a refresh token so users don't get logged out when the id_token expires
- **Role-based access** — use Azure app roles or group claims to restrict access beyond "is in the org"
- **HTTPS in dev** — use a local TLS proxy so cookies behave the same as production
- **Rate limiting** — protect the callback endpoint from abuse
- **Logging** — structured request logs for auditing who accessed what and when
