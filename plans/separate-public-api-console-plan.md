# Separate Public API from Console (split deployment)

## Goal

Allow deploying Notifuse as two instances of the same image sharing one database:

- **Internet-facing instance**: exposes only the endpoints end users and email providers need.
- **Intranet instance**: runs the console and the full management API, unreachable from the internet.

## Design

A `SERVER_MODE` config value on `ServerConfig` (env `SERVER_MODE`):

- `all` (default): current behavior — console, management API, and public endpoints. Backward compatible.
- `public`: an allowlist middleware (`internal/http/middleware/endpoint_filter.go`) wraps the mux and answers `404` for every path that is not end-user-facing.

Public-mode allowlist:

| Category | Paths |
| --- | --- |
| Health checks | `/health`, `/healthz` |
| Subscription management (email links) | `/preferences`, `/subscribe`, `/unsubscribe`, `/unsubscribe-oneclick` |
| Email tracking | `/t/*`, `/r/*`, `/visit`, `/opens` |
| Notification center widget | `/notification-center*`, `/config.js` (loaded by the widget page) |
| Inbound provider webhooks | `/webhooks/*` (SES/SNS, Mailgun, Postmark, Supabase, …) |

`SERVER_PUBLIC_EXTRA_PATHS` (comma-separated; entries ending with `/` are prefixes) opens additional endpoints in public mode, e.g. `/api/transactional.send` for external systems sending transactional email, or `/api/cron` for an external cron provider.

A single centralized allowlist was chosen over splitting every handler's `RegisterRoutes` into public/private variants: it is auditable in one place, touches no handler code, and route registration stays identical in both modes.

## Implementation

1. `config/config.go`: `ServerConfig.Mode` + `ServerConfig.PublicExtraPaths`, `SERVER_MODE` default `all`, validation (boot fails on unknown mode), `Config.IsPublicMode()` helper. Version bumped to `34.2` (minor — no schema change).
2. `internal/http/middleware/endpoint_filter.go`: `PublicEndpointFilter(extraPaths)` middleware with the allowlist above.
3. `internal/app/app.go` `Start()`: wraps the mux with the filter when `IsPublicMode()` (innermost, so CORS/tracing/graceful-shutdown still apply).
4. `CHANGELOG.md`: 34.2 entry.

## Tests

- `internal/http/middleware/endpoint_filter_test.go`: table-driven — every public endpoint passes, console/management API 404s, extra paths (exact, prefix, normalization, blanks).
- `config/config_test.go` `TestLoad_ServerMode`: default, public, case/whitespace normalization, invalid mode fails boot, extra-path parsing.
- Run: `make test-http`, `go test ./config/`.

## CONSOLE_ENDPOINT: console-facing URLs in a split deployment

`API_ENDPOINT` must stay the **public** URL (tracking/unsubscribe links baked into
sent emails, webhook URLs registered at providers). But four URLs must point at the
**intranet** (console) instance instead. `CONSOLE_ENDPOINT` (env-only, per-instance,
defaults to `API_ENDPOINT`) covers them:

1. **Workspace invitation email link** — `pkg/mailer/mailer.go` `SendWorkspaceInvitation`
   now builds `{ConsoleEndpoint}/console/accept-invitation?token=…`.
2. **OIDC sign-in redirect** — `internal/http/oidc_handler.go` `signinBase()` uses
   `ConsoleEndpoint` (falls back to `APIEndpoint`).
3. **Derived OIDC redirect URI** — `config/oidc.go` derives
   `{ConsoleEndpoint}/api/user.oidc.callback` when `OIDC_REDIRECT_URI` is unset
   (the callback is served by the instance the console user's browser talks to).
4. **Console SPA API calls** — `config.js` now also emits `window.CONSOLE_API_ENDPOINT`
   (= `CONSOLE_ENDPOINT`, defaults to `API_ENDPOINT`); the console's API client
   (`client.ts`, `auth.ts` oidcExchange, `llm.ts`, SignInPage OIDC start) prefers it.
   `window.API_ENDPOINT` keeps the public value because the console displays it as
   the base for tracking/webhook/transactional URLs.

## Deployment notes

- Internet instance: `SERVER_MODE=public`, and typically `TASK_SCHEDULER_ENABLED=false` so only the intranet instance processes broadcast/automation tasks.
- Intranet instance: default mode, serves `/console` and the full API, with `CONSOLE_ENDPOINT=https://notifuse.intranet.example` so invitations/OIDC/console API calls stay on the intranet URL.
- `API_ENDPOINT` (URL baked into tracking/unsubscribe links in emails) must point to the **public** instance on both deployments (it is shared via the system DB).
- Workspace blogs on custom domains (served on `/` by host detection) are not available in public mode; expose them with extra paths only if needed.
