# OIDC Authentication — Implementation Plan

Add OpenID Connect (Authorization Code + PKCE) login to Notifuse **alongside** the existing passwordless magic-code flow. The work is low-risk and well-isolated because a logged-in Notifuse user is fully described by two auth-mechanism-agnostic artifacts — a single `domain.Session` row (`internal/domain/user.go:45-52`) and a single HS256 `UserClaims` JWT minted by `AuthService.GenerateUserAuthToken` (`internal/service/auth_service.go:220-241`) — and the repo already ships a non-magic-code session minter (`UserService.RootSignin`, `internal/service/user_service.go:245-327`). OIDC becomes a **third session-minter** reusing that identical tail: an external IdP issues an RS256/ES256 ID token verified by `go-oidc`; Notifuse mints its own HS256 token; the two JWT systems never mix. The only new persistent schema is one system table, `federated_identities`, keyed on the durable `(issuer, sub)` pair (never email). Config follows the proven SMTP hybrid overlay (env-wins → DB → disabled), with `client_secret` encrypted at rest. The token handoff is a **URL-fragment one-time code**: `/callback` 302s to `/console/signin#oidc_code=<code>`, the SPA reads `location.hash`, immediately `history.replaceState`s it away, then POSTs `{ code }` in the request **body** to `/api/user.oidc.exchange` (works in all deploy topologies, including split console/API origins), and finally calls the **unchanged** `useAuth().signin(token)` path. (An optional `__Host-` HttpOnly cookie variant is documented as same-origin-only hardening.) Estimated effort: **~8.5–11 dev-days** (≈2 weeks with review/QA).

## Locked Decisions

| # | Decision | Resolution | Anchor |
|---|----------|-----------|--------|
| 1 | Config surface | Hybrid, mirroring SMTP exactly: `OIDC_*` env vars win → else DB settings (setup wizard + system-settings drawer) → else disabled. `client_secret` encrypted at rest like the SMTP password. Env-set fields render locked via `GetEnvOverrides`. Saving DB settings triggers graceful restart; setup completion already restarts. Resolution lives in a **new standalone `resolveOIDCConfig` helper** invoked once after `apiEndpoint = strings.TrimRight(...)` (`config.go:764`) and before the `config := &Config{` literal (`config.go:766`), assigned as `OIDC: oidcConfig` inside that literal (alongside `SMTPBridge: smtpBridgeConfig`, `:778`). It does **not** slot into the existing SMTP `if isInstalled && systemSettings != nil { ... } else { ... }` overlay block (`config.go:599-728`, a single two-branch block, not an appendable snippet). | crypto `:304-316`; `GetEnvOverrides` `setup_service.go:151`; settings restart `settings_handler.go:226-318`; setup restart `app.go:533` |
| 2 | Provisioning | Invited-only by default (`OIDC_AUTO_CREATE_USERS=false`): unknown email → reject ("No account — ask to be invited"). JIT auto-create is opt-in, **requires** non-empty domain allowlist (boot fails otherwise) **and** `email_verified==true`. | state machine §1.3 step 2b-iii; membership separation `workspace_service.go:1136-1150` |
| 3 | Topology | Single-instance: the one-time exchange-code store is in-memory (`pkg/cache.InMemoryCache`, ~60s TTL). Requires a new atomic `GetAndDelete`. Multi-replica caveat documented; no DB-backed code store built now. | cache methods `pkg/cache/cache.go:70-146` (no `GetAndDelete` today) |
| 4 | Token handoff | **Primary: URL-fragment one-time code.** `/callback` 302s to `/console/signin#oidc_code=<one-time-code>` (the code in the URL **fragment**, never the query string — fragments are not sent to the server, not logged, and stripped from `Referer`). The SPA reads `location.hash`, immediately `history.replaceState`s it away, then POSTs `{ code }` in the **request body** to `/api/user.oidc.exchange` (no cookie; works cross-origin via the existing CORS + Bearerless POST). `/exchange` does `cache.GetAndDelete(code)` → `{ token, user, expires_at }`. Then the unchanged `useAuth().signin(token)`. Residual: the code is briefly in browser history (mitigated by single-use + ≤60s TTL + immediate `replaceState`). **Optional same-origin hardening:** a `__Host-` HttpOnly one-time-code cookie variant (does NOT work when console and API are on different origins — see §4.5.2). The AEAD-encrypted `__Host-` **flow-state** cookie (state/nonce/verifier) is set+read entirely server-side across a top-level GET redirect, so `SameSite=Lax` is correct and it is **unaffected** by this decision. | `AuthContext.tsx:61-76`; `SignInPage.tsx:33-36`; middleware Bearer-only `auth.go:37-90`; dev origin rewrite `client.ts:41-46`; CORS `cors.go` |
| — | Library | `github.com/coreos/go-oidc/v3` (v3.18.0, Apr 2026) + promote `golang.org/x/oauth2` from indirect to direct (PKCE via `GenerateVerifier`/`S256ChallengeOption`/`VerifierOption`). Internal JWT stays HS256 `golang-jwt/jwt/v5`. | `go.mod:22,113` |

---

## 0. Step 0 — Dependencies (do this FIRST, before writing any other code)

Before implementing anything else, add and pin the library and verify the symbol surface compiles:

```bash
go get github.com/coreos/go-oidc/v3@latest   # pulls v3.18.x (Apr 2026)
go mod tidy                                   # promotes golang.org/x/oauth2 from
                                              # indirect (go.mod:113) to a DIRECT require
```

Then write a throwaway `oidc_smoke_test.go` (or a scratch `main`) that references each symbol the plan depends on and `go build`s it, to confirm the **go-oidc v3.18** API names match before building the rest:

- `oidc.NewProvider(ctx, issuerURL)` and `provider.Endpoint()` / `provider.Verifier(&oidc.Config{...})`.
- `oidc.NewRemoteKeySet` (used internally by `Verifier`; self-refreshing JWKS).
- The alg constants `oidc.RS256`, `oidc.ES256`; `oidc.Config{ClientID, SupportedSigningAlgs}`.
- `oidc.Nonce(nonce)` auth-code option; `idToken.Nonce`, `idToken.Issuer`, `idToken.Claims(&v)`.
- `oauth2.GenerateVerifier()`, `oauth2.S256ChallengeOption(verifier)`, `oauth2.VerifierOption(verifier)`, `oauth2.AccessTypeOnline`, `(*oauth2.Config).AuthCodeURL` / `.Exchange`.

The internal session JWT continues to use `github.com/golang-jwt/jwt/v5` (`go.mod:22`) — unchanged. If any symbol name differs in the resolved version, reconcile here before proceeding (the rest of the plan assumes the names above).

---

## 1. Overview, Architecture & Identity Model

### 1.1 Feasibility verdict

Adding OIDC login is **low-risk and well-isolated**. The decisive reason: a logged-in user is fully described by two *auth-mechanism-agnostic* artifacts — one `domain.Session` row (`internal/domain/user.go:45-52`) and one HS256 `UserClaims` JWT from `AuthService.GenerateUserAuthToken(user, sessionID, expiresAt)` (`internal/service/auth_service.go:220-241`). Nothing downstream of token minting knows *how* the session was created. The verified precedent is `UserService.RootSignin` (`internal/service/user_service.go:245-327`), which creates a `domain.Session` with `MagicCode`/`MagicCodeExpires` left nil (`user_service.go:295-300`) and returns a `domain.AuthResponse` (`internal/domain/user.go:70-74`) carrying the same JWT. OIDC is therefore a *third* session-minter reusing the identical tail.

The auth middleware (`internal/http/middleware/auth.go:37-90`) is Bearer-only, pins the signing method to HMAC to prevent algorithm confusion (`auth.go:63-69`), and re-validates the DB session every request via `AuthService.VerifyUserSession` (`auth_service.go:175-217`) — so an OIDC-minted JWT is **byte-identical** to a magic-code one and needs zero middleware changes. The only new persistent schema is one system table, `federated_identities`. Config follows the proven SMTP hybrid env-wins-then-DB resolution (the SMTP version lives inline in the single two-branch overlay block at `config/config.go:599-728`; OIDC's is a NEW STANDALONE `resolveOIDCConfig` helper, §2.2) with the same encrypt-at-rest treatment used for SMTP credentials (`config/config.go:304-316`, `crypto.DecryptFromHexString`). The one genuinely new low-level primitive is an atomic `GetAndDelete` on `pkg/cache.InMemoryCache` (today the type exposes only `Get`/`Set`/`GetOrSet`/`Delete` at `pkg/cache/cache.go:70-146`), required for single-use redemption of the one-time exchange code.

### 1.2 Architecture: OIDC = a second session-minter

OIDC plugs in as a parallel front door that terminates at the *same* minter. The external IdP and the internal session JWT use two entirely separate JWT systems that **never mix**: the IdP issues an RS256/ES256 ID token verified by `go-oidc` against a self-refreshing JWKS; Notifuse issues its own HS256 `UserClaims` token signed with `SecretKey` (`auth_service.go:240`, `jwt.SigningMethodHS256`). The ID token is consumed and discarded at `/callback`; only the internal HS256 token ever reaches `localStorage` and the middleware.

End-to-end flow (token handoff per Locked Decision 4 — the one-time code travels in the URL **fragment**, then in the POST **body**, never in the query string and never in a cookie on the default path):

```
 Browser (SPA)                 Notifuse backend                    External IdP
 ──────────────                ────────────────                    ────────────
  click "Sign in with SSO"
        │  GET /api/user.oidc.start
        ▼
   ┌────────────────────────────────────────────┐
   │ build authz URL: PKCE S256 challenge,       │
   │ random state + nonce; AEAD-encrypt          │
   │ {state,nonce,verifier} into __Host-oidc_flow│
   │ cookie (AES-GCM via pkg/crypto, SameSite=Lax│
   │  HttpOnly Secure Path=/ Max-Age~300s).      │
   │ This FLOW-STATE cookie is server-side only  │
   │  and is unaffected by the handoff design.   │
   └────────────────────────────────────────────┘
        │  302 -> IdP authorize endpoint
        ▼
                                                   user authenticates / consents
        │  302 back to redirect_uri ?code=…&state=…&iss=…
        ▼
   GET /api/user.oidc.callback
   ┌────────────────────────────────────────────┐
   │ decrypt __Host-oidc_flow cookie; clear it.  │
   │ state match (constant-time).                │
   │ Exchange code+verifier->tokens.             │
   │ Verify ID token (RS256/ES256 only, aud/azp, │
   │  typ!=at+jwt, manual nonce check).          │
   │ RFC 9207: assert idToken.Issuer==IssuerURL  │
   │  UNCONDITIONALLY (post-Verify).             │
   │ Identity state machine (§1.3) -> domain.User│
   │ Create domain.Session (MagicCode nil).      │
   │ JWT = GenerateUserAuthToken(user,sess,exp). │
   │ Stash JWT in InMemoryCache under random     │
   │  one-time code (≤60s TTL, 256-bit entropy). │
   └────────────────────────────────────────────┘
        │  302 -> /console/signin#oidc_code=<one-time-code>
        │        (code in the URL FRAGMENT: not sent to the
        │         server, not logged, stripped from Referer)
        ▼
   SPA reads location.hash -> oidc_code
        │  history.replaceState(...) IMMEDIATELY strips #oidc_code
        │  POST /api/user.oidc.exchange   body: { code }   (no cookie)
        ▼
   ┌────────────────────────────────────────────┐
   │ read code from request BODY.                │
   │ cache.GetAndDelete(code) -> JWT (single use)│
   │ return { token, user, expires_at }          │
   └────────────────────────────────────────────┘
        │  { token }
        ▼
   useAuth().signin(token)  ──>  localStorage['auth_token']   (UNCHANGED)
        │  (AuthContext.tsx:61-76 stores token, calls getCurrentUser)
        ▼
   normal authenticated SPA; every API call sends Bearer token;
   middleware re-checks DB session (auth_service.go:175) — identical to magic-code
```

The one-time code never appears in a URL **query string**, in server access logs, in the `Referer` header, or in proxy logs: `/callback` redirects to `/console/signin#oidc_code=<code>` where the code is in the **URL fragment** (`#…`), which browsers never transmit to any server and which is stripped from `Referer` on subsequent navigation. The SPA reads `window.location.hash`, **immediately** calls `history.replaceState` to remove the fragment (so a refresh or back-navigation cannot replay it), then POSTs `{ code }` in the **request body** to `POST /api/user.oidc.exchange` — no cookie is involved on the default path, so the handoff works in **all deploy topologies**, including split deployments where the console SPA and the API live on different origins (the repo ships exactly such a dev origin rewrite at `console/src/services/api/client.ts:41-46`, and `SameSite=Lax` cookies are **not** sent on a cross-site programmatic POST, while `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` is browser-blocked — see `internal/http/middleware/cors.go`). The SPA reuses the **unchanged** `useAuth().signin(token)` path (`console/src/contexts/AuthContext.tsx:61-76`), which writes `localStorage['auth_token']` and calls `getCurrentUser()` — exactly the magic-code posture (`console/src/pages/SignInPage.tsx:33-36`).

**Residual:** the one-time code is briefly present in the browser's in-memory history entry before `replaceState` removes it. This is mitigated by three independent factors: the code is **single-use** (atomic `GetAndDelete`), has a **≤60s TTL**, and carries **256 bits of entropy** (`randToken(32)`), and `replaceState` runs **before** the network round-trip. Documented honestly here and in the security checklist (§6.C).

**Deployment origin constraints.** The default URL-fragment handoff works in every topology: same-origin, reverse-proxied, and fully split console/API origins. The exchange POST carries no credentials cookie, so it succeeds under the existing CORS posture (the API already serves `Authorization: Bearer` requests cross-origin). The **optional** `__Host-` HttpOnly one-time-code **cookie** variant (§4.5.2) is a *same-origin-only hardening* — it does **not** work when console and API are on different origins, because the browser will not attach the cookie to a cross-origin POST and the `*`-origin + credentials CORS combination is blocked. The AEAD-encrypted `__Host-` **flow-state** cookie (state/nonce/verifier) is a separate mechanism: it is set on `/start` and read on `/callback`, both top-level same-site GET navigations to the API origin entirely within the backend, so `SameSite=Lax` is correct and it is **unaffected** by the handoff choice.

### 1.3 Durable identity model: key on (issuer, sub), never email

Email is mutable and recyclable; the OIDC `sub` claim is the IdP's stable, non-reassigned subject identifier. We introduce a system table:

```sql
federated_identities(
  user_id     VARCHAR(32) NOT NULL REFERENCES users(id),
  idp_issuer  TEXT        NOT NULL,
  idp_sub     TEXT        NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (idp_issuer, idp_sub),   -- one Notifuse user per (issuer, sub)
  UNIQUE (user_id, idp_issuer)    -- AND at most one identity per (user, issuer)
)
```

(See §6.A for the final DDL reconciled with the codebase's no-inline-`REFERENCES` house style and the `id UUID` PK convention.) The **second** `UNIQUE(user_id, idp_issuer)` constraint is deliberate: it caps each user at one identity per issuer, makes the link-conflict check (case 2b-ii) deterministic, and blocks silent `sub` accumulation under a single account. Email is used **only** as a one-time bridge to attach an identity to an already-invited account on first SSO login; after that, all auth keys off `(issuer, sub)`. All email matching in the bridge is **case-insensitive** (see step 2b below), because the existing repo stores and looks up email exactly as given (`internal/repository/user_postgres.go`: `CreateUser` stores the raw `user.Email` ~:42, `GetUserByEmail` is `WHERE email=$1` ~:66 — no normalization).

**Callback identity / linking state machine** (executed after ID-token verification succeeds):

1. **Verify the ID token** (signature via JWKS, `aud`/`azp`, `exp`/`iat`/`nbf`, manual `nonce` equality, `typ != at+jwt`). Then, **unconditionally** (post-Verify), assert `idToken.Issuer == cfg.IssuerURL` — go-oidc pins the discovered issuer internally, but we re-assert it explicitly as the *primary* issuer control. (The `?iss=` query-param check, RFC 9207, is a *defense-in-depth pre-exchange short-circuit only* — see §3.5 / §6.C; it is not the primary defense.) Extract `issuer`, `sub`, `email`, `email_verified`.
2. **Look up `federated_identities` by `(issuer, sub)`.**
   - **2a. FOUND** → load `user_id` → load the `domain.User` → **mint session and stop**. Email is *not* consulted for authentication. (Steady-state path for every returning SSO user.)
   - **2b. NOT FOUND** (first login for this identity) → require `email_verified == true`; if false → **REFUSE** (error redirect + audit log). Then look up `users` by `email` **case-insensitively** via the new `GetUserByEmailInsensitive` (`WHERE lower(email)=lower($1)`, §6.A.6 — NOT the exact-match `GetUserByEmail`, which would miss a mixed-case invited user and could JIT-create a duplicate):
     - **2b-i. existing user found AND that user has NO `federated_identities` row for THIS `issuer`** → **LINK**: `INSERT (user_id, issuer, sub)` → mint session. *This is the bridge that lets an invited (or pre-existing) user adopt SSO on first login.* The `INSERT` is guarded by both unique constraints (see 2b-ii).
     - **2b-ii. existing user found BUT already has a DIFFERENT `sub` for THIS `issuer`** → **REFUSE** (identity conflict / possible email-recycling takeover) → error redirect (`?oidc_error=link_conflict`) + audit log. Do not silently re-link. This is now *deterministic*: `UNIQUE(user_id, idp_issuer)` guarantees `GetByUserAndIssuer` returns 0-or-1 rows, and any LINK `INSERT` that races into a `23505` on **either** unique constraint is **refused** (mapped to `link_conflict`), never swallowed as success.
     - **2b-iii. no user found** → apply **provisioning policy**:
       - default (invited-only, `OIDC_AUTO_CREATE_USERS=false`) → **REFUSE** with "No account — ask to be invited".
       - **ROOT_EMAIL guard (always, even with JIT enabled):** if the verified email matches a configured `ROOT_EMAIL` (`config.IsRootEmail`, `config/root_email.go:34`) → **REFUSE** JIT auto-create and force the invite path. Rationale: a root-matching email is synthesized owner of **all** workspaces (`internal/service/auth_service.go:149-163`), so JIT-minting one from an allowlisted domain would be privilege escalation.
       - JIT enabled (`OIDC_AUTO_CREATE_USERS=true`, which boot-validates a non-empty domain allowlist) → require `email_verified == true`, the email **not** a `ROOT_EMAIL`, **and** the email's (case-insensitive, lower-cased) domain ∈ allowlist → before creating, re-run the case-insensitive `GetUserByEmailInsensitive` duplicate check → `CreateUser` (inserts into `users` only, `user_postgres.go:26-64`) → `INSERT federated_identities` → mint session.
3. On **every** successful login, log the stable `sub` and `issuer` for audit.

**Residual email-recycling risk & guards.** The one exposed window is an invited-but-never-logged-in account (case 2b-i): if a corporate email is deprovisioned and later reassigned to a different person at the same IdP before the original invitee ever logged in via SSO, the new holder's first SSO login would link to the stale invite. Guards baked in: (a) `email_verified == true` is mandatory before any link or create; (b) once linked, step 2a keys solely off `(issuer, sub)`, so the bridge is exercised at most once per account; (c) case 2b-ii hard-refuses any attempt to attach a second `sub` to an already-linked account. We document this residual risk and reserve an **optional stricter future mode** (e.g., disallow email-bridge linking entirely and require an explicit in-app "link SSO" action from an already-authenticated session — see §6.D.7). Login is independent of workspace access regardless: `CreateUser` writes only the `users` row, and workspace membership is a *separate* `AddUserToWorkspace` insert performed by invitation acceptance (`internal/service/workspace_service.go:1136-1150`), so a freshly JIT-provisioned or newly-linked user with no `user_workspaces` row is gated by `AuthService.AuthenticateUserForWorkspace` (`auth_service.go:122-172`) and sees nothing until invited (unless they are a `ROOT_EMAIL`, per the synthesized-owner override at `auth_service.go:149-163`).

### 1.4 What does NOT change

- **Auth middleware** — `RequireAuth` (`internal/http/middleware/auth.go:37-90`) stays Bearer-only with the HMAC alg-confusion pin (`auth.go:63-69`); an OIDC-minted token is parsed identically.
- **Internal JWT scheme** — still HS256 `UserClaims` signed with `SecretKey` via `GenerateUserAuthToken` (`auth_service.go:220-241`). The external RS256/ES256 ID token never enters this system.
- **Session model** — one `domain.Session` row (`internal/domain/user.go:45-52`); OIDC creates it with `MagicCode`/`MagicCodeExpires` nil exactly like `RootSignin` (`user_service.go:295-300`). `VerifyUserSession` (`auth_service.go:175-217`) is unchanged.
- **Workspace authorization** — `AuthenticateUserForWorkspace` (`auth_service.go:122-172`) and the `ROOT_EMAIL` synthesized-owner override (`auth_service.go:149-163`) are untouched; login still ≠ workspace access.
- **Magic-code flow** — `SignIn` / `VerifyCode` / `RootSignin` and their handlers/UI (`SignInPage.tsx`) all remain; OIDC is purely additive. The existing exact-match `GetUserByEmail` (`user_postgres.go:66`) is **not** changed; OIDC adds a *separate* case-insensitive `GetUserByEmailInsensitive` used only by the OIDC bridge (§6.A.6).
- **`AuthContext` / `signin()`** — `console/src/contexts/AuthContext.tsx:61-76` is reused verbatim; the SPA's only new code is reading the `#oidc_code` URL fragment (and `?oidc_error` flag), stripping it via `replaceState`, and calling `/exchange`.
- **DB schema** — no existing table is altered; the *only* schema change is the new system table `federated_identities`, introduced via a new major migration (`v34`, `HasSystemUpdate()=true`, `VERSION` bumped `33.1` → `34.0` per `config/config.go:18` and the CLAUDE.md migration rules).

---

## 2. Configuration (env + setup wizard + settings UI)

This section specifies the **HYBRID** config surface for OIDC, mirroring SMTP/SMTP-Bridge exactly: `OIDC_*` env vars WIN, else DB `settings` rows (set via setup wizard or system-settings drawer), else OIDC is disabled. `client_secret` is encrypted at rest (`pkg/crypto`), like the SMTP password. Env-set fields render locked in the UI via the `GetEnvOverrides` pattern. Saving DB settings triggers the existing graceful-restart (`settings_handler.go:312-318`); setup completion already restarts (`app.go:533`, "server restarts after setup").

### 2.1 `OIDC_*` env var schema

| Env var | Purpose | Required-when | Default |
|---|---|---|---|
| `OIDC_ENABLED` | Master switch. Mirrors `SMTP_BRIDGE_ENABLED` semantics: `IsSet` distinguishes "explicitly off" from "unset" (DB may enable). | never | unset (`""`) |
| `OIDC_ISSUER_URL` | OIDC issuer base URL. Used for discovery (`/.well-known/openid-configuration`) and as the RFC 9207 `iss` to match. | when effective `enabled==true` | `""` |
| `OIDC_CLIENT_ID` | OAuth2 client_id. Also the expected `aud`/`azp`. | when effective `enabled==true` | `""` |
| `OIDC_CLIENT_SECRET` | OAuth2 client_secret. **Secret** — encrypted at rest in DB; never echoed to any exposed path; masked in settings GET. | when effective `enabled==true` | `""` |
| `OIDC_REDIRECT_URI` | Absolute callback URL registered at the IdP. If empty, **derive** from the resolved `apiEndpoint` (after env/DB overlay + `TrimRight "/"`, `config.go:764`) as `<apiEndpoint>/api/user.oidc.callback`. | never (derived) | `<apiEndpoint>/api/user.oidc.callback` |
| `OIDC_SCOPES` | Space-separated scopes. `ParseScopes` **force-includes `openid`** and de-dupes; `email`+`profile` recommended (needed for `email`/`email_verified`/`name`). | never | `"openid email profile"` |
| `OIDC_BUTTON_LABEL` | SSO button text on the sign-in page. **Non-secret** — exposed via `serveConfigJS` `window.*` globals. | never | `"Sign in with SSO"` |
| `OIDC_AUTO_CREATE_USERS` | JIT provisioning opt-in. When `true`, requires a non-empty `OIDC_ALLOWED_DOMAINS` (else boot fails) and `email_verified==true` at callback. Default invited-only. | never | `false` |
| `OIDC_ALLOWED_DOMAINS` | Comma/semicolon/whitespace-separated email-domain allowlist (parsed by reusing `ParseRootEmails`, `config/root_email.go:14`). Gates JIT creation. **Mandatory** when `auto_create==true`. | when effective `auto_create==true` | `""` |

> Note: `OIDC_REDIRECT_URI` is the env-var name; the resolved Go field is `OIDCConfig.RedirectURI`. The IdP-registered redirect path is **always** `/api/user.oidc.callback` (matching the route in §4). Scopes/domains are lists — reuse `ParseRootEmails(setting string) []string` (`config/root_email.go:14`, splits on `,`/`;`/whitespace, de-dupes, preserves order) verbatim for `OIDC_ALLOWED_DOMAINS` (lower-case domains before compare). Add a small `ParseScopes` wrapper in `config/oidc.go` that calls the same splitter and prepends `openid` if absent.

### 2.2 Go: `config/config.go` (+ new `config/oidc.go`)

**New sub-struct + `Config` field.** Add after `SMTPBridgeConfig` (`config.go:162`):

```go
// OIDCConfig holds resolved OpenID Connect settings (env-wins-over-DB).
type OIDCConfig struct {
    Enabled         bool
    IssuerURL       string
    ClientID        string
    ClientSecret    string   // decrypted in-memory; encrypted at rest in DB
    RedirectURI     string   // derived from APIEndpoint when empty
    Scopes          []string // always contains "openid"
    ButtonLabel     string
    AutoCreateUsers bool
    AllowedDomains  []string // lower-cased; gates JIT
}
```

Add to the `Config` struct (`config.go:20-45`), next to `SMTPBridge SMTPBridgeConfig` (`config.go:26`): `OIDC OIDCConfig`.

**`EnvValues` tracking fields.** Extend the `EnvValues` struct (`config.go:48-65`) — mirror the SMTP-bridge string-typed "tri-state" pattern for `OIDC_ENABLED` / `OIDC_AUTO_CREATE_USERS` so an explicit `false` can lock the DB out:

```go
OIDCEnabled         string // "true"/"false"/"" (unset → DB may set)
OIDCIssuerURL       string
OIDCClientID        string
OIDCClientSecret    string
OIDCRedirectURI     string
OIDCScopes          string // raw space-separated
OIDCButtonLabel     string
OIDCAutoCreateUsers string // "true"/"false"/""
OIDCAllowedDomains  string // raw comma/semicolon/space list
```

**`SetDefault` entries.** Add in `LoadWithOptions` near the SMTP defaults (`config.go:386-391`). Do **not** default `OIDC_ENABLED`/`OIDC_AUTO_CREATE_USERS` (we need `IsSet` to detect "unset", exactly like the `SMTP_BRIDGE_ENABLED` comment at `config.go:390`):

```go
// OIDC defaults
v.SetDefault("OIDC_BUTTON_LABEL", "Sign in with SSO")
v.SetDefault("OIDC_SCOPES", "openid email profile")
// NOTE: no default for OIDC_ENABLED / OIDC_AUTO_CREATE_USERS (detect unset via IsSet)
```

**Env reads.** In the env-var resolution block (after the SMTP-bridge reads, ~`config.go:555`, before the `envVals := EnvValues{...}` literal at `config.go:557`), add tri-state reads mirroring `smtpBridgeEnabledStr` (`config.go:525-530`):

```go
var oidcEnabledStr string
if v.IsSet("OIDC_ENABLED") {
    oidcEnabledStr = v.GetString("OIDC_ENABLED")
}
var oidcAutoCreateStr string
if v.IsSet("OIDC_AUTO_CREATE_USERS") {
    oidcAutoCreateStr = v.GetString("OIDC_AUTO_CREATE_USERS")
}
```

Then populate the new `EnvValues` fields inside the literal (`config.go:557-574`):

```go
OIDCEnabled:         oidcEnabledStr,
OIDCIssuerURL:       v.GetString("OIDC_ISSUER_URL"),
OIDCClientID:        v.GetString("OIDC_CLIENT_ID"),
OIDCClientSecret:    v.GetString("OIDC_CLIENT_SECRET"),
OIDCRedirectURI:     v.GetString("OIDC_REDIRECT_URI"),
OIDCScopes:          v.GetString("OIDC_SCOPES"),
OIDCButtonLabel:     v.GetString("OIDC_BUTTON_LABEL"),
OIDCAutoCreateUsers: oidcAutoCreateStr,
OIDCAllowedDomains:  v.GetString("OIDC_ALLOWED_DOMAINS"),
```

**Overlay (env-wins-else-DB) — a NEW STANDALONE helper, not an edit to the SMTP block.** The existing SMTP/bridge overlay at `config/config.go:599-728` is a single two-branch `if isInstalled && systemSettings != nil { ... } else { /* first-run env-only */ }` block, **not** a flat appendable snippet — do **not** try to slot OIDC resolution into it. Instead, define a new standalone `resolveOIDCConfig` helper (§2.3, in `config/oidc.go`), invoke it **once** in `LoadWithOptions` **after** the `apiEndpoint = strings.TrimRight(apiEndpoint, "/")` line (`config.go:764`) and **before** the `config := &Config{` literal (`config.go:766`), and assign its result into that literal as `OIDC: oidcConfig`, alongside `SMTPBridge: smtpBridgeConfig` (~`config.go:778`). Building it after the trim is required because the derived `OIDC_REDIRECT_URI` needs the **final** `apiEndpoint`.

**Fail-fast validation.** Add `func (c OIDCConfig) Validate() error` in `config/oidc.go`, called in `LoadWithOptions` right after `oidcConfig` is built (it must run on every boot path, mirroring `resolveSMTPBridgeTLSMode`'s early failure at `config.go:734-740`):

```go
func (c OIDCConfig) Validate() error {
    if !c.Enabled {
        return nil
    }
    if c.IssuerURL == "" {
        return fmt.Errorf("OIDC is enabled but OIDC_ISSUER_URL is empty")
    }
    if !strings.HasPrefix(c.IssuerURL, "https://") {
        return fmt.Errorf("OIDC_ISSUER_URL must use https (got %q)", c.IssuerURL)
    }
    if c.ClientID == "" {
        return fmt.Errorf("OIDC is enabled but OIDC_CLIENT_ID is empty")
    }
    if c.ClientSecret == "" {
        return fmt.Errorf("OIDC is enabled but OIDC_CLIENT_SECRET is empty")
    }
    if c.RedirectURI == "" {
        return fmt.Errorf("OIDC redirect URI could not be derived (set OIDC_REDIRECT_URI or API_ENDPOINT)")
    }
    if c.AutoCreateUsers && len(c.AllowedDomains) == 0 {
        return fmt.Errorf("OIDC_AUTO_CREATE_USERS=true requires a non-empty OIDC_ALLOWED_DOMAINS allowlist")
    }
    return nil
}
```

Wire in `LoadWithOptions` (after building `oidcConfig`): `if err := oidcConfig.Validate(); err != nil { return nil, err }`. This makes a misconfigured OIDC fail boot loudly — consistent with the SMTP-bridge TLS guard. (Issuer-**unreachable** is a *runtime* concern handled by the service's lazy guarded-retry init in §3.3, not here; `Validate` only checks static fields and never dials the network.)

**Keep `client_secret` out of exposed paths.** `OIDCConfig.ClientSecret` must never be returned by `serveConfigJS` (`root_handler.go:148`) nor by the settings GET (masked, see §2.5). Only `Enabled`, `ButtonLabel`, and a `redirect_uri` hint are non-secret.

**New file `config/oidc.go`** holds: `OIDCConfig`, `OIDCConfig.Validate`, `ParseScopes(string) []string` (reuses the `root_email.go` splitter, prepends `openid`), `resolveOIDCConfig(env EnvValues, ss *SystemSettings, isInstalled bool, apiEndpoint string) OIDCConfig` (§2.3), and a `func (c *Config) IsAllowedOIDCDomain(email string) bool` convenience mirroring `IsRootEmail` (`root_email.go:34`).

### 2.3 DB overlay: `loadSystemSettings` + the overlay block

**`SystemSettings` struct** (`config.go:192-212`) — append:

```go
OIDCEnabled         bool
OIDCIssuerURL       string
OIDCClientID        string
OIDCClientSecret    string // decrypted from encrypted_oidc_client_secret
OIDCRedirectURI     string
OIDCScopes          string
OIDCButtonLabel     string
OIDCAutoCreateUsers bool
OIDCAllowedDomains  string
```

**`loadSystemSettings`** (`config.go:248-356`) — inside the `if settings.IsInstalled {` block (after the SMTP-bridge loads, ~`config.go:352`), mirror the SMTP-bridge decrypt pattern (`config.go:339-350`):

```go
if v, ok := settingsMap["oidc_enabled"]; ok {
    settings.OIDCEnabled = v == "true"
}
settings.OIDCIssuerURL = settingsMap["oidc_issuer_url"]
settings.OIDCClientID = settingsMap["oidc_client_id"]
settings.OIDCRedirectURI = settingsMap["oidc_redirect_uri"]
settings.OIDCScopes = settingsMap["oidc_scopes"]
settings.OIDCButtonLabel = settingsMap["oidc_button_label"]
if v, ok := settingsMap["oidc_auto_create_users"]; ok {
    settings.OIDCAutoCreateUsers = v == "true"
}
settings.OIDCAllowedDomains = settingsMap["oidc_allowed_domains"]

// Decrypt OIDC client secret if present (mirror encrypted_smtp_password, config.go:312)
if enc, ok := settingsMap["encrypted_oidc_client_secret"]; ok && enc != "" {
    if dec, err := crypto.DecryptFromHexString(enc, secretKey); err == nil {
        settings.OIDCClientSecret = dec
    }
}
```

**Overlay logic** — implemented entirely **inside** the new standalone `resolveOIDCConfig` helper (called once from `LoadWithOptions` after `apiEndpoint` is trimmed, per §2.2). It reproduces the *semantics* of the SMTP-bridge env-wins-else-DB resolution (which lives inline in the single two-branch block at `config.go:599-728`) and the `Enabled` tri-state — but as a self-contained function, NOT by editing that block:

```go
func resolveOIDCConfig(env EnvValues, ss *SystemSettings, isInstalled bool, apiEndpoint string) OIDCConfig {
    c := OIDCConfig{
        IssuerURL:    env.OIDCIssuerURL,
        ClientID:     env.OIDCClientID,
        ClientSecret: env.OIDCClientSecret,
        RedirectURI:  env.OIDCRedirectURI,
        ButtonLabel:  env.OIDCButtonLabel,
    }
    // Enabled: explicit env wins; "" → DB (only when installed)
    switch env.OIDCEnabled {
    case "true":
        c.Enabled = true
    case "false":
        c.Enabled = false
    default:
        if isInstalled && ss != nil {
            c.Enabled = ss.OIDCEnabled
        }
    }
    // AutoCreate: same tri-state
    switch env.OIDCAutoCreateUsers {
    case "true":
        c.AutoCreateUsers = true
    case "false":
        c.AutoCreateUsers = false
    default:
        if isInstalled && ss != nil {
            c.AutoCreateUsers = ss.OIDCAutoCreateUsers
        }
    }
    // String fields: env value, else DB
    if isInstalled && ss != nil {
        if c.IssuerURL == "" { c.IssuerURL = ss.OIDCIssuerURL }
        if c.ClientID == "" { c.ClientID = ss.OIDCClientID }
        if c.ClientSecret == "" { c.ClientSecret = ss.OIDCClientSecret }
        if c.RedirectURI == "" { c.RedirectURI = ss.OIDCRedirectURI }
        if c.ButtonLabel == "" { c.ButtonLabel = ss.OIDCButtonLabel }
    }
    // Scopes: env raw, else DB raw, else default; always force-include openid
    rawScopes := env.OIDCScopes
    if rawScopes == "" && isInstalled && ss != nil { rawScopes = ss.OIDCScopes }
    if rawScopes == "" { rawScopes = "openid email profile" }
    c.Scopes = ParseScopes(rawScopes)
    // Allowed domains: env raw, else DB raw
    rawDomains := env.OIDCAllowedDomains
    if rawDomains == "" && isInstalled && ss != nil { rawDomains = ss.OIDCAllowedDomains }
    c.AllowedDomains = normalizeDomains(ParseRootEmails(rawDomains)) // lower-case each
    if c.ButtonLabel == "" { c.ButtonLabel = "Sign in with SSO" }
    // Derive redirect URI from final apiEndpoint when empty
    if c.RedirectURI == "" && apiEndpoint != "" {
        c.RedirectURI = apiEndpoint + "/api/user.oidc.callback"
    }
    return c
}
```

`normalizeDomains` lower-cases each entry. The `/api/user.oidc.callback` path must match the route registered in §4.2.

**Encryption at rest** uses `crypto.EncryptString(str, passphrase)` / `crypto.DecryptFromHexString(str, passphrase)` (`pkg/crypto/crypto.go:86,140`) with `SecretKey` — identical to the SMTP-password handling at `setting_service.go:251-258` and `config.go:312-316`.

### 2.4 `setup_service.go` + `setting_service.go`

**`setting_service.go` — `SystemConfig` struct** (`setting_service.go:13-32`): append `OIDCEnabled bool`, `OIDCIssuerURL`, `OIDCClientID`, `OIDCClientSecret`, `OIDCRedirectURI`, `OIDCScopes string`, `OIDCButtonLabel string`, `OIDCAutoCreateUsers bool`, `OIDCAllowedDomains string`.

**`GetSystemConfig`** (`setting_service.go:47-170`): after the SMTP-bridge loads (`setting_service.go:151-167`), add reads mirroring them — plain `s.repo.Get` for non-secret keys, and decrypt `encrypted_oidc_client_secret` exactly like `encrypted_smtp_password` (`setting_service.go:118-124`):

```go
if setting, err := s.repo.Get(ctx, "oidc_enabled"); err == nil {
    config.OIDCEnabled = setting.Value == "true"
}
if setting, err := s.repo.Get(ctx, "oidc_issuer_url"); err == nil { config.OIDCIssuerURL = setting.Value }
if setting, err := s.repo.Get(ctx, "oidc_client_id"); err == nil { config.OIDCClientID = setting.Value }
if setting, err := s.repo.Get(ctx, "oidc_redirect_uri"); err == nil { config.OIDCRedirectURI = setting.Value }
if setting, err := s.repo.Get(ctx, "oidc_scopes"); err == nil { config.OIDCScopes = setting.Value }
if setting, err := s.repo.Get(ctx, "oidc_button_label"); err == nil { config.OIDCButtonLabel = setting.Value }
if setting, err := s.repo.Get(ctx, "oidc_auto_create_users"); err == nil {
    config.OIDCAutoCreateUsers = setting.Value == "true"
}
if setting, err := s.repo.Get(ctx, "oidc_allowed_domains"); err == nil { config.OIDCAllowedDomains = setting.Value }
if setting, err := s.repo.Get(ctx, "encrypted_oidc_client_secret"); err == nil && setting.Value != "" {
    decrypted, err := crypto.DecryptFromHexString(setting.Value, secretKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt OIDC client secret: %w", err)
    }
    config.OIDCClientSecret = decrypted
}
```

**`SetSystemConfig`** (`setting_service.go:173-335`): after the SMTP-bridge writes (`setting_service.go:304-332`), add writes. Bools as `"true"/"false"` (like `smtp_bridge_enabled`, `setting_service.go:283-290`); plain strings always written to allow clearing (like `smtp_bridge_domain`, `setting_service.go:292-295`); the secret encrypt-or-clear identical to `encrypted_smtp_password` (`setting_service.go:250-263`). Use the full `if err := ...; err != nil { return fmt.Errorf(...) }` form for each (abbreviated here):

```go
oidcEnabledVal := "false"; if config.OIDCEnabled { oidcEnabledVal = "true" }
_ = s.repo.Set(ctx, "oidc_enabled", oidcEnabledVal)
_ = s.repo.Set(ctx, "oidc_issuer_url", config.OIDCIssuerURL)
_ = s.repo.Set(ctx, "oidc_client_id", config.OIDCClientID)
_ = s.repo.Set(ctx, "oidc_redirect_uri", config.OIDCRedirectURI)
_ = s.repo.Set(ctx, "oidc_scopes", config.OIDCScopes)
_ = s.repo.Set(ctx, "oidc_button_label", config.OIDCButtonLabel)
oidcAutoVal := "false"; if config.OIDCAutoCreateUsers { oidcAutoVal = "true" }
_ = s.repo.Set(ctx, "oidc_auto_create_users", oidcAutoVal)
_ = s.repo.Set(ctx, "oidc_allowed_domains", config.OIDCAllowedDomains)

if config.OIDCClientSecret != "" {
    enc, err := crypto.EncryptString(config.OIDCClientSecret, secretKey)
    if err != nil { return fmt.Errorf("failed to encrypt OIDC client secret: %w", err) }
    if err := s.repo.Set(ctx, "encrypted_oidc_client_secret", enc); err != nil { return ... }
} else {
    if err := s.repo.Set(ctx, "encrypted_oidc_client_secret", ""); err != nil { return ... }
}
```

**`setup_service.go` — `SetupConfig` struct** (`setup_service.go:18-36`): append the same nine OIDC fields (`OIDCEnabled bool`, `OIDCIssuerURL/ClientID/ClientSecret/RedirectURI/Scopes/ButtonLabel string`, `OIDCAutoCreateUsers bool`, `OIDCAllowedDomains string`).

**`EnvironmentConfig` struct** (`setup_service.go:68-85`): append tri-state-string fields mirroring `SMTPBridgeEnabled string` (`setup_service.go:79`): `OIDCEnabled string`, `OIDCIssuerURL`, `OIDCClientID`, `OIDCClientSecret`, `OIDCRedirectURI`, `OIDCScopes`, `OIDCButtonLabel string`, `OIDCAutoCreateUsers string`, `OIDCAllowedDomains string`.

**`ConfigurationStatus` struct** (`setup_service.go:49-54`): add `OIDCConfigured bool`. **`GetConfigurationStatus`** (`setup_service.go:109-140`): mirror the SMTP-bridge "explicitly set locks the wizard out" rule (`setup_service.go:128-132`):

```go
oidcConfigured := s.envConfig.OIDCEnabled != "" ||
    s.envConfig.OIDCIssuerURL != "" ||
    s.envConfig.OIDCClientID != ""
```

Return it in the struct, and surface it via `setup_handler.go` `StatusResponse` (`setup_handler.go:43-49`) as `oidc_configured bool`, set at `setup_handler.go:112-118`.

**`GetEnvOverrides`** (`setup_service.go:151-208`): add per-field entries mirroring the SMTP-bridge ones (`setup_service.go:188-205`). Keys must match the settings keys so the UI can lock fields:

```go
if s.envConfig.OIDCEnabled != "" { result["oidc_enabled"] = true }
if s.envConfig.OIDCIssuerURL != "" { result["oidc_issuer_url"] = true }
if s.envConfig.OIDCClientID != "" { result["oidc_client_id"] = true }
if s.envConfig.OIDCClientSecret != "" { result["oidc_client_secret"] = true }
if s.envConfig.OIDCRedirectURI != "" { result["oidc_redirect_uri"] = true }
if s.envConfig.OIDCScopes != "" { result["oidc_scopes"] = true }
if s.envConfig.OIDCButtonLabel != "" { result["oidc_button_label"] = true }
if s.envConfig.OIDCAutoCreateUsers != "" { result["oidc_auto_create_users"] = true }
if s.envConfig.OIDCAllowedDomains != "" { result["oidc_allowed_domains"] = true }
```

**`Initialize` merge** (`setup_service.go:238-373`): add an OIDC block mirroring the SMTP-bridge merge (`setup_service.go:291-310`) — env wins when `status.OIDCConfigured`, else user-provided — then map onto `SystemConfig` in the `systemConfig := &SystemConfig{...}` literal (`setup_service.go:313-332`). For `OIDCScopes`, store the parsed-and-forced string (call `appconfig.ParseScopes` and `strings.Join`) so `openid` is always persisted. Add OIDC validation to `ValidateSetupConfig` (`setup_service.go:210-235`): when the user enables OIDC in the wizard (and it's not env-configured), require `OIDCIssuerURL`/`OIDCClientID`/`OIDCClientSecret`, and require non-empty `OIDCAllowedDomains` when `OIDCAutoCreateUsers` is true — same fail-fast intent as `OIDCConfig.Validate`.

**`app.go` wiring.** `GetEnvValues` (`config.go:917-932`) is a brittle positional multi-return — do **not** extend its signature for 9 more values. Instead, in `app.go:508-525` populate the new `EnvironmentConfig` OIDC fields directly from `a.config.EnvValues.OIDC*` (the struct is already in scope, exactly as `SMTPEHLOHostname`/`SMTPBridgeTLSMode` are read at `app.go:518,524`):

```go
OIDCEnabled:         a.config.EnvValues.OIDCEnabled,
OIDCIssuerURL:       a.config.EnvValues.OIDCIssuerURL,
OIDCClientID:        a.config.EnvValues.OIDCClientID,
OIDCClientSecret:    a.config.EnvValues.OIDCClientSecret,
OIDCRedirectURI:     a.config.EnvValues.OIDCRedirectURI,
OIDCScopes:          a.config.EnvValues.OIDCScopes,
OIDCButtonLabel:     a.config.EnvValues.OIDCButtonLabel,
OIDCAutoCreateUsers: a.config.EnvValues.OIDCAutoCreateUsers,
OIDCAllowedDomains:  a.config.EnvValues.OIDCAllowedDomains,
```

### 2.5 Frontend: SetupWizard, SystemSettingsDrawer, types, handlers

**`internal/http/setup_handler.go`** — `StatusResponse` (`:43-49`) add `OIDCConfigured bool` json `oidc_configured`; `InitializeRequest` (`:52-69`) add the OIDC fields (`OIDCEnabled bool` json `oidc_enabled`, `OIDCIssuerURL`/`OIDCClientID`/`OIDCClientSecret`/`OIDCRedirectURI`/`OIDCScopes`/`OIDCButtonLabel` strings, `OIDCAutoCreateUsers bool` json `oidc_auto_create_users`, `OIDCAllowedDomains` string); map them into `service.SetupConfig` at `:177-194`.

**`internal/http/settings_handler.go`** — `SystemSettingsData` (`:22-41`) add `oidc_*` JSON fields. **Admin-gating (confirm):** the settings GET/UPDATE endpoints are already gated to ROOT_EMAIL/admin via `requireRootUser` (`settings_handler.go:101-104`); the OIDC fields inherit that gate — verify no OIDC secret can be read by a non-admin. In `handleGet` (`:110`) map non-secret fields from `sysConfig`; **mask** `oidc_client_secret`: declare `oidcSecret := sysConfig.OIDCClientSecret`, overlay env in the `GetEnvConfig()` block (`:158-204`) for each `oidc_*` override (and `oidcSecret = env.OIDCClientSecret` when `oidc_client_secret` is overridden), then `if oidcSecret != "" { settings.OIDCClientSecret = passwordMask }` alongside the SMTP mask at `:207-209` (the secret value is NEVER returned). In `handleUpdate` (`:227-318`) round-trip the mask: `if reqData.OIDCClientSecret == passwordMask { reqData.OIDCClientSecret = currentConfig.OIDCClientSecret }` (mirror `:254-257`), then map into `service.SystemConfig` (`:271-290`). The existing restart (`:312-318`) already covers the OIDC reload.

**`console/src/types/setup.ts`** — `SetupConfig` (`:1-19`) add optional `oidc_enabled?`/`oidc_issuer_url?`/`oidc_client_id?`/`oidc_client_secret?`/`oidc_redirect_uri?`/`oidc_scopes?`/`oidc_button_label?`/`oidc_auto_create_users?`/`oidc_allowed_domains?`; `SetupStatus` (`:21-27`) add `oidc_configured: boolean`.

**`console/src/types/settings.ts`** — `SystemSettingsData` (`:1-19`) add the same nine `oidc_*` fields (non-optional, matching the existing flat shape).

**`console/src/pages/SetupWizard.tsx`** — add a new **"SSO (optional)"** collapsible section after the SMTP-Bridge `Collapse` (the bridge block is the `!configStatus.smtp_bridge_configured` gate at `:550-551`). Mirror that gate with `{!configStatus.oidc_configured && (…)}`. Extend the `configStatus` state shape (`:21-31`) and the `setConfigStatus` call (`:48-53`) with `oidc_configured`. Fields: a master `Switch name="oidc_enabled"`; when on (`Form.useWatch`/`shouldUpdate` like the bridge toggle at `:566-572`): `Input name="oidc_issuer_url"` (URL rule), `Input name="oidc_client_id"`, `Input.Password name="oidc_client_secret"`, `Input name="oidc_button_label"` (placeholder "Sign in with SSO"), `Switch name="oidc_auto_create_users"`, and a `Select mode="tags"` `name="oidc_allowed_domains"` shown/required when auto-create is on. In `handleSubmit` (`:88-132`) add an `if (!configStatus.oidc_configured) {…}` block mirroring `:118-126` that joins domains/scopes to strings before assigning to `setupConfig`. Add an optional **"Test discovery"** button next to the issuer field that `fetch`es `<oidc_issuer_url>/.well-known/openid-configuration` (analogous to the SMTP `handleTestConnection` at `:64-86`). All labels via `useLingui` `t\`…\``; run `npm run lingui:extract`.

**`console/src/components/settings/SystemSettingsDrawer.tsx`** — add an **"SSO"** `<Title level={5}>{t\`SSO\`}</Title>` section after the SMTP-Bridge block (ends after `smtp_bridge_tls_key_base64` at `:517-519`), following the exact `Form.Item` + `disabled={isOverridden('<key>')}` + `help={renderEnvHint('<key>')}` pattern (`:451-519`, helpers `isOverridden` `:70`, `renderEnvHint` `:90-97`). Map `fetchSettings` (`:40-53`) to load the new fields, and `handleSave`'s `values` → settings POST. The secret field is `Input.Password name="oidc_client_secret"` whose value arrives masked (`••••••••` `passwordMask`) and round-trips unchanged unless edited. Saving triggers `waitForServerRestart` (`:119-140`) / restart confirm (`:149`) already in place.

**Config exposure for the sign-in button** (non-secret only): `serveConfigJS` (`root_handler.go:148`) emits `window.OIDC_ENABLED` (effective `config.OIDC.Enabled`) and `window.OIDC_BUTTON_LABEL`; the SPA reads them to render the SSO button (§5). `RootHandler` is constructed at `app.go:1081`; pass the relevant `config.OIDC` non-secret fields through (full details in §4.7). Add the two globals to `console/src/vite-env.d.ts`. **Never** expose `OIDCClientSecret`, `OIDCAllowedDomains`, or `OIDCScopes` here.

### 2.6 Tests (this section)

`make test-pkg`/`-service`/`-http`, `cd console && npm test`:
- `config/oidc_test.go`: `OIDCConfig.Validate` table (enabled-but-missing issuer/client_id/secret → err; non-https issuer → err; auto_create+empty domains → err; disabled → nil); `ParseScopes` (force-includes/de-dupes `openid`); `resolveOIDCConfig` (env-wins, DB-fallback, derived redirect URI from trimmed apiEndpoint, tri-state enabled/auto_create, lower-cased domains).
- `config/config_test.go`: `loadSystemSettings` decrypts `encrypted_oidc_client_secret`; `LoadWithOptions` fails boot on invalid OIDC env (sqlmock).
- `internal/service/setting_service_test.go`: `SetSystemConfig` encrypts+clears `encrypted_oidc_client_secret`, writes/clears each `oidc_*`; `GetSystemConfig` decrypts + reads (sqlmock on `domain.SettingRepository`).
- `internal/service/setup_service_test.go`: `GetConfigurationStatus`/`GetEnvOverrides` flag `oidc_*`; `Initialize` env-wins merge persists forced `openid` scope; `ValidateSetupConfig` rejects enabled-without-issuer and auto_create-without-domains.
- `internal/http/settings_handler_test.go` / `setup_handler_test.go`: client_secret masked on GET, mask round-trips on update, env-overridden OIDC fields appear in `env_overrides`; `oidc_configured` surfaced in `setup.status` (GoMock).
- Frontend: `SetupWizard.test.tsx` (SSO section hidden when `oidc_configured`, domains required when auto-create on, discovery button) and `SystemSettingsDrawer.test.tsx` (fields disabled when `env_overrides[oidc_*]`, secret masked).

**Files touched:** `config/config.go`, **new** `config/oidc.go`, `internal/service/setting_service.go`, `internal/service/setup_service.go`, `internal/http/setup_handler.go`, `internal/http/settings_handler.go`, `internal/http/root_handler.go`, `internal/app/app.go`, `console/src/types/setup.ts`, `console/src/types/settings.ts`, `console/src/pages/SetupWizard.tsx`, `console/src/components/settings/SystemSettingsDrawer.tsx`, `console/src/vite-env.d.ts` — plus the tests above.

---

## 3. OIDC Service, ID-Token Validation, Provisioning & Linking

This section specifies the new domain contract (`internal/domain/oidc.go`), the federated-identity repository (schema owned by §6.A's v34 migration), and the service (`internal/service/oidc_service.go`) that owns the full Authorization-Code+PKCE callback, ID-token validation, identity/linking state machine, session minting, and the one-time exchange-code handoff. All session minting reuses the verified `RootSignin` precedent (`internal/service/user_service.go:293-326`) so the resulting JWT is byte-identical to a magic-code login.

### 3.0 Dependencies & assumptions (verified)

- `github.com/coreos/go-oidc/v3/oidc` must be added and `golang.org/x/oauth2` promoted from **indirect** (`go.mod:113 golang.org/x/oauth2 v0.36.0 // indirect`) to a direct require — **done in Step 0** (the `go get` + `go mod tidy` + symbol-smoke-build must pass first). The internal session JWT continues to use `github.com/golang-jwt/jwt/v5` (`go.mod:22`).
- `config.OIDCConfig` (resolved env-wins-then-DB in §1/§2) is read-only here. Field names follow §2.2 (`Enabled`, `IssuerURL`, `ClientID`, `ClientSecret`, `RedirectURI`, `Scopes`, `AutoCreateUsers`, `AllowedDomains`, `ButtonLabel`).
- `pkg/crypto.EncryptString` / `crypto.DecryptFromHexString` (`pkg/crypto/crypto.go:86,140`) — AES-256-GCM, hex-encoded — are reused for `client_secret` at rest (§2) and the flow-state cookie (§4). This service receives the already-decrypted secret in `OIDCConfig`.
- `pkg/cache.InMemoryCache` (`pkg/cache/cache.go:47`) backs the one-time exchange store; it needs a new atomic `GetAndDelete` (§3.6).
- `pkg/ratelimiter.RateLimiter.Allow(namespace, key)` **fails closed on an unknown namespace** (`pkg/ratelimiter/ratelimiter.go:77,83-85`). §4.3 registers `oidc:start` / `oidc:callback` / `oidc:exchange` policies unconditionally in `app.go`.
- `tracing.Tracer` (`pkg/tracing/tracing.go:29-57`) provides `StartServiceSpan`, `AddAttribute`, `MarkSpanError` — mirror `RootSignin` (`user_service.go:246-326`). Fall back to `tracing.GetTracer()` when nil (`user_service.go:52-55`).

### 3.1 `internal/domain/oidc.go` (new file)

> The `FederatedIdentity` entity and `FederatedIdentityRepository` interface are defined once in `internal/domain/federated_identity.go` (§6.A.5). This file (`oidc.go`) holds the OIDC **service** contract, error sentinels, and flow/callback value types. Both files are in package `domain`.

```go
package domain

import (
	"context"
	"errors"
)

//go:generate mockgen -destination mocks/mock_oidc_service.go -package mocks github.com/Notifuse/notifuse/internal/domain OIDCServiceInterface

// ErrOIDCNotConfigured is returned when OIDC is disabled or the upstream
// provider has not yet initialized (graceful degradation). HTTP maps it to 503.
var ErrOIDCNotConfigured = errors.New("oidc not configured")

// ErrOIDCIdentityConflict — (issuer, email) maps to an existing user that
// already holds a DIFFERENT sub for this issuer (possible email-recycling /
// takeover). HTTP maps it to ?oidc_error=link_conflict; the service audit-logs.
var ErrOIDCIdentityConflict = errors.New("oidc identity conflict")

// ErrOIDCAccountNotProvisioned — invited-only policy: verified SSO identity has
// no matching Notifuse user and JIT is disabled.
var ErrOIDCAccountNotProvisioned = errors.New("no Notifuse account for this identity; ask to be invited")

// ErrOIDCEmailNotVerified — IdP did not assert email_verified==true.
var ErrOIDCEmailNotVerified = errors.New("oidc email not verified by provider")

// ErrOIDCDomainNotAllowed — JIT enabled but the email domain is not allowlisted.
var ErrOIDCDomainNotAllowed = errors.New("oidc email domain not allowed")

// OIDCFlowState is the per-login CSRF/replay state, AEAD-encrypted into the
// __Host- flow cookie by the HTTP layer (§4) — Verifier is a secret.
type OIDCFlowState struct {
	State    string `json:"state"`    // opaque CSRF token, compared to ?state=
	Nonce    string `json:"nonce"`    // bound into auth req; checked vs ID-token nonce claim
	Verifier string `json:"verifier"` // PKCE code_verifier (oauth2.GenerateVerifier)
}

// OIDCAuthRequest is returned by BuildAuthURL.
type OIDCAuthRequest struct {
	AuthURL   string
	FlowState OIDCFlowState
}

// OIDCCallbackInput carries the raw query params + the decrypted flow-state.
type OIDCCallbackInput struct {
	Code      string        // ?code=
	State     string        // ?state=
	Iss       string        // ?iss= (RFC 9207; may be empty for non-compliant IdPs)
	FlowState OIDCFlowState // decrypted from the __Host- cookie
}

// OIDCServiceInterface is the service contract consumed by the HTTP layer.
type OIDCServiceInterface interface {
	// IsEnabled reports config.Enabled (cheap; does NOT touch the provider).
	IsEnabled() bool
	// BuildAuthURL generates state+nonce+PKCE verifier, builds the IdP
	// authorization URL (S256), and returns both. ErrOIDCNotConfigured if disabled.
	BuildAuthURL(ctx context.Context) (*OIDCAuthRequest, error)
	// HandleCallback runs the full identity state machine (§3.5), mints the
	// session, stores the AuthResponse under a fresh one-time code, and returns
	// that code (NOT the JWT).
	HandleCallback(ctx context.Context, in OIDCCallbackInput) (oneTimeCode string, err error)
	// ExchangeCode atomically consumes the one-time code and returns the
	// AuthResponse (single-use).
	ExchangeCode(ctx context.Context, oneTimeCode string) (*AuthResponse, error)
}
```

### 3.2 Service struct, config & constructor — `internal/service/oidc_service.go` (new file)

Mirror `UserServiceConfig` (`user_service.go:37-48`) and the `NewUserService` tracer-default pattern (`user_service.go:50-55`).

```go
package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Notifuse/notifuse/config"
	"github.com/Notifuse/notifuse/internal/domain"
	"github.com/Notifuse/notifuse/pkg/cache"
	"github.com/Notifuse/notifuse/pkg/logger"
	"github.com/Notifuse/notifuse/pkg/ratelimiter"
	"github.com/Notifuse/notifuse/pkg/tracing"
)

const (
	// oidcExchangeTTL is the SINGLE shared TTL for the one-time exchange code.
	// The cache Set TTL and the optional cookie Max-Age (§4.5.2) both derive
	// from this one constant so they can never drift.
	oidcExchangeTTL       = 60 * time.Second
	oidcExchangeMaxAge    = int(oidcExchangeTTL / time.Second) // cookie Max-Age, same source of truth
	oidcExchangeKeyPrefix = "oidc:exchange:"
)

type OIDCServiceConfig struct {
	UserRepo              domain.UserRepository
	FederatedIdentityRepo domain.FederatedIdentityRepository
	AuthService           domain.AuthService
	OIDCConfig            config.OIDCConfig
	SessionExpiry         time.Duration
	RateLimiter           *ratelimiter.RateLimiter
	ExchangeCache         cache.Cache       // app wires an InMemoryCache(30s cleanup)
	IsRootEmail           func(string) bool // config.IsRootEmail — guards JIT against ROOT_EMAIL
	IsProduction          bool
	Logger                logger.Logger
	Tracer                tracing.Tracer
}

type OIDCService struct {
	userRepo      domain.UserRepository
	fedRepo       domain.FederatedIdentityRepository
	authService   domain.AuthService
	cfg           config.OIDCConfig
	sessionExpiry time.Duration
	rateLimiter   *ratelimiter.RateLimiter
	exchangeCache cache.Cache
	isRootEmail   func(string) bool
	isProduction  bool
	logger        logger.Logger
	tracer        tracing.Tracer

	initMu      sync.Mutex // guards lazy provider init + self-healing retry
	lastAttempt time.Time  // timestamp of last init attempt (for the retry window)
	provider    *gooidc.Provider
	verifier    *gooidc.IDTokenVerifier
	oauthCfg    *oauth2.Config
	initErr     error
}

func NewOIDCService(cfg OIDCServiceConfig) *OIDCService {
	tracer := cfg.Tracer
	if tracer == nil {
		tracer = tracing.GetTracer()
	}
	return &OIDCService{
		userRepo:      cfg.UserRepo,
		fedRepo:       cfg.FederatedIdentityRepo,
		authService:   cfg.AuthService,
		cfg:           cfg.OIDCConfig,
		sessionExpiry: cfg.SessionExpiry,
		rateLimiter:   cfg.RateLimiter,
		exchangeCache: cfg.ExchangeCache,
		isRootEmail:   cfg.IsRootEmail,
		isProduction:  cfg.IsProduction,
		logger:        cfg.Logger,
		tracer:        tracer,
	}
}

func (s *OIDCService) IsEnabled() bool { return s.cfg.Enabled }
```

`SessionExpiry` is the same `time.Duration` injected into `UserService` (`user_service.go:41`). `ExchangeCache` is injected so tests pass a fake and `app.go` owns the lifecycle/`Stop()`.

### 3.3 Lazy provider/verifier with guarded self-healing retry (JWKS rotation + graceful degradation)

Build `Provider`/`Verifier`/`oauth2.Config` with `context.Background()` (NOT a request context — a request cancel must not poison the long-lived discovery + self-refreshing key set). `provider.Verifier(...)` uses `oidc.NewRemoteKeySet`, which self-refreshes JWKS on unknown `kid` — do **not** snapshot keys. **A plain `sync.Once` is wrong here:** it never re-runs after a failed init, so a provider that was unreachable at the first request would stay "down" (every OIDC route 503) for the **entire process lifetime**, contradicting the lazy-self-healing promise. Instead, guard init with a `sync.Mutex` + a `lastAttempt` timestamp and a retry window (~30s): a successful build is cached forever; a failed build caches `initErr` but is **re-attempted** on the first request after the retry window elapses, so the FIRST reachable request after the issuer recovers succeeds — without a process restart.

```go
const oidcInitRetryWindow = 30 * time.Second

// ensureProvider lazily builds (and self-heals) the provider/verifier/oauth2 config.
// Success is cached forever; a failed init is retried at most once per
// oidcInitRetryWindow so a transient issuer outage recovers without a restart.
func (s *OIDCService) ensureProvider(ctx context.Context) error {
	if !s.cfg.Enabled {
		return domain.ErrOIDCNotConfigured
	}
	s.initMu.Lock()
	defer s.initMu.Unlock()

	// Already initialized successfully.
	if s.provider != nil && s.verifier != nil && s.oauthCfg != nil {
		return nil
	}
	// Within the back-off window after a previous failure: short-circuit to 503.
	if !s.lastAttempt.IsZero() && time.Since(s.lastAttempt) < oidcInitRetryWindow {
		return domain.ErrOIDCNotConfigured
	}
	s.lastAttempt = time.Now()

	bg := context.Background() // discovery + self-refreshing JWKS must outlive any request
	provider, err := gooidc.NewProvider(bg, s.cfg.IssuerURL)
	if err != nil {
		s.initErr = fmt.Errorf("oidc provider init (%s): %w", s.cfg.IssuerURL, err)
		s.logger.WithField("issuer", s.cfg.IssuerURL).WithField("error", err.Error()).
			Error("OIDC provider unreachable; routes will 503 and retry in ~30s (magic-code login unaffected)")
		return domain.ErrOIDCNotConfigured
	}
	s.provider = provider
	s.oauthCfg = &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		RedirectURL:  s.cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.cfg.Scopes, // includes "openid"
	}
	// Pin asymmetric algs; leave all Skip*/Insecure* false.
	s.verifier = provider.Verifier(&gooidc.Config{
		ClientID:             s.cfg.ClientID,
		SupportedSigningAlgs: []string{gooidc.RS256, gooidc.ES256},
	})
	s.initErr = nil
	return nil
}
```

This replaces the `sync.Once`/`initErr`-only fields in the struct (§3.2) with `initMu sync.Mutex` + `lastAttempt time.Time` (keep `provider`/`verifier`/`oauthCfg`/`initErr`). The retry window is small and single-instance-friendly. Prose and code now agree: a transiently-unreachable issuer **self-heals** on the next request after the window, rather than requiring a restart. (Open Question 4 confirms the ~30s window.)

### 3.4 `BuildAuthURL` — state + nonce + PKCE (S256)

```go
func (s *OIDCService) BuildAuthURL(ctx context.Context) (*domain.OIDCAuthRequest, error) {
	ctx, span := s.tracer.StartServiceSpan(ctx, "OIDCService", "BuildAuthURL")
	defer span.End()

	if err := s.ensureProvider(ctx); err != nil {
		return nil, err
	}
	state, err := randToken(32)
	if err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return nil, fmt.Errorf("oidc state gen: %w", err)
	}
	nonce, err := randToken(32)
	if err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return nil, fmt.Errorf("oidc nonce gen: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	authURL := s.oauthCfg.AuthCodeURL(state,
		gooidc.Nonce(nonce),                  // adds &nonce=
		oauth2.S256ChallengeOption(verifier), // adds code_challenge + method=S256
		oauth2.AccessTypeOnline,              // no refresh token; login-only
	)
	return &domain.OIDCAuthRequest{
		AuthURL:   authURL,
		FlowState: domain.OIDCFlowState{State: state, Nonce: nonce, Verifier: verifier},
	}, nil
}
```

The returned `FlowState` is handed to the HTTP layer (§4), which AEAD-encrypts it into the `__Host-` cookie. Rate-limiting of `oidc:start` happens in the handler (§4.3), keyed by client IP.

### 3.5 `HandleCallback` — full identity/linking state machine + all ID-token checks

Order matters: cheap CSRF/issuer checks first, then the network exchange, then cryptographic ID-token verification, then the DB identity state machine, then minting. Every refusal logs the stable `sub` for audit.

```go
func (s *OIDCService) HandleCallback(ctx context.Context, in domain.OIDCCallbackInput) (string, error) {
	ctx, span := s.tracer.StartServiceSpan(ctx, "OIDCService", "HandleCallback")
	defer span.End()

	if err := s.ensureProvider(ctx); err != nil {
		return "", err
	}
	// (0) CSRF: cookie state must equal ?state=.
	if in.State == "" || in.FlowState.State == "" ||
		subtle.ConstantTimeCompare([]byte(in.State), []byte(in.FlowState.State)) != 1 {
		s.tracer.AddAttribute(ctx, "error", "state_mismatch")
		return "", fmt.Errorf("oidc state mismatch")
	}
	// RFC 9207 ?iss= is a DEFENSE-IN-DEPTH PRE-EXCHANGE short-circuit only
	// (cheap, relevant for a future multi-IdP-sharing-one-redirect-URI setup).
	// It is NOT the primary issuer control — the authoritative check is the
	// UNCONDITIONAL post-Verify idToken.Issuer assertion below.
	if in.Iss != "" && in.Iss != s.cfg.IssuerURL {
		s.logger.WithField("got_iss", in.Iss).WithField("want_iss", s.cfg.IssuerURL).
			Warn("OIDC iss parameter mismatch (RFC 9207 pre-exchange short-circuit)")
		s.tracer.AddAttribute(ctx, "error", "iss_mismatch")
		return "", fmt.Errorf("oidc issuer mismatch")
	}
	// Exchange code (PKCE verifier from flow-state).
	oauth2Token, err := s.oauthCfg.Exchange(ctx, in.Code, oauth2.VerifierOption(in.FlowState.Verifier))
	if err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return "", fmt.Errorf("oidc code exchange: %w", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.tracer.AddAttribute(ctx, "error", "no_id_token")
		return "", fmt.Errorf("oidc response missing id_token")
	}
	// RFC 9068 confusion guard: reject typ at+jwt presented as an ID token.
	if err := rejectAccessTokenTyp(rawIDToken); err != nil {
		s.tracer.AddAttribute(ctx, "error", "id_token_typ_at_jwt")
		return "", err
	}
	// Cryptographic verification (RS256/ES256 pinned; iss/aud/exp/iat; Skip* all false).
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return "", fmt.Errorf("oidc id_token verify: %w", err)
	}
	// PRIMARY issuer control (RFC 9207-aligned): UNCONDITIONALLY assert the
	// signed token's issuer equals our configured issuer. go-oidc already pins
	// the discovered issuer inside Verify, but we re-assert it explicitly so the
	// guarantee does not depend on a library internal.
	if idToken.Issuer != s.cfg.IssuerURL {
		s.logger.WithField("got_iss", idToken.Issuer).WithField("want_iss", s.cfg.IssuerURL).
			Error("OIDC id_token issuer mismatch (post-Verify assertion)")
		s.tracer.AddAttribute(ctx, "error", "idtoken_iss_mismatch")
		return "", fmt.Errorf("oidc id_token issuer mismatch")
	}
	// Manual nonce equality — go-oidc Verify does NOT check nonce.
	if idToken.Nonce == "" ||
		subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(in.FlowState.Nonce)) != 1 {
		s.tracer.AddAttribute(ctx, "error", "nonce_mismatch")
		return "", fmt.Errorf("oidc nonce mismatch")
	}
	var claims struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		Azp           string   `json:"azp"`
		Aud           audience `json:"aud"` // tolerates string OR []string
	}
	if err := idToken.Claims(&claims); err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return "", fmt.Errorf("oidc claims decode: %w", err)
	}
	// Multi-audience: azp MUST equal our ClientID only when aud contains a
	// genuine SECOND DISTINCT audience. A single aud — or duplicates like
	// [ClientID, ClientID] — never requires azp (de-dupe before counting).
	if hasDistinctSecondAudience(claims.Aud, s.cfg.ClientID) && claims.Azp != s.cfg.ClientID {
		s.tracer.AddAttribute(ctx, "error", "azp_mismatch")
		return "", fmt.Errorf("oidc azp mismatch for multi-audience token")
	}
	issuer := idToken.Issuer // verified-trusted issuer from the signed token
	sub := claims.Sub
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	s.tracer.AddAttribute(ctx, "oidc.sub", sub)
	s.tracer.AddAttribute(ctx, "oidc.issuer", issuer)

	user, err := s.resolveOrProvisionUser(ctx, issuer, sub, email, claims.EmailVerified, claims.Name)
	if err != nil {
		return "", err // typed errors flow to HTTP layer for redirect mapping
	}
	authResp, err := s.mintSession(ctx, user)
	if err != nil {
		return "", err
	}
	oneTimeCode, err := randToken(32)
	if err != nil {
		return "", fmt.Errorf("oidc one-time code gen: %w", err)
	}
	s.exchangeCache.Set(oidcExchangeKeyPrefix+oneTimeCode, authResp, oidcExchangeTTL)
	s.logger.WithField("user_id", user.ID).WithField("oidc_sub", sub).
		WithField("issuer", issuer).Info("OIDC login succeeded")
	return oneTimeCode, nil
}
```

`audience` is a small local type whose `UnmarshalJSON` accepts both a bare string and a JSON array (the OIDC `aud` claim is `string | []string`).

#### `resolveOrProvisionUser` — the state machine body

Implements the five branches of §1.3. **Critical: error type-assert via `errors.As`, NOT `errors.Is`** — the user repo returns `*domain.ErrUserNotFound` (struct, `user_postgres.go:83`) and `fedRepo` returns `*domain.ErrFederatedIdentityNotFound`.

```go
func (s *OIDCService) resolveOrProvisionUser(
	ctx context.Context, issuer, sub, email string, emailVerified bool, name string,
) (*domain.User, error) {

	// (1) Stable identity lookup by (issuer, sub). Email NOT used for auth here.
	fi, err := s.fedRepo.GetByIssuerSubject(ctx, issuer, sub)
	if err == nil {
		u, uerr := s.userRepo.GetUserByID(ctx, fi.UserID)
		if uerr != nil {
			return nil, fmt.Errorf("oidc linked user load: %w", uerr)
		}
		return u, nil
	}
	var fiNotFound *domain.ErrFederatedIdentityNotFound
	if !errors.As(err, &fiNotFound) {
		return nil, fmt.Errorf("oidc federated lookup: %w", err)
	}

	// NOT FOUND -> first login. email_verified gate applies to every link/provision.
	if !emailVerified {
		s.logger.WithField("oidc_sub", sub).WithField("issuer", issuer).
			Warn("OIDC first-login rejected: email_verified=false")
		return nil, domain.ErrOIDCEmailNotVerified
	}
	if email == "" {
		return nil, domain.ErrOIDCEmailNotVerified
	}

	// (2) Existing Notifuse user by email (invited-user bridge) — CASE-INSENSITIVE.
	// We use GetUserByEmailInsensitive (WHERE lower(email)=lower($1)), NOT the
	// exact-match GetUserByEmail: an invited user stored mixed-case (e.g.
	// "Jane@Corp.com") must be bridged by a lowercased IdP email, and skipping
	// normalization here would JIT-create a duplicate account.
	existing, uerr := s.userRepo.GetUserByEmailInsensitive(ctx, email)
	if uerr == nil {
		linked, lerr := s.fedRepo.GetByUserAndIssuer(ctx, existing.ID, issuer)
		if lerr == nil {
			// Deterministic by UNIQUE(user_id, idp_issuer): at most one row.
			if linked.IDPSub != sub {
				s.logger.WithField("user_id", existing.ID).WithField("issuer", issuer).
					WithField("existing_sub", linked.IDPSub).WithField("incoming_sub", sub).
					Error("OIDC identity conflict: email maps to a user with a different sub for this issuer")
				return nil, domain.ErrOIDCIdentityConflict
			}
			return existing, nil // same sub, row appeared via race
		}
		var linkNotFound *domain.ErrFederatedIdentityNotFound
		if !errors.As(lerr, &linkNotFound) {
			return nil, fmt.Errorf("oidc user-issuer lookup: %w", lerr)
		}
		// LINK: bridge invited user to this identity. linkIdentity REFUSES (maps
		// to ErrOIDCIdentityConflict) on a 23505 from EITHER unique constraint,
		// never swallowing it as success.
		if cerr := s.linkIdentity(ctx, existing.ID, issuer, sub); cerr != nil {
			return nil, cerr
		}
		s.logger.WithField("user_id", existing.ID).WithField("oidc_sub", sub).
			Info("OIDC linked existing (invited) user to federated identity")
		return existing, nil
	}
	var userNotFound *domain.ErrUserNotFound
	if !errors.As(uerr, &userNotFound) {
		return nil, fmt.Errorf("oidc user-by-email lookup: %w", uerr)
	}

	// Provisioning policy.
	if !s.cfg.AutoCreateUsers {
		s.logger.WithField("email", email).WithField("oidc_sub", sub).
			Warn("OIDC login rejected: no Notifuse account (invited-only)")
		return nil, domain.ErrOIDCAccountNotProvisioned
	}
	// ROOT_EMAIL guard: NEVER JIT-create a user whose email matches a configured
	// ROOT_EMAIL — that email is synthesized owner of ALL workspaces
	// (auth_service.go:149-163), so auto-minting it from an allowlisted domain
	// would be privilege escalation. Force the invite path.
	if s.isRootEmail != nil && s.isRootEmail(email) {
		s.logger.WithField("email", email).WithField("oidc_sub", sub).
			Error("OIDC JIT refused: email matches ROOT_EMAIL (would be privilege escalation); invite path required")
		return nil, domain.ErrOIDCAccountNotProvisioned
	}
	if len(s.cfg.AllowedDomains) == 0 { // defense in depth (boot fails otherwise)
		return nil, domain.ErrOIDCAccountNotProvisioned
	}
	if !domainAllowed(email, s.cfg.AllowedDomains) {
		s.logger.WithField("email", email).Warn("OIDC JIT rejected: domain not in allowlist")
		return nil, domain.ErrOIDCDomainNotAllowed
	}

	// JIT create: users row ONLY (no workspace membership — login != access).
	newUser := &domain.User{
		ID:       generateID(),
		Email:    email,
		Name:     name,
		Type:     domain.UserTypeUser,
		Language: domain.DefaultLanguageCode,
	}
	if cerr := s.userRepo.CreateUser(ctx, newUser); cerr != nil {
		var exists *domain.ErrUserExists
		if errors.As(cerr, &exists) { // race: another login created it
			if u, gerr := s.userRepo.GetUserByEmailInsensitive(ctx, email); gerr == nil {
				newUser = u
			} else {
				return nil, fmt.Errorf("oidc jit re-fetch: %w", gerr)
			}
		} else {
			return nil, fmt.Errorf("oidc jit create: %w", cerr)
		}
	}
	if lerr := s.linkIdentity(ctx, newUser.ID, issuer, sub); lerr != nil {
		return nil, lerr
	}
	s.logger.WithField("user_id", newUser.ID).WithField("oidc_sub", sub).
		Info("OIDC JIT-provisioned new user")
	return newUser, nil
}

// linkIdentity inserts (user_id, issuer, sub). A duplicate-key (PG 23505) on
// EITHER unique constraint — UNIQUE(idp_issuer, idp_sub) or
// UNIQUE(user_id, idp_issuer) — is REFUSED as an identity conflict, never
// swallowed as success: it means either this (issuer,sub) is already owned by a
// different user, or this user already linked a DIFFERENT sub for this issuer
// concurrently. Both are link conflicts that must surface as
// ?oidc_error=link_conflict, not a silent re-link.
func (s *OIDCService) linkIdentity(ctx context.Context, userID, issuer, sub string) error {
	err := s.fedRepo.Create(ctx, &domain.FederatedIdentity{
		UserID: userID, IDPIssuer: issuer, IDPSub: sub,
	})
	if err == nil {
		return nil
	}
	var exists *domain.ErrFederatedIdentityExists
	if errors.As(err, &exists) {
		// Re-read to distinguish a benign exact-duplicate race (same row already
		// present: same user_id, issuer, sub) from a genuine conflict on either
		// constraint. Only an exact match is benign; anything else is a conflict.
		if cur, gerr := s.fedRepo.GetByUserAndIssuer(ctx, userID, issuer); gerr == nil &&
			cur.IDPSub == sub && cur.UserID == userID {
			return nil // exact same link landed first via race — idempotent success
		}
		s.logger.WithField("user_id", userID).WithField("issuer", issuer).
			WithField("incoming_sub", sub).
			Error("OIDC link create hit a unique-constraint conflict; refusing")
		return domain.ErrOIDCIdentityConflict
	}
	return fmt.Errorf("oidc link create: %w", err)
}
```

> `GetByUserAndIssuer` is used here to detect the 2b-ii conflict before linking; it returns 0-or-1 deterministically thanks to the new `UNIQUE(user_id, idp_issuer)` constraint (§6.A.2). §6.A.5 lists the repository methods `GetByIssuerSubject`, `Create`, `ListByUserID`; **add `GetByUserAndIssuer(ctx, userID, issuer string) (*FederatedIdentity, error)`** to the `FederatedIdentityRepository` interface and the Postgres impl (`WHERE user_id=$1 AND idp_issuer=$2`, `sql.ErrNoRows` → `*ErrFederatedIdentityNotFound`). The `*ErrFederatedIdentityExists` sentinel (duplicate-key on `Create`, on **either** unique constraint) is also added alongside `*ErrFederatedIdentityNotFound` in `federated_identity.go`.
>
> **`GetUserByEmailInsensitive` (Fix 2).** Also add `GetUserByEmailInsensitive(ctx, email string) (*User, error)` to `domain.UserRepository` and the Postgres impl (`WHERE lower(email)=lower($1)`, `sql.ErrNoRows` → `*ErrUserNotFound`), backed by a functional index `lower(email)` added in the v34 migration (§6.A.2). It is used by BOTH the invited-user link lookup and the JIT duplicate check. The existing exact-match `GetUserByEmail` (used by the magic-code flow) is **left unchanged**.

#### `mintSession` — verbatim `RootSignin` minting (`user_service.go:293-326`)

```go
func (s *OIDCService) mintSession(ctx context.Context, user *domain.User) (*domain.AuthResponse, error) {
	expiresAt := time.Now().Add(s.sessionExpiry)
	session := &domain.Session{
		ID:        generateID(),
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		// MagicCode / MagicCodeExpires left nil — identical to RootSignin (user_service.go:295-300)
	}
	if err := s.userRepo.CreateSession(ctx, session); err != nil {
		s.tracer.MarkSpanError(ctx, err)
		return nil, fmt.Errorf("oidc create session: %w", err)
	}
	token := s.authService.GenerateUserAuthToken(user, session.ID, expiresAt)
	if token == "" {
		return nil, fmt.Errorf("oidc token generation failed")
	}
	return &domain.AuthResponse{Token: token, User: *user, ExpiresAt: expiresAt}, nil
}
```

This produces a `domain.Session` with `MagicCode == nil` and an HS256 `UserClaims` JWT via `AuthService.GenerateUserAuthToken` (`auth_service.go:220-248`). `middleware.RequireAuth` (`internal/http/middleware/auth.go:37`) re-validates the session each request via `VerifyUserSession` (`auth_service.go:175`), so the OIDC-minted token is byte-identical downstream and `/api/user.me` (`user_handler.go:200`) works unchanged. Workspace access still requires a separate `user_workspaces` row (`auth_service.go:122`).

### 3.6 `ExchangeCode` + the new atomic `cache.GetAndDelete`

Add `GetAndDelete` to both the `Cache` interface (`pkg/cache/cache.go:10-33`) and `InMemoryCache` (using the existing `c.mu`/map at `cache.go:48-49,88-97,138-143`):

```go
// add to Cache interface: GetAndDelete(key string) (interface{}, bool)

func (c *InMemoryCache) GetAndDelete(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, found := c.items[key]
	if !found || item.isExpired() {
		if found {
			delete(c.items, key)
		}
		return nil, false
	}
	delete(c.items, key)
	return item.value, true
}
```

```go
func (s *OIDCService) ExchangeCode(ctx context.Context, oneTimeCode string) (*domain.AuthResponse, error) {
	ctx, span := s.tracer.StartServiceSpan(ctx, "OIDCService", "ExchangeCode")
	defer span.End()

	if !s.cfg.Enabled {
		return nil, domain.ErrOIDCNotConfigured
	}
	if oneTimeCode == "" {
		return nil, fmt.Errorf("oidc exchange: empty code")
	}
	v, ok := s.exchangeCache.GetAndDelete(oidcExchangeKeyPrefix + oneTimeCode)
	if !ok {
		s.tracer.AddAttribute(ctx, "error", "code_not_found_or_used")
		return nil, fmt.Errorf("oidc exchange: invalid or expired code")
	}
	authResp, ok := v.(*domain.AuthResponse)
	if !ok {
		return nil, fmt.Errorf("oidc exchange: corrupt cache entry")
	}
	return authResp, nil
}
```

**Multi-replica caveat:** the in-memory store assumes single-instance; under multiple replicas `/callback` and `/exchange` may hit different pods and the lookup fails. Documented loudly; future fix is a Postgres-backed code table or shared cache (§6.D.7), **not built now**. `app.go` wires `cache.NewInMemoryCache(30 * time.Second)` and adds it to the shutdown `Stop()` list near `internal/app/app.go:1431-1432`.

### 3.7 Local helpers

```go
// randToken: n random bytes base64url-encoded (no padding) — state, nonce, one-time code.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// domainAllowed: is email's domain in the allowlist (case-insensitive)?
func domainAllowed(email string, allowed []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	dom := strings.ToLower(email[at+1:])
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == dom {
			return true
		}
	}
	return false
}

// hasDistinctSecondAudience reports whether aud contains any entry that is NOT
// our ClientID — i.e. a genuine second distinct audience. Duplicates of our own
// ClientID (e.g. [ClientID, ClientID]) and a lone ClientID return false, so azp
// is required exactly when it is meaningful (per OIDC Core §3.1.3.7).
func hasDistinctSecondAudience(aud []string, clientID string) bool {
	for _, a := range aud {
		if a != clientID {
			return true
		}
	}
	return false
}

// rejectAccessTokenTyp: reject JWT header typ == "at+jwt"/"application/at+jwt" (RFC 9068) presented as an ID token.
func rejectAccessTokenTyp(raw string) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("oidc id_token malformed")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("oidc id_token header decode: %w", err)
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("oidc id_token header parse: %w", err)
	}
	// Reject both the bare media subtype and the full media type, case-insensitively
	// (RFC 9068 registers "at+jwt"; some IdPs emit "application/at+jwt").
	if strings.EqualFold(hdr.Typ, "at+jwt") || strings.EqualFold(hdr.Typ, "application/at+jwt") {
		return fmt.Errorf("oidc rejected: id_token has access-token typ %q", hdr.Typ)
	}
	return nil
}
```

### 3.8 Mock generation

`internal/domain/oidc.go` carries the `//go:generate mockgen` directive for `OIDCServiceInterface`; `internal/domain/federated_identity.go` carries the directive for `FederatedIdentityRepository` (§6.A.5). Run `go generate ./internal/domain/...` to emit `internal/domain/mocks/mock_oidc_service.go` and `mock_federated_identity_repository.go`. The HTTP tests (§4.9) use the OIDC-service mock; the service tests (§3.9) use the federated-identity-repo mock + `mock_user_repository.go` + `mock_auth_service.go`.

### 3.9 Service / repository / cache / domain tests

**`internal/domain/oidc_test.go`** (`make test-domain`): `audience.UnmarshalJSON` (string→1-elem; array→N; invalid→err). (Federated-identity error `.Error()` tests live in `internal/domain/federated_identity_test.go`, §6.B.)

**`pkg/cache/cache_test.go`** (`make test-pkg`):
- `TestInMemoryCache_GetAndDelete_Found` — Set then GetAndDelete → value+true; second call → nil+false.
- `TestInMemoryCache_GetAndDelete_Miss` — unknown key → nil+false.
- `TestInMemoryCache_GetAndDelete_Expired` — TTL-elapsed → nil+false and key removed.
- `TestInMemoryCache_GetAndDelete_Concurrent` — N goroutines on one key; exactly one observes `true` (atomic counter, run `-race`).

**`internal/service/oidc_service_test.go`** (`make test-service`; GoMock for repos + `AuthService`; fake `cache.Cache`; stub tracer via `tracing.GetTracer()`). For `Verify` cases, stand up an `httptest` OIDC provider (discovery + JWKS, test RSA key) and point `cfg.IssuerURL` at it, or factor `resolveOrProvisionUser` into a separately-tested unit so identity cases avoid real crypto:
- `IsEnabled` true/false.
- `ensureProvider` **self-healing** (Fix 5): unreachable issuer → every method returns `domain.ErrOIDCNotConfigured`, no panic; a second call **within** the retry window short-circuits without re-dialing; after the issuer becomes reachable **and** the ~30s retry window elapses (inject a fake clock or set `lastAttempt` back), the next call **succeeds** and provider/verifier are built.
- `BuildAuthURL`: distinct non-empty `state`/`nonce`; URL has `code_challenge`, `code_challenge_method=S256`, `nonce=`, `state=`; disabled → `ErrOIDCNotConfigured`.
- `HandleCallback` state-mismatch → error before exchange (no repo calls).
- RFC 9207 pre-exchange short-circuit: `in.Iss` set and != configured issuer → `iss_mismatch` (defense-in-depth path).
- **Post-Verify issuer pin (Fix 4):** a validly-signed ID token whose `iss` claim differs from `cfg.IssuerURL` → `idtoken_iss_mismatch` error, even when `?iss=` was absent/matching.
- ID-token checks: bad signature/alg (HS256 while pinned RS256/ES256) → error; `typ=at+jwt` **and** `typ=application/at+jwt` (case-insensitive) → rejected (table on `rejectAccessTokenTyp`); nonce mismatch → error; `email_verified=false` first login → `ErrOIDCEmailNotVerified`.
- **azp (Fix: also-fix):** `aud=[ClientID]` (single) → azp not required, accepted; `aud=[ClientID, ClientID]` (duplicate, still one *distinct* audience) → azp not required; `aud=[ClientID, other]` (genuine second distinct audience) + `azp != ClientID` → `azp_mismatch`; same multi-distinct-aud + `azp == ClientID` → accepted.
- State machine: found `(issuer,sub)` → loads by ID, never calls any email lookup; not-found + verified + existing user (matched **case-insensitively** via `GetUserByEmailInsensitive`) w/o link → LINK (`Create` once) → mint (assert `errors.As`, not `errors.Is`); existing user w/ DIFFERENT sub → `ErrOIDCIdentityConflict` (audit log asserted); no user + `AutoCreateUsers=false` → `ErrOIDCAccountNotProvisioned`; JIT on + empty allowlist → `ErrOIDCAccountNotProvisioned`; JIT on + domain denied → `ErrOIDCDomainNotAllowed`; JIT on + allowed → `CreateUser(Type=UserTypeUser, Language="en")` → `Create` → mint; `CreateUser`→`*ErrUserExists` race → re-fetch (insensitive) → link.
- **Email case-insensitivity (Fix 2):** invited user stored mixed-case (`Jane@Corp.com`) + lowercased IdP email (`jane@corp.com`) → bridged via `GetUserByEmailInsensitive` to the SAME existing user, **no** duplicate `CreateUser` call.
- **Link-conflict unique-violation paths (Fix 3):** LINK `Create` returns `*ErrFederatedIdentityExists` AND a follow-up `GetByUserAndIssuer` shows a different sub / different user → `ErrOIDCIdentityConflict` (both the `UNIQUE(idp_issuer, idp_sub)` and the `UNIQUE(user_id, idp_issuer)` violation paths covered); exact-duplicate race (same user/issuer/sub) → idempotent success.
- **ROOT_EMAIL JIT guard (Fix 6):** JIT enabled + allowlisted domain, but the verified email matches a configured ROOT_EMAIL (`isRootEmail` returns true) → `ErrOIDCAccountNotProvisioned`, **no** `CreateUser` call, audit log asserted.
- `mintSession` builds `Session{MagicCode:nil}` + `GenerateUserAuthToken`; empty token → error.
- `ExchangeCode`: valid code once; second call invalid/expired; empty code → error; corrupt cache type → error.

**`internal/repository/federated_identity_postgres_test.go`** (`make test-repo`, sqlmock): `GetByIssuerSubject` hit / `sql.ErrNoRows`→`*ErrFederatedIdentityNotFound`; `GetByUserAndIssuer` same; `Create` success / duplicate-key string → `*ErrFederatedIdentityExists` / other error wrapped; `ListByUserID` multi-row + empty. (Full repo spec in §6.A.6.)

**Integration** (`make test-integration`, only the new `Test*` funcs; add new SSO member emails to `tests/testutil/database.go`): a happy-path test driving `BuildAuthURL` → `HandleCallback` (against an httptest IdP) → `ExchangeCode`, then `/api/user.me` with the minted token. (See §6.B.7.)

**Anchors:** `user_service.go:37-55,245,293-326`; `auth_service.go:21,122,175,220-248`; `domain/user.go:34-52,70-74`; `user_postgres.go:17-89,57-60,83`; `pkg/cache/cache.go:10-33,47-49,88-97,138-143`; `pkg/ratelimiter/ratelimiter.go:77,83-85`; `pkg/tracing/tracing.go:29-57`; `internal/domain/languages.go:4`; `internal/app/app.go:476-484,1431-1432`; `go.mod:22,113`.

---

## 4. HTTP Handler, Routes, Cookies & Handoff

A dedicated `OIDCHandler` (NOT bolted onto `UserHandler`) owns three public routes, the AEAD-encrypted flow-state cookie, the one-time-code handoff cookie, and `config.js` exposure. It consumes the service interface from §3 and the config surface from §2.

### 4.1 New file: `internal/http/oidc_handler.go`

`OIDCHandler` is standalone because it depends on the OIDC service, `*config.Config`, the `RateLimiter`, and `SecretKey` (a different dependency set than `UserHandler`, `internal/http/user_handler.go:32-39`), and it owns cookie semantics the JSON-only `UserHandler` does not.

```go
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/Notifuse/notifuse/config"
	"github.com/Notifuse/notifuse/internal/domain"
	"github.com/Notifuse/notifuse/pkg/logger"
	"github.com/Notifuse/notifuse/pkg/ratelimiter"
	"github.com/Notifuse/notifuse/pkg/tracing"
)

type OIDCHandler struct {
	service     domain.OIDCServiceInterface
	config      *config.Config
	secretKey   string // for cookie AEAD (config.Security.SecretKey)
	rateLimiter *ratelimiter.RateLimiter
	logger      logger.Logger
	tracer      tracing.Tracer
	isSecure    bool // HTTPS? controls Secure attr / __Host- viability in dev
}

func NewOIDCHandler(
	service domain.OIDCServiceInterface,
	cfg *config.Config,
	secretKey string,
	rateLimiter *ratelimiter.RateLimiter,
	logger logger.Logger,
) *OIDCHandler {
	return &OIDCHandler{
		service:     service,
		config:      cfg,
		secretKey:   secretKey,
		rateLimiter: rateLimiter,
		logger:      logger,
		tracer:      tracing.GetTracer(),
		isSecure:    strings.HasPrefix(cfg.APIEndpoint, "https://"),
	}
}
```

The handler treats the flow cookie as **opaque ciphertext**: it passes the still-encrypted blob into `domain.OIDCCallbackInput` and lets the **service** own AEAD decryption (so the AES key — `SecretKey` — never leaves the service layer). `isSecure` is derived from `config.APIEndpoint` (canonical externally-reachable origin, overlaid at `config/config.go:606`, trailing slash trimmed at `:764`); it governs the `Secure` cookie attribute and the `__Host-` prefix (see §4.6 dev caveat).

> Reconciliation note: §3's `OIDCServiceInterface.BuildAuthURL` returns `*OIDCAuthRequest{AuthURL, FlowState}` and `HandleCallback` takes `OIDCCallbackInput`. The handler is responsible for sealing `FlowState` into the cookie on `start` and recovering it on `callback`. To keep the AEAD key in the service, expose two tiny service helpers `SealFlowState(OIDCFlowState) (string, error)` / `OpenFlowState(string) (OIDCFlowState, error)` (thin wrappers over `crypto.EncryptString`/`DecryptFromHexString` with `SecretKey`), and have the handler call them. This preserves "AEAD key lives in the service" while keeping the cookie I/O in the handler.

### 4.2 Route registration

Register as **public** (no `requireAuth`), mirroring `UserHandler.RegisterRoutes` (`internal/http/user_handler.go:375-389`, where `/api/user.signin`, `/api/user.verify`, `/api/user.rootSignin` are public):

```go
func (h *OIDCHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/user.oidc.start", h.Start)       // GET  -> 302 to IdP
	mux.HandleFunc("/api/user.oidc.callback", h.Callback) // GET  <- IdP redirect
	mux.HandleFunc("/api/user.oidc.exchange", h.Exchange) // POST <- SPA, reads cookie
}
```

Wire in `internal/app/app.go`: construct after `userHandler` (`:1075`) and call `oidcHandler.RegisterRoutes(a.mux)` immediately after `userHandler.RegisterRoutes(a.mux)` (`:1196`). `http.ServeMux` treats these as exact-match patterns. `mux.HandleFunc` does not constrain the verb, so each handler checks `r.Method`: `Start`/`Callback` require `GET` (browser navigation / IdP 302); `Exchange` requires `POST` (matching `RootSignIn`'s guard at `user_handler.go:149-156`). Wrong method on `Exchange` → `WriteJSONError(... http.StatusMethodNotAllowed)` (`internal/http/utils.go:11`); wrong method on `Start`/`Callback` → redirect to the signin error page (§4.4).

### 4.3 Rate limiting (register policies UNCONDITIONALLY)

`RateLimiter.Allow` **fails closed** on an unknown namespace (`pkg/ratelimiter/ratelimiter.go:77-87`). The three policies MUST be registered regardless of whether OIDC is enabled — otherwise enabling OIDC at runtime (settings drawer → graceful restart) would 429 every request until the next deploy. Add to the unconditional block at `internal/app/app.go:476-484`:

```go
a.rateLimiter.SetPolicy("oidc:start", 10, 1*time.Minute)    // start an SSO redirect, by IP
a.rateLimiter.SetPolicy("oidc:callback", 10, 1*time.Minute) // IdP callbacks, by IP
a.rateLimiter.SetPolicy("oidc:exchange", 10, 1*time.Minute) // one-time-code exchange, by IP
```

OIDC is keyed only by **client IP** (no email is known pre-auth). Use the idiom from `public_handler.go:128-134`; `getClientIP(r)` honors `X-Forwarded-For` → `X-Real-IP` → `RemoteAddr` (`public_handler.go:580-598`).

> **IP rate-limit caveat (also-fix).** `getClientIP` trusts `X-Forwarded-For`/`X-Real-IP` **unconditionally** (`public_handler.go:580-598`), so the per-IP limit is **spoofable** unless Notifuse runs behind a **trusted reverse proxy that overwrites XFF**. Therefore the OIDC IP rate limits are only meaningful in that topology and must not be relied on as the brute-force control. The **real** brute-force resistance for the `/exchange` one-time code is its **256-bit entropy + ≤60s TTL + single-use `GetAndDelete`** (`randToken(32)`), not the IP limit. The IP limits remain useful for crude abuse dampening but are documented as best-effort.

For `Start`/`Callback` prefer a redirect to the error page; for `Exchange` (XHR) use `WriteJSONError(StatusTooManyRequests)` + `Retry-After`.

### 4.4 `GET /api/user.oidc.start`

1. `r.Method != GET` → redirect `…/console/signin?oidc_error=auth_failed`.
2. Rate-limit `oidc:start` by client IP → on limit redirect `?oidc_error=rate_limited`.
3. `!h.service.IsEnabled()` → `WriteJSONError(w, "OIDC is not available", http.StatusServiceUnavailable)` (graceful degradation; a correctly-configured SPA only renders the SSO button when `window.OIDC_ENABLED`).
4. `req, err := h.service.BuildAuthURL(r.Context())` (returns `AuthURL` + `FlowState`). Seal the flow-state via the service helper → `flowStateEnc`. On error → redirect `?oidc_error=auth_failed` + warn log (never surface the raw error).
5. Set the flow-state cookie, then `http.Redirect(w, r, req.AuthURL, http.StatusFound)`:

```go
http.SetCookie(w, &http.Cookie{
	Name:     h.flowCookieName(),   // "__Host-oidc_flow" (prod) / "oidc_flow" (dev), §4.6
	Value:    flowStateEnc,         // AES-GCM ciphertext (hex), opaque to the browser
	Path:     "/",                  // __Host- REQUIRES Path=/ and no Domain
	MaxAge:   300,                  // ~5 min: must outlive the IdP round-trip
	Secure:   h.isSecure,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode, // Lax (NOT Strict): survives the top-level IdP -> /callback redirect
})
```

`SameSite=Lax` is mandatory: the callback arrives as a cross-site top-level GET navigation; `Strict` would suppress the cookie. The verifier inside is a secret, hence AEAD encryption (not HMAC-signing alone).

### 4.5 `GET /api/user.oidc.callback`

**Never 500, never echo a raw IdP error, never put a secret in a URL.** Every failure is a 302 to `…/console/signin?oidc_error=<reason>`. Let `base := h.config.APIEndpoint` (trailing-slash-trimmed); the redirect target is `base + "/console/signin"`.

1. `r.Method != GET` → redirect `?oidc_error=auth_failed`.
2. Rate-limit `oidc:callback` by IP → on limit redirect `?oidc_error=rate_limited`.
3. `!h.service.IsEnabled()` → redirect `?oidc_error=auth_failed` (warn-log "callback while OIDC not initialized").
4. Read & **immediately clear** the flow cookie (single-use, regardless of outcome):
   ```go
   http.SetCookie(w, &http.Cookie{Name: h.flowCookieName(), Value: "", Path: "/",
   	MaxAge: -1, Secure: h.isSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
   ```
   Missing/empty cookie → redirect `?oidc_error=auth_failed`.
5. If `q.Get("error") != ""` (e.g. `access_denied`) → redirect `?oidc_error=auth_failed`; log the IdP-supplied `error`/`error_description` server-side only.
6. Build `domain.OIDCCallbackInput{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss"), FlowState: <service.OpenFlowState(cookie)>}` and call `oneTimeCode, err := h.service.HandleCallback(r.Context(), input)`. The service performs (in order): state compare, RFC 9207 `iss` check, PKCE token exchange (`oauth2.VerifierOption`), ID-token validation (RS256/ES256, azp/typ checks, manual nonce equality), and the federated-identity state machine (§3.5).
7. Map the result:
   - **Success** → 302 to `base + "/console/signin#oidc_code=" + url.PathEscape(oneTimeCode)`. The one-time code is placed in the **URL fragment** (`#…`), never the query string — fragments are not transmitted to any server, are absent from access logs, and are stripped from `Referer`. **No code/token/email/sub in the query string and no cookie on the default path.** (See §4.5.2 for the *optional* same-origin cookie hardening.)
   - **`errors.Is(err, domain.ErrOIDCAccountNotProvisioned)`** → 302 `?oidc_error=not_provisioned`.
   - **`errors.Is(err, domain.ErrOIDCIdentityConflict)`** → 302 `?oidc_error=link_conflict`.
   - **`errors.Is(err, domain.ErrOIDCEmailNotVerified)`** → 302 `?oidc_error=email_unverified`.
   - **`errors.Is(err, domain.ErrOIDCNotConfigured)`** → 302 `?oidc_error=provider_unavailable`.
   - **any other error** (exchange/validation/decrypt/internal) → 302 `?oidc_error=auth_failed`; warn/error-log the real cause server-side, never to the client.

The fixed enumerated reasons are exactly: `not_provisioned`, `link_conflict`, `email_unverified`, `provider_unavailable`, `rate_limited`, `auth_failed`. The SPA maps each to a localized LinguiJS message (§5.4).

#### 4.5.1 One-time-code handoff (PRIMARY: URL fragment, no cookie)

The primary handoff sets **no cookie**. The one-time code is appended to the redirect target as a URL **fragment**, and the SPA reads + strips it (§5.4):

```go
// Success path in Callback:
loc := base + "/console/signin#oidc_code=" + url.PathEscape(oneTimeCode)
http.Redirect(w, r, loc, http.StatusFound)
```

The code is only a lookup key; the `AuthResponse` (JWT + user) sits in the server-side store (`pkg/cache` `InMemoryCache`, TTL bound to the shared `oidcExchangeTTL` constant, atomic `GetAndDelete`). Because it rides the fragment, it is never sent to the server on the redirect, never logged, and stripped from `Referer`. The exchange code's brute-force resistance is **256-bit entropy + ≤60s TTL + single-use `GetAndDelete`** (see §4.3 on why the IP rate limit is not the real control here).

#### 4.5.2 OPTIONAL: `__Host-` one-time-code cookie (same-origin-only hardening)

> **Warning:** this variant does **NOT** work when the console and the API are served from **different origins** — the browser will not attach the cookie to a cross-origin `POST /api/user.oidc.exchange`, and the `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` combination is browser-blocked (see `internal/http/middleware/cors.go`). Enable it **only** for same-origin deployments. The default fragment handoff (§4.5.1) is the supported path in all topologies. (Open Question 7.)

When enabled (same-origin only), the success path *additionally* sets an HttpOnly cookie carrying the same one-time code, and `/exchange` reads it from the cookie instead of the body:

```go
http.SetCookie(w, &http.Cookie{
	Name:     h.codeCookieName(),   // "__Host-oidc_code" (prod) / "oidc_code" (dev)
	Value:    oneTimeCode,          // opaque random id; the AuthResponse lives server-side
	Path:     "/",
	MaxAge:   oidcExchangeMaxAge,   // shared TTL constant (== oidcExchangeTTL seconds)
	Secure:   h.isSecure,
	HttpOnly: true,                 // JS cannot read it; only /exchange receives it
	SameSite: http.SameSiteLaxMode, // set during the top-level callback navigation
})
```

The cookie `Max-Age` and the cache TTL are both bound to **one shared constant** (`oidcExchangeTTL` / `oidcExchangeMaxAge`) so they cannot drift. `Path=/` is required by `__Host-`; the cookie is opaque, single-use, TTL-bounded.

### 4.6 `POST /api/user.oidc.exchange`

The SPA, having read `#oidc_code=<code>` from `location.hash` and stripped it via `replaceState`, POSTs the code in the **request body**: `{ "code": "<one-time-code>" }`. The handler trades it for the `AuthResponse` JSON — the response is byte-identical to `VerifyCode` (`user_handler.go:128-141`), so the SPA's `useAuth().signin(token)` path is unchanged. No cookie is involved on the default path, so this works cross-origin under the existing Bearerless CORS posture.

1. `r.Method != POST` → `WriteJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)`.
2. Rate-limit `oidc:exchange` by IP → `WriteJSONError(... http.StatusTooManyRequests)` + `Retry-After`.
3. Read the code from the **request body** (default path): decode `struct { Code string `json:"code"` }`. Missing/empty `code` → `WriteJSONError(w, "No pending sign-in", http.StatusUnauthorized)`. *(Optional §4.5.2 mode: if the `__Host-oidc_code` cookie hardening is enabled and present, read from the cookie and clear it with `MaxAge: -1` instead; the body remains the default.)*
4. `resp, err := h.service.ExchangeCode(r.Context(), code)` — atomic `GetAndDelete` (single-use). On miss/expired/error → `WriteJSONError(w, "Invalid or expired sign-in", http.StatusUnauthorized)`. `ExchangeCode` does NOT re-validate the ID token or re-mint; the JWT was already minted at callback time.
5. Success → `w.WriteHeader(http.StatusOK); json.NewEncoder(w).Encode(resp)` — the same `*domain.AuthResponse` shape (`{token, user, expires_at}`, `internal/domain/user.go:70-74`) as `VerifyCode`. The SPA calls the unchanged `useAuth().signin(resp.token)` (`AuthContext.tsx:61`).

### 4.7 `config.js` exposure (`root_handler.go`) — flags only, NEVER secrets

The SPA needs exactly two globals: `window.OIDC_ENABLED` and `window.OIDC_BUTTON_LABEL`. **No** client_id, issuer URL, secret, or provider detail reaches the browser — `/start` is built entirely server-side.

- **Struct** `RootHandler` (`root_handler.go:20-35`): add `oidcEnabled bool` and `oidcButtonLabel string`.
- **Constructor** `NewRootHandler` (`:38-70`): add two params and assign them (after the SMTP-bridge group).
- **`serveConfigJS`** (`:122-161`): extend the `fmt.Sprintf` template (`:148-159`). Compute `oidcEnabledStr := "false"; if h.oidcEnabled { oidcEnabledStr = "true" }` (idiom from `smtpBridgeEnabledStr` at `:143-146`) and append `window.OIDC_ENABLED = %s;\nwindow.OIDC_BUTTON_LABEL = %q;` with `oidcEnabledStr` and `h.oidcButtonLabel` (`%q` safely escapes the label). If the label is empty, emit the `"Sign in with SSO"` default so the SPA never renders a blank button.
- **Call site** `app.go:1081-1096`: pass `a.config.OIDC.Enabled` and `a.config.OIDC.ButtonLabel`. DB-settings changes trigger the graceful restart (`settings_handler.go:226-318`; setup restart at `app.go:533`), so `RootHandler` is reconstructed with fresh values; `config.js` is already `no-store` (`root_handler.go:124-126`).
- **Window types**: add `OIDC_ENABLED: boolean` and `OIDC_BUTTON_LABEL: string` to `console/src/vite-env.d.ts`.
- **Button-label safety (also-fix):** `window.OIDC_BUTTON_LABEL` is operator-controlled text. In the SPA it MUST be rendered as React **text content** (auto-escaped by React, e.g. `{window.OIDC_BUTTON_LABEL || t\`Sign in with SSO\`}`), and **never** via `dangerouslySetInnerHTML` or any raw-HTML sink — otherwise a crafted label is a stored-XSS vector. The `%q` server-side escaping (above) protects the JS-string literal in `config.js`; React escaping protects the DOM render.

`OIDC_ENABLED` here is the *configuration* flag. The runtime `IsEnabled()` (also requiring lazy provider init, §3.3) can differ transiently if the IdP is unreachable at boot; in that window the button renders but `/start` returns 503 — acceptable and self-healing (the SPA may treat a 503 as a soft "SSO temporarily unavailable").

### 4.8 CSRF posture & login-CSRF analysis

**Why `/exchange` is not a classic CSRF risk.** Notifuse's authenticated API uses `Authorization: Bearer` from `localStorage` (`middleware.RequireAuth` is Bearer-only, `auth.go:37`), **not** an ambient session cookie. The **default** `/exchange` reads the one-time code from the **request body** (not a cookie), so there is no ambient credential to ride: a forged cross-site POST carries no valid code (the fragment-delivered code is never readable cross-origin) and gets a 401. Even in the *optional* §4.5.2 cookie mode, the code cookie is not a session credential — it is short-lived, single-use, opaque, and `SameSite=Lax` blocks it on cross-site POSTs; a forged POST would at most consume the victim's *own* pending code and return *their own* token to *their own* browser. No anti-CSRF token is needed on `/exchange`.

**Login-CSRF surface and coverage — explicit success-path analysis.** The real OIDC CSRF concern is *login-CSRF* (an attacker completes a flow with *their* IdP account, then lures the victim's browser to the attacker's `/callback` link to silently log the victim in as the attacker). This is defeated **before any one-time code is ever issued**, by the flow cookie:
- The success one-time code is minted **only after** `/callback` finds a matching `__Host-` flow cookie **and** a `?state=` that equals the sealed cookie state, **in the same browser** that started the flow.
- An attacker **cannot plant a `__Host-` cookie cross-origin** (the prefix forbids `Domain`, forces `Secure`+`Path=/`, and the cookie is set only by *our* `/start` on *our* origin). So an attacker-completed-flow link opened in a *victim's* browser has **no flow cookie** → `/callback` rejects at the state/cookie check (`?oidc_error=auth_failed`) → **no code, no cookie, and no fragment are ever issued**, and nothing reaches `/exchange`.
- Two binding layers reinforce this: **(1) `state` binding (RFC 6749 §10.12)** — `/start` mints `state`, seals it in the AEAD flow cookie, and `/callback` requires a constant-time-equal `?state=`; the cookie is HttpOnly + AEAD-encrypted + `__Host-` + per-flow, so a matching (state, cookie) pair cannot be forged. **(2) `nonce` binding** — the ID token's `nonce` (sealed in the same cookie, checked in §3.5) ties the token to this browser's flow, defeating token injection/replay.

**Issuer pinning** is the **post-Verify `idToken.Issuer == cfg.IssuerURL` assertion** (unconditional, §3.5) — the primary IdP-mix-up defense; the `?iss=` (RFC 9207) check is only a pre-exchange defense-in-depth short-circuit (relevant for a future multi-IdP-sharing-one-redirect-URI setup). **`SameSite=Lax`** (not Strict) is the deliberate, required choice for the flow cookie — Strict would drop it on the top-level IdP redirect. **`__Host-`** forbids `Domain` scoping and forces `Secure`+`Path=/`, preventing sibling-subdomain or non-TLS injection.

**Dev-mode `__Host-` caveat:** the prefix mandates `Secure`, which browsers honor only over HTTPS. For local HTTP dev (`API_ENDPOINT=http://localhost…`, `isSecure==false`), drop the prefix (`oidc_flow`, and `oidc_code` only if the optional §4.5.2 cookie mode is enabled) and set `Secure:false`, keeping `HttpOnly`, `SameSite=Lax`, `Path=/`. Centralize name selection in `func (h *OIDCHandler) flowCookieName() string` / `codeCookieName() string` returning the `__Host-`-prefixed name only when `h.isSecure`. The **flow-state** cookie is always used; the **code** cookie exists only in the optional same-origin hardening. Production MUST be HTTPS for the hardened posture.

### 4.9 Tests

**`internal/http/oidc_handler_test.go`** (`make test-http`; GoMock for `domain.OIDCServiceInterface`; a real in-memory `RateLimiter`):
- `TestOIDCHandler_Start_RedirectsToIdP`: service returns `(AuthURL, FlowState)` → 302, `Location==AuthURL`, flow cookie set with `HttpOnly`, `Secure` (when isSecure), `SameSite=Lax`, `Max-Age=300`, `Path=/`, `__Host-` prefix.
- `TestOIDCHandler_Start_Disabled_503`: `IsEnabled()==false` → 503 JSON, no cookie.
- `TestOIDCHandler_Start_RateLimited`: exhaust `oidc:start` → redirect `?oidc_error=rate_limited`, `Retry-After`.
- `TestOIDCHandler_Start_WrongMethod`: POST → redirect `?oidc_error=auth_failed`.
- `TestOIDCHandler_Callback_Success`: valid flow cookie + matching state → 302 `Location` is `…/console/signin#oidc_code=<code>` (the code is in the **fragment**, after `#`); the **query string** contains NO `code`/`token`/`email`/`oidc=1`; flow cookie cleared; **no code cookie** set on the default path.
- `TestOIDCHandler_Callback_MissingFlowCookie` (login-CSRF guard, also-fix): valid `?code=`+`?state=` but **NO flow cookie** → `?oidc_error=auth_failed`; assert **no code cookie**, **no `#oidc_code` fragment**, and the service's `HandleCallback` is **not** reached (or reached and rejected at the empty-flow-state check before any code is minted). Proves an attacker-completed-flow link in a victim browser yields nothing.
- `TestOIDCHandler_Callback_IdPError`: `?error=access_denied` → `?oidc_error=auth_failed`; nothing from `error_description` leaks.
- `TestOIDCHandler_Callback_NotProvisioned`: service returns `domain.ErrOIDCAccountNotProvisioned` → `?oidc_error=not_provisioned`.
- `TestOIDCHandler_Callback_LinkConflict`: `domain.ErrOIDCIdentityConflict` → `?oidc_error=link_conflict`.
- `TestOIDCHandler_Callback_EmailUnverified`: `domain.ErrOIDCEmailNotVerified` → `?oidc_error=email_unverified`.
- `TestOIDCHandler_Callback_GenericError_NeverLeaks`: raw sensitive error → `?oidc_error=auth_failed`, raw string absent from body/Location, status 302 (never 500).
- `TestOIDCHandler_Callback_ClearsFlowCookieEvenOnError`: error path still emits the flow-cookie deletion.
- `TestOIDCHandler_Exchange_Success`: POST body `{"code":"<code>"}`; service returns `*domain.AuthResponse` → 200 JSON `{token,user,expires_at}`; shape matches `VerifyCode`; no cookie required.
- `TestOIDCHandler_Exchange_MissingCode`: empty/absent `code` in body → 401.
- `TestOIDCHandler_Exchange_InvalidOrExpiredCode`: service error → 401.
- `TestOIDCHandler_Exchange_WrongMethod`: GET → 405.
- `TestOIDCHandler_Exchange_RateLimited`: exhaust `oidc:exchange` → 429 + `Retry-After`.
- `TestOIDCHandler_DevMode_NonHostCookieNames`: `APIEndpoint=http://localhost` → flow cookie (and code cookie if the optional §4.5.2 mode is on) use non-`__Host-` names and `Secure:false`.

**`internal/http/root_handler_test.go`**:
- `TestServeConfigJS_OIDCEnabled`: `oidcEnabled=true, oidcButtonLabel="Sign in with Google"` → body contains `window.OIDC_ENABLED = true;` and `window.OIDC_BUTTON_LABEL = "Sign in with Google";`, contains NO issuer/client_id/secret tokens.
- `TestServeConfigJS_OIDCDisabled`: `oidcEnabled=false` → `window.OIDC_ENABLED = false;`.

**`internal/app/app.go`**: assert the three `oidc:*` policies are registered unconditionally (unit test on the policy-registration helper, or an integration assertion that `/api/user.oidc.start` does NOT 429 on the first call when OIDC is disabled).

---

## 5. Frontend (SignInPage, callback, router, i18n)

All SPA changes live in `console/`. The cardinal constraint: **`AuthContext.tsx` and the middleware are UNCHANGED**. OIDC reuses the exact magic-code token handoff — the callback effect ends by calling `useAuth().signin(token)` (`console/src/contexts/AuthContext.tsx:61`), which writes `localStorage('auth_token')` (`:65`) and fetches `/api/user.me`. The one-time code arrives in the URL **fragment** (`/console/signin#oidc_code=<code>`); the SPA reads `location.hash`, immediately `history.replaceState`s it away, and POSTs it in the exchange **body** (§5.2/§5.4) — the code never appears in a query string, in logs, or in `Referer`. Failures arrive as a non-secret `?oidc_error=<code>` query flag.

### 5.1 `console/src/vite-env.d.ts` — declare the two new window globals

The `Window` interface is at `vite-env.d.ts:4-13`. Add alongside the existing `SMTP_BRIDGE_*` block:

```ts
declare global {
  interface Window {
    API_ENDPOINT: string
    IS_INSTALLED: boolean
    VERSION: string
    ROOT_EMAIL: string
    SMTP_BRIDGE_ENABLED: boolean
    SMTP_BRIDGE_DOMAIN: string
    SMTP_BRIDGE_PORT: number
    SMTP_BRIDGE_TLS_MODE: 'off' | 'starttls' | 'implicit'
    OIDC_ENABLED: boolean
    OIDC_BUTTON_LABEL: string
  }
}
```

### 5.2 `console/src/services/api/auth.ts` — add `oidcExchange(code)`

**Why the code travels in the BODY, not a cookie.** The shared `request()` helper (`console/src/services/api/client.ts:33-54`) does **NOT** set `credentials` on `fetch`, and when `API_ENDPOINT` is a different origin (the `localapi.notifuse.com` rewrite at `client.ts:41-46`) cross-origin cookies are dropped entirely — and the backend's CORS sends `Access-Control-Allow-Origin: *` (`cors.go`), which browsers **refuse to combine with credentials**. A cookie-based handoff therefore cannot work in split-origin deployments. The default handoff instead passes the one-time code (read from the URL fragment by the SPA, §5.4) in the **request body**, with **no** `credentials`, so it works cross-origin exactly like every other Bearerless POST.

Reuse `VerifyResponse` (`auth.ts:19-21`, `{ token: string }`) and the same `apiEndpoint` resolution as `client.ts:41-46`:

```ts
/**
 * Complete the OIDC Authorization-Code login by exchanging the one-time code for
 * the internal session JWT. The code is read from the URL fragment by the caller
 * (SignInPage) and passed here in the REQUEST BODY — no cookie is used on the
 * default path, so this works across split console/API origins (the shared
 * api.post() can't be used because we need an explicit dedicated fetch and the
 * code is not a typed endpoint param). Returns the JWT, identical in shape to
 * verifyCode().
 */
async function oidcExchange(code: string): Promise<VerifyResponse> {
  let defaultOrigin = window.location.origin
  if (defaultOrigin.includes('notifusedev.com')) {
    defaultOrigin = 'https://localapi.notifuse.com:4000'
  }
  const apiEndpoint = window.API_ENDPOINT?.trim().replace(/\/+$/, '') || defaultOrigin

  const response = await fetch(`${apiEndpoint}/api/user.oidc.exchange`, {
    method: 'POST',
    // NOTE: no `credentials` — the code is in the body, not a cookie, so this
    // succeeds cross-origin under the existing CORS (* origin + Bearerless) posture.
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code })
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => null)
    throw new ApiError(errorData?.error || 'OIDC exchange failed', response.status, errorData)
  }
  return response.json() as Promise<VerifyResponse>
}
```

Add `ApiError` to the import at `auth.ts:1`: `import { api, ApiError } from './client'` (exported at `client.ts:3`). Register on the `authService` object (`auth.ts:64-71`):

```ts
export const authService = {
  signIn: (data: SignInRequest) => api.post<SignInResponse>('/api/user.signin', data),
  verifyCode: (data: VerifyCodeRequest) => api.post<VerifyResponse>('/api/user.verify', data),
  oidcExchange,
  getCurrentUser: () => api.get<GetCurrentUserResponse>('/api/user.me'),
  logout: () => api.post<LogoutResponse>('/api/user.logout', {}),
  updateLanguage: (language: string) =>
    api.post<UpdateLanguageResponse>('/api/user.updateLanguage', { language })
}
```

**Backend CORS note:** because the default handoff sends the code in the body (no cookie), `/api/user.oidc.exchange` needs **no** special CORS treatment — it works under the existing `Access-Control-Allow-Origin: *` posture exactly like every Bearerless POST. (This is precisely why the fragment+body design was chosen over the cookie: the `* origin + Allow-Credentials:true` combination already set by `cors.go` is browser-blocked, so a credentialed cookie POST would fail cross-origin.) The *optional* §4.5.2 cookie hardening is, by contrast, same-origin-only and would require a concrete (non-`*`) origin + `Allow-Credentials`.

### 5.3 `console/src/router.tsx` — extend `SignInSearch` + `validateSearch`

`SignInSearch` is at `router.tsx:40-42`; `validateSearch` at `:79-81`. Only the **error** flag is a query param (`?oidc_error=<code>`, a non-secret enum); the **success** one-time code arrives in the URL **fragment** (`#oidc_code=…`), which TanStack Router's `validateSearch` does **not** see (fragments are not search params) — the SPA reads it from `location.hash` directly (§5.4). So `validateSearch` only needs `oidc_error`:

```ts
export interface SignInSearch {
  email?: string
  oidc_error?: string
}
```

```ts
const signinRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/console/signin',
  component: SignInPage,
  validateSearch: (search: Record<string, unknown>): SignInSearch => ({
    email: search.email as string | undefined,
    oidc_error: typeof search.oidc_error === 'string' ? search.oidc_error : undefined
  })
})
```

No new route — the backend `/callback` 302s to the existing `/console/signin#oidc_code=<code>` (success) or `/console/signin?oidc_error=<code>` (failure), reusing `signinRoute`. The `from: '/console/signin'` in `useSearch` at `SignInPage.tsx:14` surfaces `oidc_error`; the success code is read from `window.location.hash`.

### 5.4 `console/src/pages/SignInPage.tsx` — SSO button + callback effect

The component already imports `App`, `Button`, `Space` from antd (`:1`), `useSearch`/`useNavigate` (`:3`), `useEffect`/`useRef`/`useCallback` (`:4`), `authService` (`:5`), `useLingui` (`:8`). Add `Divider`:

```ts
import { Form, Input, Button, Card, App, Space, Divider } from 'antd'
```

**(a) Ref + `handleOidcExchange`.** Add a guard ref next to `hasAutoSubmitted` (`:21`):

```ts
const hasExchangedOidc = useRef(false)
```

Define the callback (after `handleCodeSubmit`, before the existing `useEffect` at `:83`); it takes the one-time `code` read from the fragment, and ends with the **UNCHANGED** `signin(token)` + the same 100ms-delayed navigate used by `handleCodeSubmit` (`:36-42`):

```ts
const handleOidcExchange = useCallback(
  async (code: string) => {
    try {
      setLoading(true)
      const { token } = await authService.oidcExchange(code) // code from URL fragment
      await signin(token) // UNCHANGED AuthContext path -> localStorage('auth_token')
      message.success(t`Successfully signed in`)
      setTimeout(() => {
        navigate({ to: '/console' })
      }, 100)
    } catch {
      message.error(t`Single sign-on failed. Please try again or use a magic code.`)
    } finally {
      setLoading(false)
    }
  },
  [signin, message, navigate, t]
)
```

**(b) Mount `useEffect`** that reads the one-time code from `window.location.hash`, **immediately** strips it via `history.replaceState` (BEFORE any await), then exchanges it. The error flag is still a query param (`search.oidc_error`). Add directly after the email-auto-submit effect (`:83-104`):

```ts
// OIDC callback handoff: backend /callback 302s to
//   /console/signin#oidc_code=<code>   (success)  or
//   /console/signin?oidc_error=<code>  (failure).
// The success code rides the URL FRAGMENT (never the query string, never logged,
// stripped from Referer). We read it, IMMEDIATELY replaceState it away so a
// refresh/back cannot replay it, then POST it in the exchange body.
useEffect(() => {
  if (hasExchangedOidc.current) return

  if (search.oidc_error) {
    hasExchangedOidc.current = true
    message.error(mapOidcError(search.oidc_error, t))
    navigate({ to: '/console/signin', search: {}, replace: true })
    return
  }

  const hash = window.location.hash // e.g. "#oidc_code=AbC123..."
  const m = /[#&]oidc_code=([^&]+)/.exec(hash)
  if (m) {
    hasExchangedOidc.current = true
    const code = decodeURIComponent(m[1])
    // Strip the fragment BEFORE the network round-trip (single-use + replaceState).
    window.history.replaceState(null, '', window.location.pathname + window.location.search)
    void handleOidcExchange(code)
  }
}, [search.oidc_error, navigate, message, t, handleOidcExchange])
```

`mapOidcError` (module scope, top of file) translates backend error codes to Lingui strings. The union is kept in sync with the codes the backend emits (§4.5): `not_provisioned`, `link_conflict`, `email_unverified`, `provider_unavailable`, `rate_limited`, `auth_failed`:

```ts
function mapOidcError(code: string, t: (s: TemplateStringsArray) => string): string {
  switch (code) {
    case 'not_provisioned':
      return t`No Notifuse account is linked to that identity. Ask an administrator to invite you first.`
    case 'email_unverified':
      return t`Your identity provider has not verified your email address.`
    case 'link_conflict':
      return t`This account is already linked to a different single sign-on identity.`
    case 'provider_unavailable':
      return t`Single sign-on is temporarily unavailable. Please try a magic code.`
    case 'rate_limited':
      return t`Too many sign-in attempts. Please wait a moment and try again.`
    default:
      return t`Single sign-on failed. Please try again or use a magic code.`
  }
}
```

(The `t` param typing is the simplest that satisfies the `t\`...\`` tagged-template call; type it to the project's richer `MessageDescriptor`-returning signature if available — the tag-call form is what `lingui:extract` needs.)

**(c) SSO button + divider JSX**, gated on `window.OIDC_ENABLED`, rendered in the email-form branch (`:133-157`, the `!showCodeInput` case) below the "Send Magic Code" `Form.Item` (`:152-156`). It is a default (NOT `type="primary"`) button whose label comes from `window.OIDC_BUTTON_LABEL`, and whose `onClick` does a **full-page** navigation to the backend start endpoint:

```tsx
              <Form.Item>
                <Button type="primary" htmlType="submit" block loading={loading}>
                  {t`Send Magic Code`}
                </Button>
              </Form.Item>

              {window.OIDC_ENABLED && (
                <>
                  <Divider plain>{t`or`}</Divider>
                  <Button
                    block
                    onClick={() => {
                      const base =
                        window.API_ENDPOINT?.trim().replace(/\/+$/, '') || window.location.origin
                      window.location.assign(`${base}/api/user.oidc.start`)
                    }}
                  >
                    {window.OIDC_BUTTON_LABEL || t`Sign in with SSO`}
                  </Button>
                </>
              )}
```

Notes: `window.location.assign(...)` (not `navigate`) is required — `/api/user.oidc.start` sets the AEAD flow-state cookie and 302s to the IdP, so it must be a real browser navigation. The button is hidden entirely when `OIDC_ENABLED` is false (magic-code-only deployments are visually unchanged). `loading` is intentionally not applied to the SSO button (it navigates away), but the shared `loading` state covers the post-callback exchange. **`window.OIDC_BUTTON_LABEL` is rendered as React text content** (`{window.OIDC_BUTTON_LABEL || t\`Sign in with SSO\`}`), which React auto-escapes — it MUST **never** be passed to `dangerouslySetInnerHTML` (operator-controlled label = XSS sink otherwise; see §4.7).

**UI mockup this produces:**

```
┌──────────── Sign In ────────────┐
│ Email                           │
│ [ you@example.com            ]  │
│ [   Send Magic Code  (primary)] │
│ ───────────── or ────────────── │
│ [   Sign in with SSO (outline)] │
└─────────────────────────────────┘
```

### 5.5 i18n (LinguiJS)

All new literals use the `t\`...\`` macro from `useLingui()` (destructured at `SignInPage.tsx:11`). New strings: `` t`or` ``, `` t`Sign in with SSO` ``, `` t`Successfully signed in` `` (dedup'd by Lingui), plus the `mapOidcError` strings. After implementation, from `console/`:

```bash
npm run lingui:extract   # adds msgids to all locales/*.po (en + ca/de/es/fr/it/ja/pt-BR)
# fill in en.po; others fall back to msgid until translated
npm run lingui:compile   # before building
```

Locale files: `console/src/i18n/locales/` (`en.po`, `fr.po`, `de.po`, `es.po`, `it.po`, `ja.po`, `pt-BR.po`, `ca.po` + compiled `.js`).

### 5.6 Tests (Vitest + RTL; `cd console && npm test`)

Mock structure follows `console/src/__tests__/SignInPage.test.tsx` (router/`useSearch` mock at lines 23-30, `authService` mock at 9-17, antd `App.useApp`/`message` spy at 33-58, `renderWithProviders` at 42-48).

**`console/src/services/api/auth.test.ts`** — add `describe('oidcExchange')`, stubbing `global.fetch`:
- `posts the code in the body to /api/user.oidc.exchange` — call `oidcExchange('AbC123')`; assert URL ends `/api/user.oidc.exchange`, `method: 'POST'`, request `body` is `JSON.stringify({ code: 'AbC123' })`, and **no** `credentials` key is set (the load-bearing cross-origin guard — a cookie/credentials handoff must NOT regress in).
- `returns { token } on 200` — `{ ok: true, json: () => ({ token: 'jwt-x' }) }` → resolves `{ token: 'jwt-x' }`.
- `throws ApiError on non-ok` — `{ ok: false, status: 401, json: () => ({ error: 'not_provisioned' }) }` → rejects with `status === 401`.
- `resolves API base from window.API_ENDPOINT with trailing slash stripped`.

**`console/src/__tests__/SignInPage.test.tsx`** — add `oidcExchange: vi.fn()` to the `authService` mock; widen `mockSearch` to `{ email?: string; oidc_error?: string }` and reset in `beforeEach`; stub `window.location.hash` / `window.history.replaceState` per-test:
- `renders SSO button + "or" divider when window.OIDC_ENABLED` (set true, reset false in `afterEach`).
- `hides SSO button when OIDC disabled`.
- `uses OIDC_BUTTON_LABEL when set, falls back otherwise` (assert rendered as escaped text, not raw HTML).
- `SSO button click navigates to API start endpoint` — spy `window.location.assign`; assert called with `https://api.example.com/api/user.oidc.start`.
- `on #oidc_code=<code> calls oidcExchange(code), signs in, navigates` — set `window.location.hash = '#oidc_code=jwt-code'`; mock `oidcExchange`→`{ token: 'jwt-x' }`; assert `oidcExchange('jwt-code')` once then `mockNavigate({ to: '/console' })` (handle the 100ms `setTimeout` via `waitFor`/fake timers as in the magic-code test at lines 124-129).
- `strips #oidc_code from the URL before exchange` — spy `window.history.replaceState`; assert it is called (removing the fragment) **before** the `oidcExchange` promise resolves.
- `runs the exchange exactly once (guard ref)` — even if the effect re-fires.
- `on ?oidc_error shows mapped message and does not call oidcExchange` — and `mockNavigate({ to: '/console/signin', search: {}, replace: true })`.
- `on oidcExchange rejection shows error toast` and no navigation to `/console`.

### 5.7 Files touched (frontend)

| File | Change |
|---|---|
| `console/src/vite-env.d.ts:4-13` | add `OIDC_ENABLED`, `OIDC_BUTTON_LABEL` |
| `console/src/services/api/auth.ts:1,19-21,64-71` | import `ApiError`; add `oidcExchange(code)` (dedicated `fetch`, code in **body**, **no** `credentials`); register on `authService` |
| `console/src/router.tsx:40-42,79-81` | extend `SignInSearch` (`oidc_error` only) + `validateSearch` |
| `console/src/pages/SignInPage.tsx:1,21,83,133-157` | `Divider` import; `hasExchangedOidc` ref; `handleOidcExchange(code)`; OIDC callback `useEffect` (read `location.hash` + `history.replaceState` + body exchange); `mapOidcError`; SSO `Button`+`Divider` JSX |
| `console/src/i18n/locales/*.po` | `lingui:extract` then `lingui:compile` |
| `console/src/services/api/auth.test.ts`, `console/src/__tests__/SignInPage.test.tsx` | new tests (§5.6) |

**Unchanged (verify):** `console/src/contexts/AuthContext.tsx` (`signin(token)` at `:61-76` reused verbatim), `console/src/services/api/client.ts` (the OIDC exchange deliberately bypasses it), and all auth middleware.

---

## 6. Data Model & Migration, Test Plan, Ops & Rollout

### 6.A Data Model & Migration

#### 6.A.1 Where the schema lives (system DB)

`users`, `user_sessions`, `workspaces`, `user_workspaces`, `workspace_invitations`, `settings` are all **system-DB** tables. Fresh-install DDL is `internal/database/schema/system_tables.go:7-89` (`TableDefinitions`); the table list is `TableNames` (`system_tables.go:129-138`); post-create idempotent alterations go in `MigrationStatements` (`system_tables.go:93-121`). `federated_identities` is a new system-DB table, so add it in **both** places: (1) `TableDefinitions` for fresh installs, and (2) the v34 migration `UpdateSystem` for existing installs — mirroring how `users.language` was added to the `users` DDL (`system_tables.go:13`) **and** in `v32.go:37-43`. House style at `system_tables.go:6`: "Don't put REFERENCES … in the CREATE TABLE statements" — declare the FK column without inline `REFERENCES` and add the constraint separately (§6.A.3).

#### 6.A.2 `federated_identities` table

```sql
CREATE TABLE IF NOT EXISTS federated_identities (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL,
    idp_issuer  VARCHAR(255) NOT NULL,   -- ID-token `iss`, e.g. https://accounts.google.com
    idp_sub     VARCHAR(255) NOT NULL,   -- ID-token `sub` (stable subject id)
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (idp_issuer, idp_sub),        -- durable identity key: one user per (issuer, sub)
    UNIQUE (user_id, idp_issuer)         -- Fix 3: at most one identity per (user, issuer)
)
```

- **PK** `id UUID` (consistent with `users.id`, `user_sessions.id`, `workspace_invitations.id`, all `UUID PRIMARY KEY` — `system_tables.go:9,18,43`). Generate with `uuid.New().String()` in the repo, as `userRepository.CreateUser` does (`user_postgres.go:28`).

  > Note: §1.3 sketched `user_id VARCHAR(32)`; the final, codebase-consistent type is `UUID` (matching `users.id`). The Go `FederatedIdentity.UserID` field is a `string` either way.
- **`UNIQUE (idp_issuer, idp_sub)`** is the durable identity key (a UNIQUE constraint creates the btree index — no separate `(idp_issuer, idp_sub)` index needed).
- **`UNIQUE (user_id, idp_issuer)` (Fix 3)** caps each user at one identity per issuer, makes `GetByUserAndIssuer` deterministic (0-or-1), makes the 2b-ii link-conflict check deterministic, and blocks silent `sub` accumulation. A LINK `INSERT` racing into a `23505` on **either** unique constraint is refused (`?oidc_error=link_conflict`), never swallowed (§3.5 `linkIdentity`).
- Add one extra index for the user fan-out (account deletion, `ListByUserID`, FK scan):

```sql
CREATE INDEX IF NOT EXISTS idx_federated_identities_user_id ON federated_identities (user_id)
```

- **Functional index for case-insensitive email lookup (Fix 2).** The OIDC bridge matches the invited/JIT user via `lower(email)=lower($1)` (`GetUserByEmailInsensitive`, §6.A.6). Back that with a functional index on `users(lower(email))` so the bridge lookup stays index-served (the existing exact-match `GetUserByEmail` is unchanged):

```sql
CREATE INDEX IF NOT EXISTS idx_users_lower_email ON users (lower(email))
```

#### 6.A.3 FK decision — reconcile `ON DELETE CASCADE` with the no-inline-`REFERENCES` house style

Add the FK as a **named, separately-created constraint** (idempotent via the `pg_constraint` guard already used at `system_tables.go:94-108`), keeping `CREATE TABLE` REFERENCES-free **and** giving the requested cascade:

```sql
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'federated_identities_user_id_fkey'
        AND conrelid = 'federated_identities'::regclass
    ) THEN
        ALTER TABLE federated_identities
            ADD CONSTRAINT federated_identities_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;
```

Place this block in both `system_tables.go:MigrationStatements` and v34 `UpdateSystem` (after the `CREATE TABLE`).

> Decision note: if the team prefers strictly FK-free system tables (like every other one) and app-level cleanup (`idx_federated_identities_user_id` + an explicit `DELETE FROM federated_identities WHERE user_id=$1` in the user-deletion path), that is acceptable and more consistent with the rest of the schema. The brief explicitly requested CASCADE, so the plan defaults to the DB-level FK; flag this in review.

#### 6.A.4 Migration `internal/migrations/v34.go`

Model on `v32.go` (system-only). Bump `config/config.go:18` `VERSION = "33.1"` → `"34.0"`.

```go
package migrations

import (
	"context"
	"fmt"

	"github.com/Notifuse/notifuse/config"
	"github.com/Notifuse/notifuse/internal/domain"
)

// V34Migration adds OIDC / SSO support: a new federated_identities system table
// keyed by the durable (idp_issuer, idp_sub) pair linking an external IdP
// subject to a Notifuse user (email is NOT used for authentication once a link
// exists). SQL is kept identical to system_tables.go to avoid new/migrated drift.
type V34Migration struct{}

func (m *V34Migration) GetMajorVersion() float64 { return 34.0 }
func (m *V34Migration) HasSystemUpdate() bool     { return true }
func (m *V34Migration) HasWorkspaceUpdate() bool  { return false }
func (m *V34Migration) ShouldRestartServer() bool { return false }

func (m *V34Migration) UpdateSystem(ctx context.Context, cfg *config.Config, db DBExecutor) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS federated_identities (
			id          UUID PRIMARY KEY,
			user_id     UUID NOT NULL,
			idp_issuer  VARCHAR(255) NOT NULL,
			idp_sub     VARCHAR(255) NOT NULL,
			created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (idp_issuer, idp_sub),
			UNIQUE (user_id, idp_issuer)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_federated_identities_user_id ON federated_identities (user_id)`,
		// Fix 2: functional index backing GetUserByEmailInsensitive (case-insensitive OIDC bridge).
		`CREATE INDEX IF NOT EXISTS idx_users_lower_email ON users (lower(email))`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conname = 'federated_identities_user_id_fkey'
				AND conrelid = 'federated_identities'::regclass
			) THEN
				ALTER TABLE federated_identities
					ADD CONSTRAINT federated_identities_user_id_fkey
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
			END IF;
		END $$`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("v34 system migration failed: %w", err)
		}
	}
	return nil
}

func (m *V34Migration) UpdateWorkspace(ctx context.Context, cfg *config.Config, workspace *domain.Workspace, db DBExecutor) error {
	return nil
}

func init() { Register(&V34Migration{}) }
```

`init()` self-registers via `Register` (`registry.go:53`); the manager runs migrations in ascending order. `V34Migration` satisfies the full `MajorMigrationInterface` (`internal/migrations/interfaces.go:19`): `GetMajorVersion`/`HasSystemUpdate`/`HasWorkspaceUpdate`/`ShouldRestartServer`/`UpdateSystem`/`UpdateWorkspace` (all six implemented above). `ShouldRestartServer()=false` is correct — the schema change is additive; the OIDC config restart is driven by the settings/setup handlers (§2), not the migration. Also add the same statements to `system_tables.go` (the `CREATE TABLE` with **both** UNIQUE constraints + the `idx_federated_identities_user_id` index → `TableDefinitions`; the `idx_users_lower_email` functional index and the `DO $$` FK → `MigrationStatements`; `"federated_identities"` → `TableNames`).

#### 6.A.5 Domain entity + repository interface — `internal/domain/federated_identity.go` (new file)

```go
package domain

import (
	"context"
	"time"
)

//go:generate mockgen -destination mocks/mock_federated_identity_repository.go -package mocks github.com/Notifuse/notifuse/internal/domain FederatedIdentityRepository

type FederatedIdentity struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	IDPIssuer string    `json:"idp_issuer" db:"idp_issuer"`
	IDPSub    string    `json:"idp_sub" db:"idp_sub"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ErrFederatedIdentityNotFound — no row for the given lookup.
type ErrFederatedIdentityNotFound struct{ Message string }

func (e *ErrFederatedIdentityNotFound) Error() string { return e.Message }

// ErrFederatedIdentityExists — duplicate on EITHER UNIQUE(idp_issuer, idp_sub)
// OR UNIQUE(user_id, idp_issuer) (PG 23505). The service distinguishes a benign
// exact-duplicate race from a genuine link conflict (§3.5 linkIdentity).
type ErrFederatedIdentityExists struct{ Message string }

func (e *ErrFederatedIdentityExists) Error() string { return e.Message }

type FederatedIdentityRepository interface {
	// GetByIssuerSubject returns the identity for (issuer, sub) or
	// ErrFederatedIdentityNotFound. Served by UNIQUE(idp_issuer, idp_sub).
	GetByIssuerSubject(ctx context.Context, issuer, sub string) (*FederatedIdentity, error)
	// GetByUserAndIssuer returns the link for (user_id, issuer) or
	// ErrFederatedIdentityNotFound. Used to detect the link-conflict case (§3.5).
	GetByUserAndIssuer(ctx context.Context, userID, issuer string) (*FederatedIdentity, error)
	// Create inserts a new link; ErrFederatedIdentityExists on UNIQUE violation.
	Create(ctx context.Context, fi *FederatedIdentity) error
	// ListByUserID returns all federated identities for a user (audit / account view).
	ListByUserID(ctx context.Context, userID string) ([]*FederatedIdentity, error)
}
```

Mirrors `UserRepository` placement and the `//go:generate mockgen` convention (`user.go:8`); the not-found sentinel mirrors `ErrUserNotFound` (`user_postgres.go:83`); the duplicate detection reuses the PG-23505 string match in `CreateUser` (`user_postgres.go:57-58`).

#### 6.A.6 Postgres impl + mock — `internal/repository/federated_identity_postgres.go` (new file)

`type federatedIdentityRepository struct { systemDB *sql.DB }` + `func NewFederatedIdentityRepository(db *sql.DB) domain.FederatedIdentityRepository`, copying `userRepository` (`user_postgres.go:17-24`). Use `tracing.StartServiceSpan` as `GetUserByID` does (`user_postgres.go:92`). `Create` auto-fills `id` with `uuid.New().String()` when empty (`user_postgres.go:28`).

- `GetByIssuerSubject`: `SELECT id, user_id, idp_issuer, idp_sub, created_at FROM federated_identities WHERE idp_issuer=$1 AND idp_sub=$2` → `sql.ErrNoRows` → `&domain.ErrFederatedIdentityNotFound{...}`. Served by `UNIQUE(idp_issuer, idp_sub)`.
- `GetByUserAndIssuer`: same shape, `WHERE user_id=$1 AND idp_issuer=$2` → returns 0-or-1 deterministically thanks to `UNIQUE(user_id, idp_issuer)`.
- `Create`: `INSERT INTO federated_identities (id, user_id, idp_issuer, idp_sub, created_at) VALUES ($1,$2,$3,$4,$5)` with PG-23505 on **either** unique constraint → `&domain.ErrFederatedIdentityExists{...}` (the service's `linkIdentity` then re-reads to decide idempotent-success vs `ErrOIDCIdentityConflict`, §3.5).
- `ListByUserID`: `SELECT ... WHERE user_id=$1 ORDER BY created_at` (uses `idx_federated_identities_user_id`).

**`GetUserByEmailInsensitive` on `UserRepository` (Fix 2) — `internal/repository/user_postgres.go`.** Add a NEW method (do NOT modify the existing exact-match `GetUserByEmail` at `:66`): `SELECT id, email, name, type, language, created_at, updated_at FROM users WHERE lower(email)=lower($1)` → `sql.ErrNoRows` → `&domain.ErrUserNotFound{...}`. Add it to the `domain.UserRepository` interface (`internal/domain/user.go`) and regenerate `mock_user_repository.go`. Backed by the `idx_users_lower_email` functional index (§6.A.2). Repo test (in `user_postgres_test.go`): a user stored `Jane@Corp.com` is returned for input `jane@corp.com`; no row → `*ErrUserNotFound`.

Mock: `internal/domain/mocks/mock_federated_identity_repository.go` via `go generate ./internal/domain/...`; regenerate `mock_user_repository.go` for the new method. Wire into DI in `internal/app/app.go` next to `userRepository` construction (~`app.go:409`) and pass `NewFederatedIdentityRepository(...)`, plus `config.IsRootEmail` as the `IsRootEmail` guard, into `NewOIDCService`.

### 6.B Test Plan (per layer)

Go commands per `Makefile`: `make test-domain`, `test-service`, `test-http`, `test-repo`, `test-migrations`, `test-pkg`, `test-unit`, `test-integration`. Frontend: `cd console && npm test`. GoMock + go-sqlmock throughout.

**6.B.1 Migration — `internal/migrations/v34_test.go`** (copy `v32_test.go:15-60`): `GetMajorVersion`→`34.0`; `HasSystemUpdate`→true, `HasWorkspaceUpdate`→false, `ShouldRestartServer`→false; `UpdateSystem_Success` (sqlmock `ExpectExec` for the `CREATE TABLE` with **both** UNIQUE constraints, `idx_federated_identities_user_id`, the `idx_users_lower_email` functional index, and the `DO $$` FK block — in order); `UpdateSystem_Error` (first exec errors → message contains `"v34 system migration failed"`); `UpdateWorkspace_NoOp`.

**6.B.2 Config — `config/config_test.go` + `config/oidc_test.go`** (see §2.6): env-wins, DB-fallback, disabled, JIT-requires-allowlist fail-fast, allowed-domains parse, issuer trailing-slash normalization, `Validate` table, `ParseScopes`.

**6.B.3 pkg/cache — `pkg/cache/cache_test.go`** (see §3.9): `GetAndDelete` Found/Miss/Expired/Concurrent (`-race`, exactly-one-winner).

**6.B.4 Domain — `internal/domain/federated_identity_test.go` + `oidc_test.go`**: `ErrFederatedIdentityNotFound/Exists.Error()` return `Message`; `audience.UnmarshalJSON` string/array/invalid.

**6.B.5 Repository — `internal/repository/federated_identity_postgres_test.go`** (sqlmock, pattern from `user_postgres_test.go`): `GetByIssuerSubject` Found/NotFound; `GetByUserAndIssuer` Found/NotFound; `Create` Success / DuplicateConflict on the `(idp_issuer, idp_sub)` 23505 / DuplicateConflict on the `(user_id, idp_issuer)` 23505 (both → `*ErrFederatedIdentityExists`); `ListByUserID` multi-row/empty. Plus, in `user_postgres_test.go`: `GetUserByEmailInsensitive` returns a mixed-case-stored user for a lowercased input; NotFound → `*ErrUserNotFound` (Fix 2).

**6.B.6 Service — `internal/service/oidc_service_test.go`** (the core, §3.9): build a fake-IdP `httptest.Server` exposing `/.well-known/openid-configuration` (issuer == httptest base URL), `/jwks` (RSA public JWKS; test holds the private key), and `/token` (returns `id_token`+`access_token`, verifies the PKCE `code_verifier` against the prior `S256` challenge). A `mintIDToken(claims)` helper signs RS256 with `typ:"JWT"`. Cases enumerated in §3.9 (happy-path federated-found; first-login link via case-insensitive email match; mixed-case-invited bridged with no duplicate create; link-conflict refused + audit on both unique-constraint paths; email-verified-false refused; nonce/state/`?iss=`-pre-check mismatch; **post-Verify `idToken.Issuer` mismatch refused**; `at+jwt` and `application/at+jwt` rejected; azp required only on a genuine distinct second audience; non-asymmetric alg rejected; JIT allowlisted/denied; **ROOT_EMAIL JIT refused**; invited-only refused; exchange single-use; **lazy-init 503 then self-heal after retry window**).

**6.B.7 HTTP — `internal/http/oidc_handler_test.go`** (§4.9): start sets encrypted `__Host-` flow cookie + 302 to IdP; callback success 302s to `…/console/signin#oidc_code=<code>` (code in the **fragment**, no code cookie on the default path, no `code` in the query string); **callback with valid `?code`+`?state` but NO flow cookie → `?oidc_error=auth_failed`, no fragment, no cookie, no code issued** (login-CSRF guard); state mismatch → error redirect; exchange reads the code from the **POST body** → JWT (passes `RequireAuth` unchanged); replay fails; rate-limited → 429; disabled → 503; dev-mode non-`__Host-` names. Plus `root_handler_test.go` config.js assertions (no secret in body; label is `%q`-escaped).

**6.B.8 Integration — `tests/integration/oidc_test.go`** (`make test-integration`): start `docker compose -f tests/compose.test.yaml up -d` (Postgres:5433 + Mailpit); **add new member emails to `tests/testutil/database.go`** (seed list ~`database.go:164-183`) or signin returns 400. Use an `httptest.Server` fake IdP. Drive **start → callback → exchange**:
- `TestOIDC_Integration_EndToEnd_ExistingMember`: seed a federated identity for a seeded member → drive start → callback (read the `#oidc_code` fragment from the redirect `Location`) → exchange that code in the POST body → JWT → `POST /api/user.me` (`user_handler.go:200`) returns that user.
- `TestOIDC_Integration_CaseInsensitiveBridge` (Fix 2): seed an **invited** member with a mixed-case email (e.g. `Jane@Example.com`) and **no** federated identity → first SSO login with a lowercased IdP email (`jane@example.com`, verified) → bridges to the SAME user (no duplicate created) → subsequent login keys off `(issuer, sub)`.
- `TestOIDC_Integration_WorkspaceStill403WithoutMembership`: JIT-create a brand-new SSO user (allowlisted `@example.com`) with **no** `user_workspaces` row → `/api/user.me` 200, but any workspace-scoped endpoint returns **403** (`AuthenticateUserForWorkspace`, `auth_service.go:122`; login ≠ access).
- `TestOIDC_Integration_ExchangeSingleUse`: replay the exchange code → second call fails.
- Run ONLY these `Test*` funcs (integration suite is ~9 min).

**6.B.9 Frontend — `console`** (§5.6): SignInPage SSO button render/gating + `#oidc_code` fragment flow (read `location.hash` + `replaceState` strip) + `oidcExchange(code)` posting the code in the **body** with **no** `credentials` + Setup/Settings OIDC fields (locked when env-overridden) + i18n extract/compile.

### 6.C Security Checklist (controls A–F)

1. **(A)** Durable identity key = `(issuer, sub)`, never email. `UNIQUE(idp_issuer, idp_sub)` enforced; auth lookup is `GetByIssuerSubject` first. Email only bridges a first login to a pre-existing (invited) account, and only when `email_verified==true`.
2. **(A)** Identity state machine: FOUND→mint; NOT FOUND + verified email: existing user w/o this-issuer link → LINK; existing user w/ a *different* sub for this issuer → **REFUSE + audit**; no user → provisioning policy. Stable `sub` logged on every login.
3. **(A)** Residual email-recycling risk for an *invited-but-never-logged-in* user documented; optional future strict mode noted (§6.D.7).
4. **(B)** **Primary issuer control = UNCONDITIONAL post-Verify `idToken.Issuer == cfg.IssuerURL` assertion** (§3.5). The `?iss=` query-param check (RFC 9207) is only a **defense-in-depth pre-exchange short-circuit** (relevant for a future multi-IdP-sharing-one-redirect-URI setup), **not** the main defense. go-oidc also pins the discovered issuer internally; we re-assert explicitly.
5. **(C)** Asymmetric algs only — `SupportedSigningAlgs = ["RS256","ES256"]`; HS256/none rejected (no confusion with the internal HS256 session JWT).
6. **(C)** `azp == client_id` enforced exactly when the ID token has a **genuine second distinct audience** (duplicates of our own ClientID and single-aud never require azp; see `hasDistinctSecondAudience`).
7. **(C)** `typ: at+jwt` **and** `application/at+jwt` rejected, case-insensitively (RFC 9068 access-token-as-ID-token confusion).
8. **(C)** All `oidc.Config` `Skip*`/`Insecure*` left **false**.
9. **(C)** Manual `nonce` equality (go-oidc `Verify` does not check it).
10. **(C)** `email_verified==true` enforced before any provisioning **or** link.
11. **(D)** Flow-state cookie AEAD-encrypted (`crypto.EncryptString(…, SecretKey)`, AES-GCM, `crypto.go:86`) — `state`+`nonce`+**PKCE verifier**; `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` (not Strict), `Path=/`, `Max-Age≈300`, cleared on callback.
12. **(Decision 4)** One-time code never in a URL **query string** — it rides the URL **fragment** (`/console/signin#oidc_code=<code>`, not sent to the server, not logged, stripped from `Referer`); the SPA reads `location.hash`, **immediately `history.replaceState`s** it away, then POSTs `{ code }` in the **body** to `/api/user.oidc.exchange` (works in all topologies, including split origins). The optional `__Host-` HttpOnly code cookie (§4.5.2) is same-origin-only hardening. **Residual:** the code is briefly in browser history — mitigated by single-use + ≤60s TTL + immediate `replaceState`; documented honestly (§1.2).
13. **(3 / cache)** One-time code single-use via atomic `cache.GetAndDelete`; concurrent-redemption test proves exactly-one success. The cache TTL and the optional cookie Max-Age derive from a **single shared constant** (`oidcExchangeTTL`).
14. **(E)** JWKS auto-rotation — Provider/Verifier built lazily with `context.Background()` and `oidc.NewRemoteKeySet` (self-refreshing); never a frozen snapshot.
15. **(E / Fix 5)** Graceful degradation **with self-healing** — issuer unreachable at boot ⇒ server boots, magic-code works, OIDC routes 503; init is guarded by a `sync.Mutex` + `lastAttempt` retry window (~30s), **not** a plain `sync.Once`, so the first reachable request after the issuer recovers **succeeds without a restart**. Loud warning log on each failed attempt.
16. **(F)** Rate limits registered **unconditionally** in `app.go` for `oidc:start`/`oidc:callback`/`oidc:exchange` (`Allow` fails closed on unknown namespace, `ratelimiter.go:77/83`). **Caveat:** `getClientIP` trusts `X-Forwarded-For` unconditionally (`public_handler.go:580`), so the per-IP limit is **spoofable** and meaningful only behind a trusted reverse proxy that overwrites XFF. The real brute-force resistance for the exchange code is **256-bit entropy + ≤60s TTL + single-use `GetAndDelete`**, not the IP limit.
17. `client_secret` encrypted at rest like the SMTP password (`EncryptString`/`DecryptFromHexString`, `setting_service.go:235-242`); env-set value rendered locked in UI (`GetEnvOverrides`).
18. PKCE everywhere — `GenerateVerifier` + `S256ChallengeOption` on authorize, `VerifierOption` on exchange.
19. JWT systems never mix — external IdP tokens RS256/ES256 (go-oidc); internal session HS256 `golang-jwt/jwt/v5` (`GenerateUserAuthToken`, `auth_service.go:220`); the HS256 alg-confusion pin in `RequireAuth` (`auth.go:37`) is preserved.
20. Login ≠ authorization — a JIT/invited SSO user with no `user_workspaces` row gets zero workspace access (`AuthenticateUserForWorkspace`, `auth_service.go:122`; `CreateUser` touches only `users`, `user_postgres.go:42`). Verified by integration test 6.B.8.
21. Redirect URI fixed & exact — single registered `OIDC_REDIRECT_URI`; open-redirect avoided by 302-ing only to the fixed internal `/console/signin` (with the code in the fragment, or `?oidc_error=<enum>` on failure). The fragment/error are appended to a constant internal base, never an attacker-controlled URL.
22. **(A / Fix 6)** ROOT_EMAIL JIT guard — JIT auto-create **refuses** when the verified email matches a configured `ROOT_EMAIL` (`config.IsRootEmail`), forcing the invite path, because a root-matching email is synthesized owner of **all** workspaces (`auth_service.go:149-163`) — auto-minting one would be privilege escalation. Covered by a service test.
23. **(A / Fix 2)** Case-insensitive email bridge — the OIDC invited-user link and JIT duplicate check use `GetUserByEmailInsensitive` (`lower(email)=lower($1)`, functional-indexed), so a mixed-case invited user is matched (not missed → no duplicate JIT create). The magic-code `GetUserByEmail` is unchanged.
24. **(A / Fix 3)** Second unique constraint — `UNIQUE(user_id, idp_issuer)` (in addition to `UNIQUE(idp_issuer, idp_sub)`) makes the link-conflict check deterministic and blocks silent sub-accumulation; a LINK insert hitting `23505` on **either** constraint is **refused** (`?oidc_error=link_conflict`), never swallowed as success.
25. **Never log raw tokens** — never log `id_token`, `access_token`, or `client_secret`. Beware `%w`-wrapping oauth2 token-endpoint errors that can embed response bodies; log a generic message and the typed error class, not the raw token-endpoint payload. Audit logs record only the stable `(issuer, sub)` and `user_id`.
26. **Settings-secret masking + admin gating** — the system-settings GET masks `oidc_client_secret` (returns `passwordMask`, never the value, mirroring SMTP at `settings_handler.go:207-209`) and the settings GET/UPDATE endpoints are gated to ROOT_EMAIL/admin (`requireRootUser`, confirmed at `settings_handler.go:101-104`). `serveConfigJS` exposes only `OIDC_ENABLED` + `OIDC_BUTTON_LABEL` — never the secret, client_id, issuer, scopes, or allowed-domains.
27. **Button-label XSS** — `window.OIDC_BUTTON_LABEL` is rendered as React **text content** (auto-escaped), never via `dangerouslySetInnerHTML`; the server-side `config.js` literal is `%q`-escaped.

### 6.D Ops & Rollout

#### 6.D.1 Phased rollout

1. **Phase 0 — schema only.** Ship v34 (additive `federated_identities`; `ShouldRestartServer()=false`). No behavior change; safe to deploy ahead of code.
2. **Phase 1 — backend dark.** Deploy service/handlers/routes with OIDC **disabled**. Routes exist but return not-enabled. Magic-code untouched.
3. **Phase 2 — single-tenant pilot.** Enable via `OIDC_*` env on one instance (env-wins, no DB write/restart churn), invited-only. Validate Google **and** Keycloak end-to-end.
4. **Phase 3 — GA via UI.** Surface OIDC in the setup wizard + System Settings drawer; saving DB settings triggers the existing graceful restart (`settings_handler.go ~:300`; setup completion at `app.go:533`). Optionally enable JIT (`OIDC_AUTO_CREATE_USERS=true` **+** non-empty `OIDC_ALLOWED_DOMAINS`).

#### 6.D.2 Graceful-degradation behavior (operator-visible)

- Issuer down at boot + `OIDC_ENABLED=true`: server boots, magic-code works, OIDC routes 503, loud warn log; provider lazily initializes on first reachable request.
- Misconfig fail-fast at boot: `OIDC_AUTO_CREATE_USERS=true` with empty allowlist → **refuse to boot** with an explicit error.
- Multi-replica caveat: the one-time exchange-code store is in-memory, so behind N replicas a code minted on replica A can't be redeemed on B. Until a DB-backed store lands: sticky sessions pinning the flow to one replica, or run a single instance. **Documented, not built now.**

#### 6.D.3 `redirect_uri` exact-match gotcha

Providers require the `redirect_uri` at `/authorize` to **byte-exactly** match a pre-registered URI (scheme, host, port, path, trailing slash). `OIDC_REDIRECT_URI` must equal the registered value exactly — e.g. `https://app.example.com/api/user.oidc.callback`. Common failures: `http` vs `https`, missing/extra trailing slash, `www.` vs apex, a dev port. Behind a reverse proxy, derive the public origin from config (the `apiEndpoint` overlay, `config.go:606`), not request headers.

#### 6.D.4 Provider setup — Google Workspace

1. Google Cloud Console → APIs & Services → Credentials → Create Credentials → OAuth client ID → **Web application**.
2. Authorized redirect URIs → add the exact `OIDC_REDIRECT_URI` (e.g. `https://app.example.com/api/user.oidc.callback`).
3. Copy Client ID / Client secret → `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` (or the DB settings drawer; secret stored encrypted).
4. Issuer = `https://accounts.google.com` → `OIDC_ISSUER_URL`.
5. Scopes `openid email profile`. Google sets `email_verified`.
6. Restrict to a Workspace domain via `OIDC_ALLOWED_DOMAINS` (server-side allowlist is the security boundary; Google's `hd` claim is advisory only).

#### 6.D.5 Provider setup — Keycloak

1. Realm → Clients → Create client → type OpenID Connect, set Client ID (= `OIDC_CLIENT_ID`).
2. Client authentication = On (confidential) → Credentials tab → copy the Secret → `OIDC_CLIENT_SECRET`.
3. Valid redirect URIs → exact `OIDC_REDIRECT_URI` (no wildcard).
4. Issuer = `https://<host>/realms/<realm>` → `OIDC_ISSUER_URL`.
5. Client scopes → ensure `email` is default and its mapper emits `email` + `email_verified`. If `email_verified` is absent, logins are refused — fix the mapper or verify users.
6. Standard flow (Authorization Code) enabled; PKCE supported natively (Notifuse always sends `S256`).

#### 6.D.6 Risks

- **Email recycling** for invited-but-never-logged-in users (documented residual; future strict mode).
- **Single registered redirect URI** behind multiple public hostnames — pick one canonical origin.
- **In-memory exchange-code store** breaks under HA (§6.D.2).
- **Boot-time issuer dependency** softened by lazy init, but a permanently-wrong issuer URL silently keeps OIDC at 503 — surface in a health/status check.
- **Provider clock skew** can fail `exp`/`iat`; rely on go-oidc default skew tolerance, don't widen it.

#### 6.D.7 Deferred work

- **DB-backed one-time exchange-code store** for true multi-replica HA (replaces in-memory `cache.GetAndDelete`).
- **BFF migration** (HttpOnly session cookie replacing localStorage handoff) — out of scope; current posture matches magic-code.
- **Multi-provider / per-workspace IdP** (today: one global issuer config).
- **SLO/alerting** on OIDC start→callback→exchange success rate and the 503 lazy-init state.
- **Account-linking UX** (attach/detach a federated identity from settings) and **federated-identity admin view** (`ListByUserID` already supports it).
- **Strict anti-recycling mode** (out-of-band confirmation before the email→link bridge).

### 6.E Files touched (full list)

`go.mod`/`go.sum` (Step 0: add go-oidc/v3, promote x/oauth2 to direct), `config/config.go:18` (+OIDC struct/validation/overlay via new standalone `resolveOIDCConfig`), **new** `config/oidc.go`, `config/root_email.go` (reuse splitter; `IsRootEmail` passed into OIDC service), **new** `internal/migrations/v34.go` (+ `v34_test.go`), `internal/database/schema/system_tables.go` (table + both UNIQUE constraints + `idx_federated_identities_user_id` + `idx_users_lower_email` + FK), **new** `internal/domain/federated_identity.go` (+ test), **new** `internal/domain/oidc.go` (+ test), `internal/domain/user.go` (+ `GetUserByEmailInsensitive` on `UserRepository`), `internal/repository/user_postgres.go` (+ `GetUserByEmailInsensitive`, + test), `internal/domain/mocks/mock_federated_identity_repository.go` + `mock_oidc_service.go` + regenerated `mock_user_repository.go`, **new** `internal/repository/federated_identity_postgres.go` (+ test), **new** `internal/service/oidc_service.go` (+ test), `internal/service/setup_service.go`, `internal/service/setting_service.go`, **new** `internal/http/oidc_handler.go` (+ test), `internal/http/setup_handler.go`, `internal/http/settings_handler.go`, `internal/http/root_handler.go:148`, `pkg/cache/cache.go` (+ `GetAndDelete`, test), `internal/app/app.go` (DI + routes + rate-limit policies + exchange cache + `IsRootEmail`), `console/src/vite-env.d.ts`, `console/src/services/api/auth.ts` (+ test), `console/src/router.tsx`, `console/src/pages/SignInPage.tsx`, `console/src/types/setup.ts`, `console/src/types/settings.ts`, `console/src/pages/SetupWizard.tsx`, `console/src/components/settings/SystemSettingsDrawer.tsx`, `console/src/i18n/locales/*.po`, `console/src/__tests__/SignInPage.test.tsx`, `tests/testutil/database.go` (seed), `tests/integration/oidc_test.go`. **Unchanged (verify):** `console/src/contexts/AuthContext.tsx`, `console/src/services/api/client.ts`, `internal/http/middleware/auth.go`, and the existing exact-match `GetUserByEmail`.

---

## Open Questions for the User

1. **FK vs. app-level cleanup (§6.A.3).** The brief requested `ON DELETE CASCADE`, but every other system table is inline-`REFERENCES`-free. Default in this plan is a named DB-level FK with cascade. Confirm, or prefer the strictly-FK-free convention with an explicit `DELETE FROM federated_identities WHERE user_id=$1` in the user-deletion path?
2. **Strict anti-recycling mode (§1.3 / §6.D.7).** Ship the email-bridge linking now (invited-only default, the inviter chose the email) and defer the stricter "invitation pre-bound to (issuer, sub)" mode? Or block the email bridge from day one and require an in-app "link SSO" action from an authenticated session?
3. **Single registered issuer.** This plan supports exactly one global IdP. Is one provider sufficient for launch, or is multi-provider (e.g. Google **and** Keycloak simultaneously, or per-workspace IdP) an initial requirement?
4. **Lazy-init retry window (§3.3).** Confirm the ~30s guarded retry (`sync.Mutex` + `lastAttempt` window, replacing a plain `sync.Once`) on a failed provider init is the right window — it lets a transiently-unreachable issuer self-heal on the next request after the window, without a process restart.
5. **JIT default Type/role.** JIT-provisioned users are created as `Type=UserTypeUser` with no workspace membership (login ≠ access). Confirm this is the intended posture (they see nothing until explicitly invited).
6. **Dev-mode cookie downgrade (§4.8).** Acceptable to drop the `__Host-` prefix + `Secure` over plain HTTP in local dev only, with production mandated HTTPS for the hardened posture?
7. **Optional `__Host-` cookie hardening (§4.5.2).** The default token handoff is now a URL-fragment one-time code (works in all topologies). Do you want the **optional** `__Host-` HttpOnly one-time-code **cookie** hardening enabled for **same-origin** deployments (it does NOT work across split console/API origins)? Default: off (fragment-only).

## Effort Estimate

| Area | Est. |
|---|---|
| Migration v34 + schema/system_tables + domain/repo/mock + tests | 0.5–1 d |
| Config surface (env + DB hybrid, encrypt secret, fail-fast, `GetEnvOverrides`) + tests | 1 d |
| OIDC service (provider guarded-retry init, PKCE, full identity state machine, exchange code) + fake-IdP service tests | 2.5–3 d |
| HTTP handlers (start/callback/exchange, cookies, rate limits, 503 degradation) + tests | 1.5–2 d |
| `pkg/cache.GetAndDelete` + concurrency tests; ratelimiter policy wiring | 0.5 d |
| Frontend (SignInPage SSO button + `#oidc_code` fragment exchange, `auth.ts`, Setup/Settings OIDC fields, i18n) + Vitest | 1.5–2 d |
| Integration tests + seed updates + Google/Keycloak manual validation | 1–1.5 d |
| **Total** | **~8.5–11 dev-days** (≈2 weeks with review/QA buffer) |

---

## Revision Notes

This plan was hardened after two adversarial security + completeness reviews. The following fixes were applied (each updated across the flow diagram, the relevant numbered section, the security checklist, and the test plan, keeping route/env-var names identical throughout):

- **Token handoff switched to a URL-fragment one-time code** (primary), because the prior `__Host-` HttpOnly cookie handoff breaks in split-origin deployments (dev origin rewrite `client.ts:41-46`; `SameSite=Lax` not sent on cross-site POST; `Access-Control-Allow-Origin:*` + `Allow-Credentials:true` browser-blocked, `cors.go`). `/callback` now 302s to `/console/signin#oidc_code=<code>`; the SPA reads `location.hash`, `replaceState`s it away, and POSTs `{ code }` in the body. The `__Host-` cookie variant is demoted to an optional same-origin hardening (§4.5.2). The AEAD `__Host-` flow-state cookie is unchanged. Residual (code briefly in history) documented honestly.
- **Case-insensitive email bridge (Fix 2):** added `GetUserByEmailInsensitive` (`lower(email)=lower($1)`, functional-indexed) for the invited-user link and JIT duplicate check, so a mixed-case invited user is matched (no duplicate JIT create). The magic-code `GetUserByEmail` is unchanged.
- **Second unique constraint (Fix 3):** `UNIQUE(user_id, idp_issuer)` added alongside `UNIQUE(idp_issuer, idp_sub)`; `GetByUserAndIssuer` is now deterministic; a LINK insert hitting `23505` on either constraint is **refused** (`link_conflict`), never swallowed.
- **Issuer pin made unconditional (Fix 4):** an UNCONDITIONAL post-Verify `idToken.Issuer == cfg.IssuerURL` assertion is the primary control; the `?iss=` (RFC 9207) check is demoted to a defense-in-depth pre-exchange short-circuit.
- **Provider self-healing (Fix 5):** replaced the plain `sync.Once` with a `sync.Mutex` + `lastAttempt` retry window (~30s) so a transiently-unreachable issuer recovers on the next request without a restart.
- **ROOT_EMAIL + JIT safety (Fix 6):** JIT auto-create refuses when the verified email matches a configured `ROOT_EMAIL` (`config.IsRootEmail`), forcing the invite path (else privilege escalation via the synthesized-owner override `auth_service.go:149-163`).
- **Config overlay accuracy (Fix 7):** `resolveOIDCConfig` is a NEW STANDALONE helper invoked after `apiEndpoint` trim (`config.go:764`) and before the `config := &Config{` literal (`:766`), assigned as `OIDC: oidcConfig`; it does NOT edit the single two-branch SMTP overlay block (`config.go:599-728`).
- **IP rate-limit reality:** documented that `getClientIP` trusts `X-Forwarded-For` unconditionally (spoofable except behind a trusted proxy); the real exchange-code brute-force resistance is 256-bit entropy + ≤60s TTL + single-use `GetAndDelete`.
- **Login-CSRF success-path analysis** made explicit (success code issued only after a matching `__Host-` flow cookie + state in the same browser; attacker cannot plant the cookie cross-origin), with a no-flow-cookie test that asserts no code/cookie/fragment is issued.
- **azp** enforced exactly when a genuine second distinct audience exists (`hasDistinctSecondAudience`); duplicate/single aud never requires azp; tests added.
- **typ rejection** now matches both `at+jwt` and `application/at+jwt` (case-insensitive).
- **Button label** must render as React text content (auto-escaped), never `dangerouslySetInnerHTML`.
- **Never log raw tokens:** added a checklist rule (no `id_token`/`access_token`/`client_secret`; beware `%w`-wrapped token-endpoint bodies).
- **Settings-secret masking + admin gating** confirmed: system-settings GET masks `oidc_client_secret` and is gated to ROOT_EMAIL (`requireRootUser`, `settings_handler.go:101-104`).
- **Shared TTL constant:** one-time-code cache TTL and the optional cookie Max-Age both bound to `oidcExchangeTTL`.
- **Step 0 deps** added: `go get github.com/coreos/go-oidc/v3@latest` + `go mod tidy` (promote `x/oauth2` to direct) + verify go-oidc v3.18 symbol names compile before building the rest.
- **Migration interface anchor** corrected: `MajorMigrationInterface` at `internal/migrations/interfaces.go:19`; `Register` at `registry.go:53`; `V34Migration` satisfies all six interface methods.