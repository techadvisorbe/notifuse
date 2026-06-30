# Stop-on-Reply via Inbound Reply Detection (multi-ESP) — Implementation Plan

Implements issue **#346**: when a contact replies to any email in a sequence
automation, stop sending the remaining emails. Built test-first (TDD) with
integration coverage. Target branch: `dev` (no PR — implement directly).

---

## 1. Scope

**In scope**

1. **Inbound reply ingestion** via ESP webhooks, behind a provider-agnostic
   abstraction (one normalization layer + one parser per ESP).
2. **Reply classification**: drop bounces/DSNs, treat auto-responders/out-of-office
   as non-exit, separate unsubscribes — only a *genuine human reply* triggers exit.
3. **Message-ID matching**: `In-Reply-To`/`References` → stored outbound
   `smtp_message_id` → the `message_history` row → `automation_id` + contact →
   journey; **sender address as fallback**.
4. **Stop mechanism = layered guarantee** behind a per-automation `exit_on_reply`
   setting: (a) event-driven interrupt, (b) queue-worker just-in-time guard,
   (c) executor optimistic-lock fix.
5. **ESPs (webhook-based):** Mailgun (reference), SendGrid, Postmark, SparkPost,
   Mailjet. Built first for Mailgun, then the others via a docs-research phase.
6. **Security**: per-integration endpoint token + native provider signature where
   supported.
7. Full **TDD** + per-layer unit tests + **integration tests** on real Postgres.

**Out of scope (deferred — not built now)**

- SES inbound (receipt rule → SNS/S3) and SMTP (IMAP polling) — different ingestion
  shape; SES is a common provider so it's the top future addition.
- Inbound-route **auto-registration** (we show manual setup instructions instead).
- Filter-node / segment-condition reply path (the layered guarantee replaces it).
- `email.replied` as an automation **trigger** (start-on-reply).
- Pause-and-resume on OOO (we record auto-replies and skip exit only).
- "Replied to which email" timeline UI; AI intent classification; account/domain
  suppression; per-message attribution UI.

---

## 2. Key context (why this shape)

- **Trigger ≠ exit.** A timeline trigger only *enrolls* a contact
  (`automation_enroll_contact`, `internal/migrations/v21.go`); it cannot exit a
  running journey. So the exit must act on `contact_automations` directly.
- **Two async race windows** (verified in code): a contact can be asleep in a
  **delay** (`automation_executor.go`), and the email node only **enqueues**
  (`automation_node_executor.go:415`) — a separate worker (`queue/worker.go`) sends
  later. Closing only one window leaks emails, so the guarantee is layered.
- **The existing `notifuse_message_id`** is a custom tag/var the ESPs echo in
  *event* webhooks — it is NOT the RFC `Message-ID:` a reply's `In-Reply-To`
  carries, so it can't be reused directly; we record the recipient-visible
  `Message-ID` as `smtp_message_id` instead.

---

## 3. Architecture

```
SEND  (automation_executor → Email node → queue worker)
  generate messageID = uuid (= message_history.id)
  record the recipient-visible RFC Message-ID as message_history.smtp_message_id
    set_own (Mailgun/Postmark) → <messageID@domain>   |  capture (Mailjet) → returned id
  enqueue EmailQueueEntry{ source=automation, contact_automation_id=CA, status=pending }
     │
     ▼  QUEUE WORKER (queue/worker.go), before the ESP call:
        ★ JIT GUARD  — re-read contact_automations.status by CA;
                       if != active → cancel entry, skip send            [Boundary B]
     ▼  ESP send API → 📧 carries Message-ID

WAIT  next node is a Delay → contact sleeps (scheduled_at future), status=active

REPLY  contact replies → In-Reply-To: <Message-ID>
       → ESP inbound parse (MX→ESP) → POST /webhooks/email/inbound?ws&integ&token

INGEST  (inbound_webhook_event_service.ProcessInboundReply)
  verify token (constant-time, else 401)
  ReplyParser[kind].Verify (provider signature) + .Parse → InboundReply
  CLASSIFY: bounce/DSN → drop · auto-reply/OOO → store email.auto_reply, no exit
            unsubscribe → unsubscribe flow · genuine → ▼
  MATCH:  In-Reply-To → message_history.smtp_message_id → (automation_id, contact)
          else sender → contact's active exit_on_reply journeys
          (ErrContactNotFound → ignore/200 · real DB error → 5xx/retry)
  dedup (integration_id, message_id) → store inbound_webhook_events{type:reply}
     │ DB trigger → contact_timeline INSERT kind='email.replied'  (display/audit)
     ▼
  ★ EVENT INTERRUPT — UPDATE contact_automations
       SET status='exited', exit_reason='replied' WHERE id=CA AND status='active'  [Boundary A]

EXECUTOR  persist step made conditional (WHERE status='active'; 0 rows → abort tick) [clobber fix]
```

---

## 4. Design details

### 4.1 Canonical model & parser interface (domain)

`internal/domain/inbound_reply.go` (new):

```go
type InboundReply struct {
    FromEmail  string; ToEmail string; Subject string
    MessageID  string    // reply's own Message-ID, brackets stripped (dedup key)
    InReplyTo  string    // matching key (→ our smtp_message_id)
    References []string
    ReceivedAt time.Time
    AutoSubmitted, Precedence, ContentType string  // classification inputs
    RawHeaders map[string]string
}
type ReplyClass int // ReplyGenuine | ReplyAutoResponder | ReplyBounce | ReplyUnsubscribe
type InboundRequest struct { Header http.Header; ContentType string; Query, Form url.Values; Body []byte }
type ReplyParser interface {
    Source() WebhookSource
    Verify(req *InboundRequest, integration *Integration) error
    Parse(req *InboundRequest) (*InboundReply, error)
}
```

- Add `EmailEventReply = "reply"` and `EmailEventAutoReply = "auto_reply"` to
  `inbound_webhook_event.go`.
- Parser registry `map[EmailProviderKind]ReplyParser` in the service.

### 4.2 Reply classification

`Classify(reply) ReplyClass` (pure, table-tested):
- **Bounce/DSN** → `Content-Type: multipart/report` / `report-type=delivery-status`,
  or `mailer-daemon@`/`postmaster@` → **drop**.
- **Auto-responder/OOO** → `Auto-Submitted: auto-*`, `Precedence: bulk|auto_reply`,
  `X-Autoreply` → store `email.auto_reply`, **no exit**.
- **Unsubscribe** → `List-Unsubscribe`/intent → unsubscribe flow.
- **Genuine** → everything else → exit-eligible.

### 4.3 Message-ID matching (per-ESP)

Contract: for sends **from an `exit_on_reply` automation**, persist the
recipient-visible RFC `Message-ID` as `message_history.smtp_message_id` when we can
know it (all other sends leave it NULL — the feature is free for everyone else).
Verified per ESP (workflow `esp-messageid-reply-matching`):

| ESP | Strategy | How | smtp_message_id |
|-----|----------|-----|-----------------|
| Mailgun | set_own | `h:Message-Id` form field (mailgun_service.go:770,856) | `<messageID@domain>` |
| Postmark | set_own | `Headers:[{Name:"Message-ID",…}]` (postmark_service.go:~591) | `<messageID@domain>` |
| Mailjet | capture | parse `MessageUUID` from response (mailjet_service.go:~646) | returned id |
| SendGrid | sender-match | RFC Message-ID is protected; response id is internal | NULL |
| SparkPost | sender-match | can't set; transmission response has no RFC id | NULL |

- **Match order:** (1) `In-Reply-To`/`References` (strip `<>`) → `message_history`
  by `smtp_message_id` → journey; (2) sender → contact's active `exit_on_reply`
  journeys.
- **Graceful degradation:** match always tries Message-ID then sender, so a NULL
  `smtp_message_id` (or an unexpected ESP overwrite) degrades to sender-level
  matching — it never breaks stop-on-reply.
- **Cost gate:** `smtp_message_id` is written only for `exit_on_reply` sends, and its
  index is **partial** (`WHERE smtp_message_id IS NOT NULL`), so non-using workspaces
  add no index entries and pay no per-send index maintenance (see §12).

### 4.4 Stop mechanism (layered guarantee)

- **`Automation.ExitOnReply bool`** (default false; UI toggle). Scope: this automation.
- **(a) Event interrupt** — in `ProcessInboundReply`, conditional bulk update of the
  matched contact's active journeys (precedent: `automation_postgres.go:401`). New
  repo method `ExitContactJourneysOnReply(ctx, ws, contactEmail, automationID *string, reason)`
  (Message-ID match → scope to that automation; sender match → all `exit_on_reply`
  journeys for the contact).
- **(b) JIT guard** — in `queue/worker.go`, only for entries **flagged at enqueue**
  (`contact_automation_id` set, which the email node does *only* when the source
  automation has `exit_on_reply=true`): before the ESP call, read that journey's
  `contact_automations.status`; if not `active`, mark the entry cancelled and skip.
  Entries from non-feature automations carry no `contact_automation_id` → the worker
  runs **zero** extra queries for them.
- **(c) Optimistic-lock fix** — `automation_executor.go` persist becomes conditional
  (`WHERE id=$1 AND status='active'`); 0 rows → abort the tick.

### 4.5 Security

- **Endpoint token** (per-integration, in the URL) — `crypto/subtle` constant-time
  check before any work; 401 on mismatch. Stored encrypted on `EmailProvider`
  (mirror `APIKey`/`EncryptedAPIKey`).
- **Native provider signature** in `parser.Verify` where supported (Mailgun
  `timestamp+token+signature` HMAC).
- **PII minimization** — `raw_payload` stores only canonical fields (compact JSON),
  not the full body/attachments. `http.MaxBytesReader` cap before parse.

### 4.6 Correctness fixes

- **Error vs not-found:** `errors.Is(err, ErrContactNotFound)` → ignore/200; other
  errors → return (5xx → provider retries).
- **Dedup:** partial unique index on
  `(integration_id, message_id) WHERE type IN ('reply','auto_reply') AND message_id IS NOT NULL`.
- **`recipient_email`** holds the contact; documented; replies excluded from bounce
  logic by `type`.

---

## 5. Implementation by layer (TDD — write the test first)

### Step A — Domain (`make test-domain`)
1. `inbound_reply.go` (new): types + `Classify()`. Tests: classification table.
2. `inbound_webhook_event.go`: `EmailEventReply`, `EmailEventAutoReply`; list
   validation; `ProcessInboundReply` on the service interface.
3. `automation.go`: `Automation.ExitOnReply bool` (+ validation/JSON).
4. `message_history.go`: `SMTPMessageID *string`.
5. `email_provider.go`: `InboundToken`/`EncryptedInboundToken` + encrypt/decrypt
   wired into `Encrypt/DecryptSecretKeys`. Tests: round-trip.
6. Hand-edit `internal/domain/mocks/*` for new interface methods.

### Step B — Outbound Message-ID (send path) (`make test-service`)
7. **Only for sends from an `exit_on_reply` automation**, record `smtp_message_id`
   on the `message_history` row and set `contact_automation_id` on the
   `EmailQueueEntry` (all other sends leave both NULL → no JIT guard, no index entry):
   - set_own — Mailgun (`h:Message-Id`), Postmark (`Headers` Message-ID) →
     `<messageID@domain>`.
   - capture — Mailjet (parse `MessageUUID`).
   - SendGrid/SparkPost → leave NULL (sender-match).
   Tests: an `exit_on_reply` send sets/captures the expected `smtp_message_id` and
   flags the queue entry; a non-feature send leaves both NULL.

### Step C — Provider parsers (`make test-service`)
8. `MailgunReplyParser` (reference): `Verify` = HMAC of `timestamp+token` with the
   signing key (form fields); `Parse` reads base fields + the `message-headers` JSON
   (`Message-Id`/`In-Reply-To`/`References`/`Auto-Submitted`/`Precedence`/
   `Content-Type`) into the canonical reply. Helpers `extractEmailAddress`,
   `parseMessageIDList`, `headersFromMailgunJSON`. Tests: golden Mailgun fixtures
   (genuine/OOO/bounce); signature valid/invalid; `from` fallback + lowercasing.
9. SendGrid/Postmark/SparkPost/Mailjet parsers implemented in **Step H** after research.

### Step D — Service: ingest + match + interrupt (`make test-service`)
10. `ProcessInboundReply`: provider → `Verify` → `Parse` → `Classify` → match
    (Message-ID → sender, with the ErrContactNotFound fix) → dedup → store event →
    `ExitContactJourneysOnReply`. Tests: genuine reply matched by Message-ID exits
    that journey; sender fallback exits only `exit_on_reply` journeys; OOO records
    auto_reply, no exit; bounce dropped; unknown sender ignored (200); real DB error
    propagates; dedup; unsupported provider; signature failure.

### Step E — Repository (`make test-repo`)
11. `inbound_webhook_event_postgres.go`: insert reply/auto_reply tolerating the
    partial-unique conflict.
12. `message_history_postgres.go`: persist + look up by `smtp_message_id` (indexed).
13. `automation_postgres.go`: `ExitContactJourneysOnReply` + `UpdateContactAutomationIfActive`
    (returns rows-affected). Tests: sqlmock incl. 0-rows path.

### Step F — Executor lock + JIT guard (`make test-service`)
14. `automation_executor.go`: conditional persist; on 0 rows abort the tick. Test:
    concurrent exit not clobbered.
15. `queue/worker.go`: JIT guard **only for entries with `contact_automation_id` set**
    (exit_on_reply sends). Tests: flagged entry whose journey is exited → cancelled,
    no ESP call; flagged + active → sends; **unflagged entry → no status query at all**.

### Step G — Database + migration (`make test-migrations`, `make test-database`)
16. `init.go`: `track_inbound_webhook_event_changes()` → `type='reply'` ⇒
    `kind='email.replied'`, `type='auto_reply'` ⇒ `kind='email.auto_reply'`; reply
    dedup partial-unique index; `smtp_message_id` on message_history with a **partial**
    index `WHERE smtp_message_id IS NOT NULL`; `exit_on_reply` on automations;
    `contact_automation_id` on email_queue. (Column adds are nullable/constant-default
    → instant, no table rewrite.)
17. `internal/migrations/v33.go` (workspace): SQL byte-identical to init.go additions
    (`ADD COLUMN IF NOT EXISTS`, `CREATE OR REPLACE`, `IF NOT EXISTS`); full
    `MajorMigrationInterface`; `init(){Register}`.
18. `config/config.go`: `VERSION = "33.0"` (tree at 32.5; v33 free).
19. `manager_test.go`: "up to date" `32`→`33`; grep other latest-version assertions.
    `v33_test.go` (sqlmock execs + error wrap).

### Step H — ESP research + remaining parsers (see §6)
20. After A–G green: run the research phase, then implement SendGrid/Postmark/
    SparkPost/Mailjet parsers + per-ESP setup docs, each with a golden fixture test.

### Step I — Frontend (`cd console && npm test`, then lingui)
21. Automation settings: **"Exit on reply"** toggle. Next to the label, an **info
    icon** (Ant `<Tooltip>` + `InfoCircleOutlined`) whose tooltip explains the
    feature **requires inbound reply forwarding set up at the ESP** — i.e. the
    sending domain's inbound (MX) must route replies to the ESP, which forwards them
    to Notifuse's webhook; without it, replies aren't detected and the sequence won't
    stop. Tooltip text via `` t`…` `` (Lingui), with a link to the per-ESP setup docs.
    Also show the inline "Needs inbound replies set up" state when inbound isn't
    configured for the integration.
22. Email integration settings: **"Inbound replies"** section — generate the endpoint
    token; show the webhook URL `…/webhooks/email/inbound?workspace_id&integration_id&token`
    + the MX/route setup instructions per ESP (from §6).
23. `ContactTimeline.tsx`: labels/icons for `email.replied` (faReply) and
    `email.auto_reply` (faRobot).
24. Component tests (Vitest/RTL); `npm run lingui:extract && lingui:compile`.

### Step J — Integration tests (`make test-integration`, run only the new tests)
25. `tests/integration/inbound_reply_test.go` (real Postgres + app). Start stack:
    `docker compose -f tests/compose.test.yaml up -d`; add any new signin email to
    `tests/testutil/database.go`. Cases:
    - **Auth:** wrong/missing token → 401.
    - **Classification:** bounce DSN → no entry, no exit; OOO → `email.auto_reply`,
      journey still active.
    - **Message-ID match:** seed a `message_history` with a known `smtp_message_id`
      for an active journey; reply whose `In-Reply-To` matches → that journey
      `exited` (reason `replied`); duplicate POST → one event/exit.
    - **Sender fallback:** reply with no `In-Reply-To`, sender matches → active
      `exit_on_reply` journeys exited; non-flagged journeys untouched.
    - **JIT guard (Boundary B):** enqueue an automation email, exit via reply before
      the worker drains → pending email cancelled, not sent (Mailpit/queue status).
    - **Interrupt while sleeping (Boundary A):** contact in a delay; reply → exited
      before the delay elapses.
    - **Optimistic lock:** reply exit during an executor tick not clobbered.
    - **Unknown sender:** 200, no entry, no exit.

---

## 6. ESP research phase (parallel agents, official docs)

After Mailgun is green. One agent per remaining ESP (SendGrid, Postmark, SparkPost,
Mailjet). Capture: inbound setup (how the user routes their sending domain's inbound
to the ESP + the MX target), transport (form vs JSON; field names for sender/from/
recipient/subject/Message-Id/In-Reply-To/References), classification-header
availability (`Auto-Submitted`/`Precedence`/`Content-Type`), auth (native signature
or token), quirks (success status, batching, size), and a real example payload →
golden fixture. **Support criterion:** the inbound webhook must forward
`In-Reply-To`/`References`.

---

## 7. Migration & versioning

- `VERSION` 32.5 → **33.0**. `v33.go` SQL identical to `init.go` additions (diff to
  guard drift); idempotent. `CHANGELOG.md`: `## [33.0]`.

---

## 8. Test commands

```bash
make test-domain        # A
make test-service       # B, C, D, F
make test-repo          # E
make test-migrations    # G
make test-database      # G
cd console && npm test  # I (+ lingui:extract && lingui:compile)
docker compose -f tests/compose.test.yaml up -d   # J
make test-integration   # run only TestInboundReply* / stop-on-reply tests
```

---

## 9. Why the layered guarantee (not a single check)

Two async windows: a contact asleep in a **delay** (closed by the **event
interrupt**, which flips `status` so the scheduler stops picking it up), and an email
**already enqueued** (closed by the **JIT guard** at the actual ESP call, since the
email node only enqueues). The **optimistic-lock fix** prevents the executor from
overwriting a mid-tick exit. Result: once `status='exited'`, no further emails
enqueue or send.

---

## 10. Risks & mitigations

- **Interrupt vs executor clobber** → optimistic-lock the persist (Step F14); top
  priority.
- **JIT guard placement** → in the queue worker (real ESP call), not the email node.
- **OOO false exit** → classification records auto-replies but skips exit.
- **SES Message-ID** (when SES ingestion lands) → AWS overwrites a supplied
  Message-ID; must capture + verify empirically. (Out of scope now.)
- **Reception** → replies only arrive if the receiving domain's MX → the ESP;
  documented in the inbound-setup UI. Mailbox-hosted domains need IMAP (deferred).
- **init.go/v33 drift** → identical SQL + diff step.
- **Migration index build** → the `message_history(smtp_message_id)` index is
  **partial** and starts empty (all existing rows NULL), so the build is a fast scan
  that indexes nothing — no `message_history` rewrite, minimal lock.

---

## 11. Follow-ups (post-merge)

- SES inbound (SNS/S3) and SMTP **IMAP** ingestion (SES is the top addition).
- Inbound-route **auto-registration** via each ESP's API; DNS-verify/status UI.
- `email.replied` as a start-on-reply **trigger**; pause-and-resume on OOO.
- AI intent classification; account/domain-level suppression; per-message
  attribution UI.
- Fix the pre-existing dead `email.*` automation triggers (timeline writes
  `open_email` but `ValidEventKinds` has `email.opened`) — separate issue.

---

## 12. Performance — free until used

A workspace that never enables `exit_on_reply` pays **no new recurring SQL**:

- **One-time only:** migration v33 — instant `ADD COLUMN`s, a small dedup index, and
  a near-empty partial `smtp_message_id` index.
- **Send path:** `smtp_message_id` and the queue `contact_automation_id` flag are
  written only for `exit_on_reply` sends → non-feature sends add no index entries and
  no extra queries.
- **Queue worker:** the JIT status `SELECT` runs only for flagged entries → none for
  non-feature automations.
- **Inbound:** matching + interrupt SQL runs only when a reply is actually received;
  there is no background poller.
- **Executor:** the persist gains a `WHERE status='active'` predicate (a modified
  existing UPDATE on the PK, not a new query) — negligible, and a correctness win.
- **Trigger:** a constant-time `CASE` branch on `NEW.type` — no query.
```
