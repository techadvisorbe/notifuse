# Plan: Amazon SES inbound reply detection for stop-on-reply

Extend the existing **stop-on-reply** feature (currently Mailgun-only) to **Amazon SES**, so a
contact replying to an automation email exits their journey when the automation has
**Exit on reply** enabled.

**Verdict:** feasible, with caveats. ~5–8 backend engineer-days (excluding a mandatory
manual AWS verification step), concentrated in two places where SES differs fundamentally
from Mailgun.

## Implementation status (2026-06-17)

- **Phase 1 (send capture):** DONE. `CapturedMessageID` field; capture at `ses_service.go`
  send paths; `ProviderCapturesMessageID(SES)`; worker capture branch. Tested.
- **Phase 2 (inbound parser):** DONE. `SESReplyParser` (SNS decode, RSA signature verify v1/v2,
  cert host allowlist + SSRF-safe fetch, subscription confirm-after-verify, control-message
  ack, header extraction with raw-MIME fallback); registry; service early-ack. Tested.
- **Phase 3 (auto-provisioning):** DONE. `EnsureInboundRoute` (region allowlist, SNS topic +
  publish policy + SignatureVersion 2 + subscribe, coexistence-safe receipt rule into the
  active set), `UnregisterWebhooks` deletes only our rule, `GetWebhookStatus` reports
  `inbound_registered`. SES/SNS interface + mock methods added. Tested with mocked AWS.
- **Phase 5 (console + docs):** DONE. SES added to `INBOUND_REPLY_PROVIDER_KINDS`; inbound
  status UI generalized; `amazon-ses.mdx` + `automations.mdx` updated; CHANGELOG [33.1].
- **Phase 4 (S3 large email >150 KB):** DEFERRED (optional follow-up).
- **Message-ID suffix:** RESOLVED differently than originally planned — see below. No live-AWS
  blocker remains for matching; a real send is still worth doing to confirm end-to-end.

**Key design change vs. original plan — host-independent matching.** Research into the AWS
docs (2026) found AWS does NOT contractually pin the Message-ID host: public sources show
`email.amazonses.com`, `mail.amazonses.com`, and region-qualified variants. Rather than bet
on one suffix constant (whose wrongness would silently break *every* SES reply), we store the
**bare SES-returned MessageId** (its globally-unique local part) and, at match time, strip the
`@*.amazonses.com` host from the reply's `In-Reply-To`/`References` to recover that local part
(`SESReplyCandidate` in `reply_matching.go`, applied in `matchReply`). Matching is therefore
independent of the exact host SES stamps.

## The two hard differences from Mailgun

| | Mailgun (done) | SES (this plan) |
|---|---|---|
| **Send / Message-ID** | We set our own `h:Message-Id`; Mailgun preserves it | SES **overwrites** any caller Message-ID → we must **capture the SES-returned `MessageId`** (today discarded) and store the reconstructed value |
| **Receive** | One account-level forward **Route** → POST to our endpoint | **Receipt-rule-set → SNS** (or S3 for large mail) → our endpoint, with SNS `SubscriptionConfirmation` + signature verification; only **one active receipt rule set** per account/region |

Everything *after* parsing is reused verbatim: `domain.InboundReply` + `ReplyParser`,
`Classify`, `matchReply` → `GetBySMTPMessageID`, the dedup-gated exit, and the layered stop
guarantee. SES routing is automatic by `integration.EmailProvider.Kind`.

## Architecture

**Send (capture, not set).** SES overwrites the Message-ID header
([AWS docs](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)). So SES is a
*capture* provider, not a *set_own* provider. `SESService.SendEmail`/`sendRawEmail` currently
discard the response (`ses_service.go:909`, `:1104`). We keep `out.MessageId`, surface it to
the worker, and store the bracket-free `<MessageId>@email.amazonses.com` as
`message_history.smtp_message_id`. A reply's `In-Reply-To`/`References` echoes that value;
`reply_matching.go` already bracket-strips both sides, so matching resolves unchanged.

**Receive (receipt rule + SNS).** Inbound mail reaches SES only when: (1) the SES region
supports receiving, (2) an MX record `10 inbound-smtp.<region>.amazonaws.com` points the
domain at SES (manual DNS, like Mailgun's MX), and (3) a receipt rule in the **active** rule
set has an SNS action publishing to an SNS topic HTTPS-subscribed to
`/webhooks/email/inbound`. SES POSTs an SNS envelope: first a `SubscriptionConfirmation`, then
per-email a `Received` `Notification` whose stringified `Message` contains `receipt` + `mail`
+ `content` (raw MIME). A new `SESReplyParser` double-decodes the envelope, auto-confirms the
subscription (after verifying it), verifies the SNS signature + TopicArn, extracts
`In-Reply-To`/`References` from the inner payload, and hands off to the existing pipeline.

## Send-side design (capture)

1. **Stop discarding the response** — `ses_service.go:909` `_, err = ...SendEmailWithContext`
   → `out, err := ...`; same at `:1104` for `SendRawEmailWithContext`. The `SESClient`
   interface + mock already return the typed outputs, so **no interface/mock regen needed**.
2. **Surface the captured id without changing `EmailServiceInterface.SendEmail`** (that
   signature has an 8-provider + 2-mock + 6-call-site blast radius). Add a
   `CapturedMessageID *string` result field to `SendEmailProviderRequest`
   (`email_provider.go:351-362`); the worker already builds `request` as a pointer
   (`worker.go:373`), so SES writes through the shared pointer target across the by-value copy.
3. **Reconstruct & store** — `smtp_message_id = capturedMessageID + "@email.amazonses.com"`
   (bracket-free). Do **not** use `RFCMessageIDValue(entry.MessageID, FromAddress)` (the From
   domain is never what SES emits). Add `ProviderCapturesMessageID(SES)` parallel to
   `ProviderSetsOwnMessageID` (stays Mailgun-only), and a capture branch in the worker's
   post-send `upsertMessageHistory` (`worker.go:525-534`). Note: the **pre-send** upsert
   (`worker.go:368`) does NOT apply to SES — the id is only known *after* the send.

## Receive-side design (receipt rule + SNS)

**Provisioning** — new `SESService.EnsureInboundRoute` (auto-wired by the existing
`InboundRouteRegistrar` type-assertion at `webhook_registration_service.go:108-113`; SES is
already a registered `WebhookProvider`, so **zero wiring**):
1. Validate the SES region against a receiving-supported allowlist (NOT GovCloud, ap-south-2,
   eu-central-2, ca-west-1, …); surface a clear error / `inbound_registered=false` otherwise.
2. Create/own an SNS topic, `SetTopicAttributes SignatureVersion=2`, subscribe HTTPS endpoint
   = `GenerateInboundWebhookURL(...)` (reuse the topic+subscribe plumbing at
   `ses_service.go:261-282`). Requires adding `SetTopicAttributesWithContext` to the
   `SNSClient` interface (+ mock regen).
3. **Coexistence-safe rule insertion** — `DescribeActiveReceiptRuleSet` first; if a set is
   active, `CreateReceiptRule` **into** it. Only create + `SetActiveReceiptRuleSet` a
   dedicated `notifuse` set when **none** is active. Never blindly activate a fresh set — it
   silently deactivates WorkMail / other apps (the SES analog of the Mailgun `stop()` hazard).
   Rule: `notifuse-inbound-<id>`, `Enabled`, `Recipients`=verified domain(s), one
   `SNSAction{TopicArn, Encoding=Base64}` (inline) for the simple path.

**Parser** — new `internal/service/inbound_reply_ses.go` implementing `domain.ReplyParser`
(mirror `inbound_reply_mailgun.go`), registered in the `replyParsers` map
(`inbound_webhook_event_service.go:49`):
- `Verify()`: unmarshal the SNS envelope. `SubscriptionConfirmation` → **verify signature +
  TopicArn, then** GET `SubscribeURL` via the **SSRF-safe client** → signal control message.
  `UnsubscribeConfirmation` → ack **without** GETting (re-GET re-subscribes). Otherwise verify
  the SNS signature (v1=SHA1 / v2=SHA256; sorted `Key\nValue` string-to-sign; `SigningCertURL`
  host guard `^sns\.[a-z0-9-]{3,}\.amazonaws\.com(\.cn)?$`; fetch+cache cert; `rsa.VerifyPKCS1v15`)
  and validate `TopicArn` against the ARN persisted on the Integration.
- `Parse()`: double-decode (`envelope.Message` → `Received`), take From/To/Subject from
  `commonHeaders`, and `In-Reply-To`/`References` from `mail.headers[]` or by parsing the raw
  `content` MIME (`commonHeaders` omits them).
- `ProcessInboundReply` (`inbound_webhook_event_service.go:57-96`) must early-ack control
  messages (no reply to classify) instead of erroring.

## Integration points (file:line)

| Component | Change | Location |
|---|---|---|
| Capture SES MessageId | keep `out`, write to `request.CapturedMessageID` | `ses_service.go:909`, `:1104` |
| Request result field | add `CapturedMessageID *string` | `email_provider.go:351-362` |
| Capture predicate | add `ProviderCapturesMessageID(SES)` | `reply_matching.go:32-39` |
| Worker storage gate | capture branch → `capturedID + "@email.amazonses.com"` | `worker.go:525-534` |
| SES reply parser | new file, `ReplyParser` impl | `internal/service/inbound_reply_ses.go` (mirror `inbound_reply_mailgun.go`) |
| Parser registry | add `EmailProviderKindSES` entry | `inbound_webhook_event_service.go:49-51` |
| Control-message ack | tolerate confirmation (no reply) | `inbound_webhook_event_service.go:83-96` |
| `SESService.EnsureInboundRoute` | region allowlist + topic + coexistence-safe receipt rule | new (mirror `mailgun_service.go:1054-1113`) |
| `SNSClient` interface | add `SetTopicAttributesWithContext` (+ mock) | `email_provider_ses.go:31-36` |
| SES `GetWebhookStatus` | set `inbound_registered` (detect rule+subscription) | `ses_service.go:594-683` |
| SES `UnregisterWebhooks` | `DeleteReceiptRule` (ours only); never null active set | SES `UnregisterWebhooks` |

## Risks

- **🔴 Pre-existing SSRF (fix as part of this):** the SES **event** path already GETs
  `SubscribeURL` with **no signature check, no TopicArn allowlist, plain `http.Get`**
  (`inbound_webhook_event_service.go:422`). A forged `SubscriptionConfirmation` → server-side
  request to an attacker URL. The new inbound path must verify-then-GET via the SSRF-safe
  client; strongly consider hardening the event path too.
- **Single active receipt rule set** — must `DescribeActiveReceiptRuleSet` and insert into the
  active set; blindly activating a `notifuse` set deactivates a customer's existing setup.
- **Message-ID suffix unverified** — code assumes `@email.amazonses.com`; sources disagree
  (`email` vs `mail`). If wrong, **every** SES reply silently fails to match (no error).
  Verify with a real send; keep it a single constant.
- **150 KB inline limit** — SES bounces inbound mail >150 KB before SNS's 256 KB matters;
  large quoted threads/attachments are never delivered (silent miss). S3+SNS (40 MB) is the
  robust follow-up (needs bucket + GetObject + bucket policy).
- **Region coverage** — receiving unsupported in several regions; allowlist-validate.
- **Hand-rolled SNS signature verification** — fiddly (string-to-sign differs by `Type`);
  needs a golden fixture from a real signed message, or vendor `go-sns-message-validator`.
- SES can accept a message without sending → an orphan `smtp_message_id` (low false-match risk).

## Phasing

0. **Empirical verification (blocker):** send one real SES message, confirm the exact
   Message-ID suffix and that the API `MessageId` is the local part; capture a real signed SNS
   message as a golden test fixture.
1. **Send capture:** `CapturedMessageID` field; capture at `:909`/`:1104`;
   `ProviderCapturesMessageID(SES)`; worker capture branch. (~0.5–1d, low-risk)
2. **Inbound parser** (works with manual provisioning): `SESReplyParser` (SNS decode,
   signature+TopicArn verify, confirmation handling, header extraction); registry; control-ack.
   (~2–3d, riskiest)
3. **Auto-provisioning:** `EnsureInboundRoute` (region allowlist, topic+`SetTopicAttributes`,
   coexistence-safe rule), `UnregisterWebhooks` reversal, `GetWebhookStatus`. (~1.5–2d)
4. **Large-email (optional):** S3Action + SNS-metadata path >150 KB. (~1–2d follow-up)
5. **Console + docs:** SES `inbound_registered` UI (mirror Mailgun); document MX record +
   supported regions; add SES to the frontend `INBOUND_REPLY_PROVIDER_KINDS`. (~0.5d)

## Testing strategy

- **Domain:** `ProviderCapturesMessageID` table test; the `@email.amazonses.com` reconstruction.
- **Service (SES send):** mocked `SESClient` returning a `MessageId`; assert it lands in
  `request.CapturedMessageID`. Worker test: SES automation send stores
  `smtp_message_id = <id>@email.amazonses.com`.
- **Service (parser):** golden SNS fixtures — `SubscriptionConfirmation` (verify-then-confirm),
  `UnsubscribeConfirmation` (ack-no-GET), forged signature (reject), a real `Received` MIME
  (extract `In-Reply-To`/`References`, classify, match). Cover the SSRF guard.
- **Service (provisioning):** mocked SES/SNS — active-set-exists (insert into it) vs
  none-active (create+activate); `UnregisterWebhooks` deletes only our rule.
- **Integration:** extend `tests/integration/inbound_reply_test.go` — POST an SES-shaped SNS
  `Received` body to `/webhooks/email/inbound` for an SES integration, assert match + exit
  (mirrors the Mailgun subtests). The `EnsureInboundRoute`/AWS calls are unit-tested with
  mocked clients (no live AWS), as with Mailgun.
- Run `make test-service test-http` + the touched integration tests.

## Open decisions

- Confirm the Message-ID suffix (`@email.amazonses.com` likely) before hard-coding.
- Capture mechanism: `CapturedMessageID` result field (recommended) vs changing
  `SendEmail` to return `(string, error)` vs a side-channel.
- Delivery: inline SNS (simple, ≤150 KB) vs S3+SNS (40 MB) — recommend inline first.
- Where to persist the created `TopicArn` on the Integration (for the parser's TopicArn allowlist).
- Harden the existing SES **event** path's SubscriptionConfirmation as part of this work?
- Hand-roll SNS verification (~60 lines, no new dep) vs vendor a validator.
