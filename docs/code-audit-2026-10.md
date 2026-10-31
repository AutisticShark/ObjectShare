# Code audit, October 2026

This record covers the dependency refresh and code-quality audit of 2026-10-13.
Four reviews covered authentication and administration, uploads and storage,
billing, and configuration and the database layer. Each finding was checked
against the code before it was fixed, ruled out, or left open. Each fix is its
own commit; this file keeps the reasoning the commits do not, the maintainer's
decisions, and the items that are still open.

## Dependency updates

| Area | Update | Notes |
| --- | --- | --- |
| Go | 1.27.1 to 1.27.2 | `go.mod`, Dockerfile builder digest, Dockerfile frontend `docker/dockerfile:1.28` |
| Go modules | 30 modules | chi v5.4.0 fixes GHSA-j6qf-3m9c-vwj3 in `ClientIPFrom*`, which ObjectShare does not use. go-redis v9.23.0 adds a pipeline pool; ObjectShare uses no pipelines. |
| Frontend | Tabler 1.4.0 to 1.6.1, HTMX 2.0.10 to 2.0.11 | Every class and `--tblr-*` variable the templates use exists in Tabler 1.6.1. HTMX 4.0 is only on npm's `next` tag and is a breaking rewrite, so HTMX stays on 2.x. |
| Images | Redis 8.2.9 to 8.10.2, PostgreSQL 18.6 digest refresh | PostgreSQL 19 is still in beta. Back up `redis-data` before rolling Redis back: an older Redis cannot load a newer one's files. |
| Actions | `upload-artifact` v7.0.2, `download-artifact` v8.0.2 | Every other action was already at its latest release. |

`govulncheck` reports no reachable vulnerability. It lists GO-2026-5932
(`golang.org/x/crypto/openpgp` is unmaintained), which has no fix and is not
imported.

## Fixed

| Commit subject | Problem |
| --- | --- |
| fix: credit Stripe top-ups paid in a localized currency | With Adaptive Pricing on the pinned 2024-06-20 webhook schema, `currency` and `amount_total` are the customer's, so a paid top-up went to manual reconciliation. |
| fix: keep OAuth sign-ins signed in after the provider redirect | The SameSite=Strict JWT cookie set in the callback was not sent through the cross-site redirect chain, so users without MFA landed on the login form. |
| fix: send lockout and OAuth error pages with their status and headers | `WriteHeader` ran before `renderStatus`, so `no-store` was lost and every locked attempt logged a superfluous-call warning. |
| fix: accept recovery codes typed with capitals, spaces, or dashes | Exact matching rejected valid codes and counted toward the lockout. |
| fix: log MFA storage and key failures instead of reporting a wrong code | Database and settings-key failures were shown as an invalid code and never logged. |
| fix: keep canceled subscriptions from reviving on same-second events | A same-second `active` update delivered after a cancellation reactivated the subscription. |
| fix: show ended gateway subscriptions as expired on the billing page | The page said benefits were "paused because access is active". |
| fix: tell PayPal customers a pending capture is still processing | A pending capture showed "Internal server error", inviting a second payment. |
| fix: name an open provider subscription in the purchase conflict message | The message named only a gateway payment in progress. |
| fix: send download errors without the attachment headers | A busy cipher slot or decryption error was saved as the file. |
| fix: limit file update and delete bodies before the CSRF check | The 4 KiB limit was applied after the CSRF check had parsed the whole body. |
| fix: mention plan direct-link limits only when billing is enabled | Instances without plans told owners a plan governed their direct links. |
| fix: scope the CSP to the pinned jsDelivr packages | Scripts from any jsDelivr package were allowed. |
| fix: leave settings empty in .env.example so config.json keeps its values | Copying the example overrode a mounted `config.json` at the first import. |
| fix: document every parsed configuration variable in the README | Ten parsed variables were not documented. |
| fix: require the administrator's password to reset a password | A stolen administrator JWT alone could set any account's password. |
| fix: accept only card payments in Stripe Checkout | A delayed ACH or SEPA payment could settle after the checkout deadline and be paid twice. |
| fix: accept PayPal webhooks delivered up to 30 minutes late | Retries and delayed deliveries older than five minutes were refused. |
| fix: stop counting abandoned upload reservations after they expire | Abandoned reservations blocked new uploads with 413 or 429 until cleanup ran. |
| fix: greet SMTP servers with the sender's domain | `EHLO localhost` was rejected by relays that require a fully qualified name. |
| fix: wait briefly for the cipher slot instead of failing at once | A short overlap with another encrypted transfer failed a download or rolled back a whole batch. |
| fix: sign a banned account's browser out with the refusal | The browser got 403 on every page until its JWT expired. |
| fix: keep a sign-in when its last-login time cannot be recorded | A failed write after MFA returned 500 and wasted the code. |
| fix: stop claiming JWTs were invalidated when access did not change | The message was shown even when nothing changed. |
| fix: reject batch files with the same status and wording as single uploads | Batches showed raw validator text and 400 for oversized files. |
| chore: remove billing repository methods that nothing calls | Four methods had no production caller since earlier refactors. |

Most fixes have a regression test. These do not: the body-limit reorder, the
direct-link note, the ended-subscription label, the pending PayPal capture
message, the purchase conflict message, and the access message. Three of the
tests also guard against future drift: the CSP
must cover every CDN asset in `partials.html`, `.env.example` may set only
secrets and Compose topology, and every parsed variable must appear in the
README.

## Ruled out

- **A failed checkout creation blocks plan purchases until the checkout
  deadline.** This is deliberate. The README limits retries of a lost first
  gateway response to five minutes, within the providers' idempotency windows,
  and requires operator reconciliation before releasing an ambiguous
  reservation, so that a checkout that was created remotely cannot be charged
  twice.
- **A subscription conflict answers 500 instead of 422 with a reconciliation
  row.** Both providers retry any non-2xx response, and the code leaves the event
  unapplied on purpose so that a retry succeeds once the prepaid credit plan ends.
- **Proxied downloads are cut off by `ReadTimeout`.** Go clears the read deadline
  in `startBackgroundRead`, so the request context is not cancelled.

## Decisions

The maintainer decided these items after the first report:

- Administrator password resets require the acting administrator's password.
- Stripe Checkout accepts card payments only, including Apple Pay and Google
  Pay.
- PayPal webhooks are accepted up to 30 minutes after transmission.
- Downgrading after a dashboard save on a newer release is not supported. An
  older release may refuse the stored document because `OpenRuntime` uses
  `DisallowUnknownFields`; restore the pre-upgrade database backup instead. The
  README states this.
- A pending upload reservation is canceled five minutes after it expires and no
  longer counts against any quota.

## Still open

1. **PayPal declined captures.** `INSTRUMENT_DECLINED` still shows "Internal
   server error". PayPal recommends returning the buyer to the approval URL, but
   the capture request ID is reused (`capture-<order>`), and whether PayPal
   replays a cached failure for it is not documented.
2. **Migration locks.** Every start runs `ALTER TABLE ... ADD COLUMN IF NOT
   EXISTS` and full-table backfills inside one transaction (`db/db.go`). The
   ACCESS EXCLUSIVE locks block the other live replicas until it commits.
   Guarding each step with a cheap catalog or `EXISTS` check, or recording
   completed migrations, avoids this.
3. **Prepared statements during rolling deploys.** `PrepareStmt: true` with
   GORM's `SELECT *` makes PostgreSQL reject cached plans after a newer replica
   adds a column ("cached plan must not change result type"), and GORM evicts
   only on `driver.ErrBadConn`. Old replicas fail until their connections are
   recycled.
4. **Proxied upload spooling.** A proxied upload's body is spooled to disk
   before the CAPTCHA, guest-cap, and quota checks run, so a refused request can
   still make the server write up to `max_file_size` times
   `max_files_per_batch`. Rejecting a declared `Content-Length` above the
   remaining allowance, or checking the CAPTCHA token from a header first,
   would avoid it.

## Verification

- `go test -race -p 1 ./...` passed on every package, including the PostgreSQL
  integration tests against a local PostgreSQL 18 cluster. Running packages in
  parallel under the race detector ran out of Windows commit memory on the
  audit machine; that was an environment limit, not a test failure.
- `go vet`, gofmt on the normalized content, actionlint, and the Node frontend
  tests passed.
- Each commit was checked out separately and built, vetted, formatted, and
  unit-tested. The Node frontend tests, which the Go suite launches, failed
  intermittently in that loop while the machine had about 2 GB of commit memory
  left; no commit changes JavaScript or those tests, and the affected commit
  passed in two further full runs, as did twelve standalone Node runs.
- Seven new tests (Stripe localized currency, same-second cancellation, CSP
  coverage, `.env.example`, README coverage, expired reservations, and the SMTP
  greeting) were also checked by reverting their fix and confirming they fail.
- Not run locally: the Docker image build and the Compose smoke test, which CI
  runs.

## SonarCloud review, 2026-10-31

SonarCloud's automatic analysis of `fb01bda` failed the quality gate on one
low-severity vulnerability and listed 32 code smells. Three commits fix 15
findings: "chore: name literals that SonarCloud flagged as duplicated", "chore:
split the functions SonarCloud flagged as too complex" (six production
functions), and "chore: clear the remaining minor SonarCloud findings". Behavior
is unchanged.

The other 18 were closed on SonarCloud with these reasons:

- **`http://` in `healthURL` (go:S5332), false positive.** The container health
  probe calls the process's own listener on a loopback address.
- **Meta refresh in `oauth_continue.html`, accepted.** It starts the same-site
  navigation that carries the SameSite=Strict JWT cookie after an OAuth callback
  (see the OAuth fix above).
- **`await` in a loop in `upload.js`, accepted.** A batch is sent one file at a
  time, each with a freshly renewed short-lived URL.
- **`!important` in `branding.css`, accepted.** It overrides Tabler's
  `!important` `.ms-auto` utility.
- **`checkoutWindowGateway` interface name, accepted.** The `-er` form would be
  less clear.
- **Repeated `"id = ?"` in `db/invoice.go`, accepted.** It is the idiomatic GORM
  condition.
- **Cognitive complexity of 11 test functions, accepted.** They are
  table-driven scenarios; splitting them would not improve coverage.
