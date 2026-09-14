# Production readiness

ObjectShare's release target is a turnkey file-sharing website with clear upload
and sharing workflows, familiar billing, and dedicated administration. Passing
unit tests alone does not establish that target. This checklist records the
required product behavior and the evidence needed before a production release.

## Product acceptance

| Area | Required behavior | Current evidence and remaining work |
| --- | --- | --- |
| Navigation | A user can find uploads, their files, billing, account settings, and permitted administration from the main workflows. | Shared signed-in navigation now includes file details as well as the workspace pages. Server-rendered templates are tested. Local Edge checks cover billing navigation, keyboard activation of plan comparison, invoice history and return links, and file search. The full desktop, mobile, and keyboard matrix remains open. |
| Upload and sharing | Users can choose files, understand limits and access, track progress, recover from failures, and send a usable sharing link. | File selection and encryption tests cover single/batch modes, limits, and ciphertext. HTTP tests cover private access and owner isolation. Direct batches retain per-file completion and can retry transfers or lost completion responses using the same reservations and ciphertext while the page remains open. Automated fault-injection tests cover both failures. Browser verification and durable recovery across page reloads remain open; proxied uncertain responses require checking My files before retrying. |
| Encryption onboarding | New account users can set up and back up their key, upload, download, and share without exposing their account key or passphrase. | Automated cryptographic and authorization tests exist. Verify the complete workflow in a browser with a second account and a guest recipient, including a wrong passphrase and a restored key backup. |
| Billing | Prices and plan duration are clear; users review an invoice, pay once, see the resulting balance and benefits, and retrieve receipts. | Local PostgreSQL and HTTP checks exercise invoice-first credit payment, insufficient credit, replay protection, and private PDFs. Browser form failures retain their error status and link back to billing. Paid receipts distinguish disabled email from queued delivery. Real gateway acceptance remains unverified. |
| Administration | Administrators can navigate configuration, accounts, moderation, quotas, plans, invoices, and operational status without gaining unauthorized file access. | New overview and invoice queries have PostgreSQL tests; role boundaries and rendered pages have handler tests. Verify configuration forms and account actions in the browser, including long lists and narrow screens. |
| Error handling | A failed page or payment must not look successful or encourage an unsafe duplicate purchase. | Template output is buffered before committing HTTP headers. Tests reject partial output, raw error disclosure, and incorrect success status. Billing form errors provide recovery links while API clients retain plain-text errors and HTTP status codes. |

## Deployment acceptance

These checks require a staging deployment representative of the intended
production environment. Use test accounts, synthetic files, gateway sandbox
credentials, and a disposable database. Do not infer provider success from an
enabled configuration indicator.

New installations copied from `.env.example` publish the application on
`127.0.0.1:8080` for first-time setup. Existing `.env` bindings remain in effect.
Run `docker compose config --quiet` before startup, complete administrator setup
through localhost or a tunnel, then configure the public HTTPS proxy.

- [ ] Start the published container and Compose configuration from a fresh volume;
  complete administrator bootstrap and configure the public site through the UI.
- [ ] Upgrade a populated installation without losing users, files, invoice terms,
  configuration values, encryption vaults, or token invalidation behavior.
- [ ] Validate the public HTTPS origin, secure cookies, CSRF, reverse-proxy client
  addresses, CAPTCHA, and rate limits through the deployed proxy.
- [ ] Send verification and paid-invoice emails through the chosen provider;
  inspect links and attached PDFs in a real mailbox.
- [ ] Complete Stripe and/or PayPal sandbox checkout, cancellation, delayed
  confirmation, and webhook replay. Confirm one settlement and the correct
  invoice, balance, and plan. Check ambiguous payments before retrying them.
- [ ] Upload and download through the selected object store. For large proxied
  deployments, verify direct-upload CORS, authorization expiry, completion, and
  restricted-file downloads using the real public origin.
- [ ] Verify partial batches, interrupted connections, expired authentication,
  and server restarts during upload and payment. Include provider PUT requests
  still in flight when cancellation or authorization expiry starts cleanup.
- [ ] Test multiple replicas sharing the database and storage, including runtime
  configuration reload and background work ownership.
- [ ] Run race/concurrency checks and a realistic storage, upload, and list-page
  load test with the intended limits.
- [ ] Restore database, objects, settings secret, and required encryption metadata
  to an isolated environment, then download an existing encrypted file and inspect
  a paid invoice. Confirm the operator has retained the required key backups.
  Follow the [backup and restore runbook](backup-and-restore.md).
- [ ] Complete browser checks at desktop and narrow widths in light and dark
  themes: navigation, focus visibility, labels, file selection, drag-and-drop,
  encryption, sharing, checkout, administrator dialogs, and error recovery.

## Local verification

Run the ordinary Go suite, JavaScript checks, vet, and build:

```text
go test -mod=mod ./...
node --test tests/client-encryption.test.cjs tests/upload-selection.test.cjs tests/sharing.test.cjs tests/theme.test.cjs tests/admin-users.test.cjs
go vet -mod=mod ./...
go build -mod=mod ./...
git diff --check
```

Set `OBJECTSHARE_TEST_POSTGRES_DSN` to a disposable PostgreSQL instance to enable
the database integration tests. They create their own isolated schemas; without
that variable those tests are skipped. The Go test suite runs the JavaScript
tests when Node is available. On Windows, use workspace-local `GOCACHE` and
`GOMODCACHE` directories when the default cache location is unavailable.

The CI Go job provisions a disposable PostgreSQL service and supplies
`OBJECTSHARE_TEST_POSTGRES_DSN` to the race-enabled suite, so integration tests
do not silently skip for lack of a database. It also requires Node to be present
before running the suite. These CI service settings require no repository secrets;
the checked-in password belongs only to the disposable test database. The workflow
was checked with actionlint; actual service-container startup still requires a CI run.

The CI container job loads the newly built image, generates ephemeral bootstrap
secrets, and starts a uniquely named Compose project on loopback. Its installation
smoke check bootstraps a synthetic administrator, renders admin/workspace pages,
stores and decrypts a private encrypted file, denies guest access, restarts the app,
and verifies that the administrator, JWT, vault, metadata, and stored bytes remain
usable. The job collects failure diagnostics and removes only its disposable
project volumes. The same smoke logic passed locally using a fresh PostgreSQL
database and native application process, including a real process restart.
Loopback target guards and rejection of an already initialized site also passed.
The workflow passed actionlint; Docker image startup, container restart, and volume
ownership remain unverified until the container job actually runs.

The full local suite passed `go test -mod=mod -race -count=1 ./...` with
`OBJECTSHARE_TEST_POSTGRES_DSN` set to the disposable PostgreSQL instance.
This run used Go 1.27.1 on Windows/amd64, CGO enabled, and the upstream
LLVM-MinGW 20260908 toolchain (Clang 23.1.1), whose archive SHA-256 was checked
against the release metadata before extraction. The compiler and caches remain
under ignored `.tmp` directories; application dependencies were not changed.
Set `CC` to `x86_64-w64-mingw32-clang.exe` and add that toolchain's `bin` directory
to the process `PATH` when reproducing this Windows run. The installed Zig 0.16.0
compiler could not link the required synchronization library and was not used
for the passing run. See the [Go race detector requirements](https://go.dev/doc/articles/race_detector)
and the [LLVM-MinGW release](https://github.com/mstorsjo/llvm-mingw/releases/tag/20260908).
No data races were reported by the exercised tests. This does not establish
production load capacity or multi-replica/provider behavior.

The optional [workspace benchmark](workspace-performance.md) passed with 5,000
accounts, 50,000 file records, and 25,000 invoices. Serial query means in the local
100-operation baseline ranged from 1.42 to 12.47 ms; mixed reads also passed with
12 workers. The full database suite and mixed-read benchmark passed under the
race detector after adding this fixture. These query-only measurements do not
complete the staging load-test gate.

The current local evidence includes PostgreSQL integration tests and HTTP checks
against the application with synthetic accounts, plans, invoices, and files.
A local dump/restore drill matched all 15 application tables and three copied
objects, opened restored runtime settings with the retained key, decrypted a
private encrypted fixture with its restored vault/metadata, and regenerated a
paid-invoice PDF. The restored application then started on an isolated localhost
port with copied objects, disabled external providers, and a new JWT secret. HTTP
checks verified existing-user login, Files/Billing/Invoices, private owner download
and decryption, guest and administrator authorization boundaries, and JWT isolation
from the source preview. The one-page invoice PDF passed visual inspection.
The deployed restore and browser acceptance gate remains open.
Build-context exclusions passed 19 cases using Moby patternmatcher v0.6.1,
including nested environment secrets and retained build inputs. Compose-go
v2.15.0 interpolation and port parsing passed six cases for the loopback example,
existing bare ports, explicit public and IPv6 bindings, and the unset fallback.
These libraries were used only in an ignored local verification module. Docker
is unavailable in the local environment; parser checks do not prove container
startup, runtime port exposure, volume permissions, or migration behavior.
Administrator directory tests cover bounded pagination, literal text and exact-ID
search, role/moderation/verification filters, global totals, secret-column
exclusion, administrator authorization, and preservation of search context after
enhanced actions. Live administrator browser checks remain unverified.
Upload lifecycle tests cover competing completion/deletion database transitions,
stale cancellation and expiry reads, and failed object deletion followed by
cleanup retry. These checks cover both direct completion and proxied finalization;
provider requests already in flight still require deployment verification.
The sharing workspace has local Edge checks for account registration, encryption
setup, saved-access guidance, unsaved changes, HTMX validation, wrong passphrases,
encrypted-link generation, and copying. Desktop light/dark presentation and a
390-pixel mobile viewport were inspected; the mobile page had no horizontal
overflow. The encrypted fixture for sharing-page checks was created through the
local API. Browser file selection remains unverified because the extension denied
file access. Recipient browser access after expanding the fixture's permissions
awaits explicit approval; automated tests still cover server authorization and
decryption with the generated per-file key.
The shared theme toggle applies the persisted preference in place with HTMX.
Local Edge verification confirmed that changing the theme preserves the current
sharing URL, an unsaved recipient list, and the saved-access warning. Native form
fallback retains the existing My account redirect. Automated tests cover CSRF,
success events, error feedback, and the guest system-theme behavior.
Local Edge checks also cover the billing overview at desktop and 390-pixel widths,
the plan catalog, empty invoice history, and file-search results. The empty invoice
history previously clipped its guidance inside a horizontally scrolling table;
it now uses a dedicated empty state with a plan link. A later empty page explains
how to return to the latest invoices. Both return navigation and the corrected
390-pixel layout were verified; the empty page has no horizontal overflow.
The invoice-review submission was blocked by Edge with `ERR_BLOCKED_BY_CLIENT`,
so that browser path and checkout remain unverified. The test account's invoice
history remained empty afterward. No browser payment was performed.
These checks do not establish all browser workflows, actual provider delivery,
container operation, or staging readiness. Re-run the applicable checks against the exact release
build; treat the unchecked deployment items as open release gates.
