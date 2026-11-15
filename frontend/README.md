# Frontend

ObjectShare's web interface is a Svelte 5 application built with Vite 8 and
type-checked with TypeScript 7. Tabler supplies the underlying UI styles; the
workspace layout and components live in `src/`. The build output in `dist/` is
embedded in the Go executable and served under `/assets/frontend/`. There is no
Node.js service in production, and the interface requires JavaScript.

## Build and check

From the repository root, using Node.js 26 LTS and npm:

```sh
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run check
npm --prefix frontend test
npm --prefix frontend run build
go run . -config config.json
```

`dev` runs Vite's build watcher. Rebuild Go after a frontend rebuild so the
executable embeds the new assets. Generated files in `dist/` are not committed
(only `dist/.gitkeep`, which the Go embed needs). Docker and binary-release
workflows build them before compiling Go. A binary built without them refuses to
start the server and prints the build command.

The type checker runs **TypeScript 7.0.2** over both `.ts` files and the generated
TypeScript representation of every Svelte component. Svelte's current
`svelte2tsx` adapter still uses TypeScript 6's compiler API to produce that
representation. Its compatibility dependency is isolated in the
`tools/svelte-types` workspace; it does not replace the TypeScript 7 checker or
ship in browser assets. The temporary `.check/` directory is removed after checks.
Svelte compiler warnings fail the check as well.

## Server boundary

- Go handlers own every route, authorization check, JWT authentication, CSRF
  check, form validation, and payment step.
- Each HTML response is a minimal shell: document metadata, the bundle, an empty
  `#objectshare-app` mount point, a `<noscript>` notice, and the page data as
  inert, HTML-escaped JSON. Nothing else is rendered on the server, so no
  server markup can appear before the interface starts. Signed-in pages carry the
  saved theme on `<html>`; guests follow the system theme through CSS.
- Database models have explicit public projections: password hashes, JWTs, owner
  tokens, stored MFA secrets, and verification hashes must never be serialized.
  Administrator configuration is redacted before serialization. MFA enrollment
  keys and newly issued recovery codes appear only on their authorized, uncached
  result page.
- Forms marked `data-enhance` submit with `fetch` (`src/lib/submit.ts`). A
  returned page renders in place, a redirect becomes a normal navigation, and a
  plain-text error appears in the submitting form. Other forms post natively.
- Links are ordinary page loads. The bundle is render-blocking, so the empty
  shell never paints, and a cross-document view transition fades between pages.
- The encryption, sharing, upload-recovery, CAPTCHA, and dialog controllers live
  in `src/controllers/` and are bundled at build time. They are not evaluated as
  strings at runtime. Document/window listeners are scoped to each mounted page
  and removed when that page is replaced.
- The Content Security Policy allows scripts, styles, and fonts only from the
  site itself and never needs `unsafe-inline` or `unsafe-eval`.
- No third-party CDN or web font is loaded. Configured branding images, direct
  object-storage transfers, and an enabled Turnstile widget retain their
  existing explicitly allowed external origins.

When adding a page, add its Svelte view and TypeScript contract, route it in
`App.svelte`, and review its backend projection. Keep security constraints on the
server. New user-visible features must also update the root README roadmap.

## Browser tests

The Playwright suite creates the first administrator, uploads and deletes fixture
files, changes configuration, records test account credit, and buys a test plan.
**Use a new disposable database and a loopback-only test application.** The suite
refuses an installation whose setup is already complete. It does not contact
payment gateways or email providers.

```sh
# Start ObjectShare with an empty disposable PostgreSQL database first.
# Install the test browser once (or use an installed Edge with the channel below).
npm --prefix frontend exec -- playwright install chromium
OBJECTSHARE_E2E_ORIGIN=http://127.0.0.1:8192 \
OBJECTSHARE_E2E_ALLOW_SETUP=1 \
npm --prefix frontend run test:e2e
```

`OBJECTSHARE_BROWSER_CHANNEL=msedge` selects an installed Microsoft Edge. Otherwise
Playwright runs its full Chromium build in new headless mode, not the headless
shell, whose frame scheduling hides first-paint regressions. CI provisions a disposable application with
`scripts/test-e2e.sh` and runs the same suite. Browser traces and screenshots
remain in ignored `frontend/test-results/`.

Coverage includes desktop/narrow layouts, light/dark themes, the first paint while
the bundle is still loading, keyboard navigation, the no-JavaScript notice, form
validation, account management, MFA, settings activation, credit invoices/PDFs,
owner-only file operations, browser encryption, and key-fragment decryption in a
separate browser context. Emulated narrow viewports are not a substitute for
checking touch behavior, safe areas, and the software keyboard on a physical
phone.
