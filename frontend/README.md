# Frontend

ObjectShare uses Svelte 5, Vite 8, and TypeScript 7. Tabler supplies the underlying
UI styles; the workspace layout and components live in `src/`. Assets are bundled
locally, embedded in the Go executable, and served under `/assets/frontend/`.
There is no Node.js service in production.

## Build and check

From the repository root, using Node.js 26 LTS and npm:

```sh
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run check
npm --prefix frontend test
npm --prefix frontend run build
go run . -config config.json
```

`dev` runs Vite's build watcher. Restart/rebuild Go after a frontend rebuild so the
executable embeds the new assets. Generated files in `template/frontend/` are not
committed. Docker and binary-release workflows build them before compiling Go.
An unbuilt source checkout continues to serve the server-rendered native forms.

The type checker runs **TypeScript 7.0.2** over both `.ts` files and the generated
TypeScript representation of every Svelte component. Svelte's current
`svelte2tsx` adapter still uses TypeScript 6's compiler API to produce that
representation. Its compatibility dependency is isolated in the
`tools/svelte-types` workspace; it does not replace the TypeScript 7 checker or
ship in browser assets. The temporary `.check/` directory is removed after checks.
Svelte compiler warnings fail the check as well.

## Server boundary

- Go handlers retain the existing routes, authorization, JWT authentication,
  CSRF checks, form validation, payment processing, and native-form fallbacks.
- Each HTML response contains inert, HTML-escaped JSON page data. Database models
  have explicit public projections: password hashes, JWTs, owner tokens, stored
  MFA secrets, and verification hashes must never be serialized. Administrator
  configuration is redacted before serialization. MFA enrollment keys and newly
  issued recovery codes appear only on their authorized, uncached result page.
- Svelte owns page markup and layout. HTMX submits enhanced forms; the entry point
  renders returned page data into Svelte rather than swapping the fallback HTML.
  Redirects still perform a normal navigation. Plain-text form errors remain
  visible in the submitting form.
- Existing encryption, sharing, upload-recovery, CAPTCHA, and dialog controllers
  are bundled directly from `template/` at build time. They are not copied or
  evaluated as strings at runtime. Document/window listeners are scoped to each
  mounted page and removed when that page is replaced.
- HTMX evaluation, response-script execution, and injected indicator styles are
  disabled. The Content Security Policy does not require `unsafe-inline` or
  `unsafe-eval`. Build tools may still report HTMX's unused evaluation code.
- Tabler and HTMX need no third-party CDN or web font. Configured branding images,
  direct object-storage transfers, and an enabled Turnstile widget retain their
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
Playwright uses its Chromium build. CI provisions a disposable application and
runs the same suite. Browser traces and screenshots remain in ignored
`frontend/test-results/`.

Coverage includes desktop/narrow layouts, light/dark themes, keyboard navigation,
no-JavaScript forms, form validation, account management, settings activation,
credit invoices/PDFs, owner-only file operations, browser encryption, and
key-fragment decryption in a separate browser context. Emulated narrow viewports
are not a substitute for checking touch behavior, safe areas, and the software
keyboard on a physical phone.
