import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { createHmac, randomBytes } from 'node:crypto';

test.describe.configure({ mode: 'serial' });
const runtimeErrors = new WeakMap<Page, string[]>();

const email = `frontend-${randomBytes(6).toString('hex')}@example.test`;
const password = randomBytes(24).toString('hex');
let state: Awaited<ReturnType<APIRequestContext['storageState']>>;
const csrf = (html: string) => {
  const token = html.match(/name="csrf_token" value="([^"]+)"/);
  if (!token) throw new Error('Expected a native CSRF-protected form.');
  return token[1];
};
const shell = (page: Page) => expect(page.locator('#objectshare-app .app-shell')).toBeVisible();
async function expectNoOverflow(page: Page, route: string) {
  const layout = await page.evaluate(() => ({
    width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
    outside: [...document.querySelectorAll<HTMLElement>('body *')].filter(element => {
      const bounds = element.getBoundingClientRect();
      return bounds.width > 0 && (bounds.right > innerWidth + 1 || bounds.left < -1);
    }).slice(0, 15).map(element => ({ tag: element.tagName, class: element.className, width: element.getBoundingClientRect().width, right: element.getBoundingClientRect().right })),
  }));
  expect(layout.scrollWidth, `${route}: ${JSON.stringify(layout)}`).toBeLessThanOrEqual(layout.width);
}

async function login(request: APIRequestContext) {
  const page = await request.get('/login');
  const response = await request.post('/login', { form: { csrf_token: csrf(await page.text()), email, password }, maxRedirects: 0 });
  expect([204, 303]).toContain(response.status());
  state = await request.storageState();
}

test.beforeAll(async ({ request, baseURL }) => {
  expect(process.env.OBJECTSHARE_E2E_ALLOW_SETUP).toBe('1');
  const origin = new URL(baseURL!);
  expect(['127.0.0.1', 'localhost', '[::1]']).toContain(origin.hostname);
  expect(origin.protocol).toBe('http:');
  const setup = await request.get('/setup', { maxRedirects: 0 });
  expect(setup.status(), 'Use a fresh disposable database, never an existing installation.').toBe(200);
  const created = await request.post('/setup', { form: {
    csrf_token: csrf(await setup.text()), display_name: 'Cat', email, password, password_confirm: password,
  }, maxRedirects: 0 });
  expect(created.status()).toBe(303);
  state = await request.storageState();
});

test.beforeEach(async ({ context, page, request }) => {
  await login(request);
  await context.addCookies(state.cookies);
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|unsafe-eval/i.test(message.text())) errors.push(message.text()); });
  runtimeErrors.set(page, errors);
});

test.afterEach(async ({ page }) => {
  expect(runtimeErrors.get(page) ?? []).toEqual([]);
});

test('every workspace renders in light, dark, and narrow layouts without external assets', async ({ page, baseURL }, info) => {
  const external: string[] = [];
  page.on('request', request => { if (new URL(request.url()).origin !== new URL(baseURL!).origin) external.push(request.url()); });
  for (const route of ['/', '/files', '/account', '/account/mfa', '/billing', '/plans', '/invoices', '/admin', '/admin/users', '/admin/plans', '/admin/invoices', '/admin/settings']) {
    await page.goto(route);
    await shell(page);
    await expect(page.locator('h1')).toHaveCount(1);
    await expectNoOverflow(page, route);
  }
  await page.goto('/');
  await shell(page);
  await page.screenshot({ path: info.outputPath('upload-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', 'dark');
  await expect(page.locator('#file')).toBeEnabled();
  await page.screenshot({ path: info.outputPath('upload-dark.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', 'light');
  await page.setViewportSize({ width: 390, height: 844 });
  for (const route of ['/', '/files', '/account', '/admin/users', '/admin/settings']) {
    await page.goto(route);
    await shell(page);
    await expectNoOverflow(page, route);
  }
  await page.goto('/');
  await shell(page);
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await expect(page.locator('#workspace-sidebar')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#workspace-sidebar')).toBeHidden();
  await page.screenshot({ path: info.outputPath('upload-mobile.png'), fullPage: true });
  expect(external).toEqual([]);
});

test('upload, search, rename, sharing, and deletion preserve owner permissions', async ({ page }) => {
  await page.goto('/');
  await shell(page);
  await page.locator('#file').setInputFiles({ name: 'project-notes.txt', mimeType: 'text/plain', buffer: Buffer.from('ObjectShare browser upload fixture\n') });
  await expect(page.locator('#file-selection')).toContainText('project-notes.txt');
  await page.getByRole('button', { name: 'Switch to dark theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', 'dark');
  expect(await page.locator('#file').evaluate((input: HTMLInputElement) => input.files?.length)).toBe(1);
  await expect(page.locator('#file-selection')).toContainText('project-notes.txt');
  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', 'light');
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page).toHaveURL(/\/file\/[0-9a-f-]+$/);
  await shell(page);
  await expect(page.locator('h1')).toHaveText('project-notes.txt');
  const fileURL = page.url();
  await page.locator('input[name="name"]').fill('renamed-notes.txt');
  await page.getByRole('button', { name: 'Rename', exact: true }).click();
  await expect(page.locator('h1')).toHaveText('renamed-notes.txt');
  await page.getByRole('link', { name: 'Sharing & permissions' }).click();
  await shell(page);
  await page.locator('#share-mode').selectOption('private');
  await expect(page.locator('#unsaved-sharing')).toBeVisible();
  await page.getByRole('button', { name: 'Save permissions' }).click();
  await expect(page.locator('#saved-access')).toContainText('Only you');
  const guest = await page.request.get(fileURL, { headers: { Cookie: '' } });
  expect(guest.status()).toBe(404);
  await page.goto('/files');
  await shell(page);
  await page.locator('input[name="q"]').fill('renamed-notes');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await shell(page);
  await expect(page.locator('tbody')).toContainText('renamed-notes.txt');
  await page.goto(fileURL);
  await shell(page);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(page).not.toHaveURL(fileURL);
});

test('HTMX validation keeps the Svelte interface and password fields out of page data', async ({ browser, baseURL }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(baseURL + '/login');
  await shell(page);
  await page.locator('#email').fill(email);
  await page.locator('#password').fill('wrong-password');
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
  await expect(page.locator('[role="alert"]')).toBeVisible();
  await shell(page);
  expect(await page.locator('#password').inputValue()).toBe('');
  const html = await (await context.request.get(baseURL + '/login')).text();
  expect(html).not.toContain('PasswordHash');
  await context.close();
});

test('administrator dialogs, settings round-trip, plans, and credit invoices work', async ({ page }) => {
  const name = 'A long account name 測試 — ' + 'x'.repeat(45);
  await page.goto('/admin/users');
  await shell(page);
  await page.getByRole('button', { name: 'Create user', exact: true }).first().click();
  const create = page.locator('#create-user');
  await expect(create).toBeVisible();
  await create.locator('[name="display_name"]').fill(name);
  await create.locator('[name="email"]').fill('new-user@example.test');
  await create.locator('[name="password"]').fill(password);
  await create.locator('[name="password_confirm"]').fill('mismatch-password');
  await create.getByRole('button', { name: 'Create user', exact: true }).click();
  await expect(page.locator('#create-user[open] [role="alert"]')).toBeVisible();
  await shell(page);
  await create.locator('[name="display_name"]').fill(name);
  await create.locator('[name="email"]').fill('new-user@example.test');
  await create.locator('[name="password"]').fill(password);
  await create.locator('[name="password_confirm"]').fill(password);
  await create.getByRole('button', { name: 'Create user', exact: true }).click();
  await expect(page.locator('tbody')).toContainText(name);
  await page.getByRole('button', { name: `Manage ${email}`, exact: true }).click();
  const dialog = page.locator('dialog[open]');
  await dialog.locator('[name="credit_delta"]').fill('100');
  await dialog.locator('[name="credit_description"]').fill('Browser integration fixture');
  await dialog.getByRole('button', { name: 'Record adjustment' }).click();
  await expect(page.locator('tbody')).toContainText('100 credits');
  await page.goto('/admin/settings');
  await shell(page);
  await expect(page.locator('[name="rate_limit_window"]')).toHaveValue(/m|s/);
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.locator('.status-banner')).toContainText('Configuration saved and activated');
  await shell(page);
  await expect(page.locator('[name="rate_limit_window"]')).toHaveValue(/m|s/);
  await expect(page.locator('[name="email_smtp_password"]')).toHaveValue('');
  await page.goto('/admin/plans');
  await shell(page);
  const form = page.locator('form[action="/admin/plans"]');
  await form.locator('[name="name"]').fill('Studio');
  await form.locator('[name="storage_quota_gib"]').fill('10');
  await form.locator('[name="price"]').fill('10');
  await form.getByRole('button', { name: 'Add plan' }).click();
  await shell(page);
  await page.goto('/plans');
  await shell(page);
  await page.getByRole('button', { name: 'Review invoice' }).click();
  await expect(page).toHaveURL(/\/invoices\/[0-9a-f-]+$/);
  await shell(page);
  await page.getByRole('button', { name: 'Pay 10 credits from account' }).click();
  await shell(page);
  await expect(page.locator('.invoice-document')).toContainText('Payment confirmed');
  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download PDF' }).click();
  expect((await download).suggestedFilename()).toMatch(/\.pdf$/);
});

test('encrypted upload and key-fragment download round-trip in the browser', async ({ page, browser }) => {
  await page.goto('/account');
  await shell(page);
  const passphrase = 'A browser-only encryption passphrase 2026';
  const setup = page.locator('#encryption-setup');
  await setup.locator('#encryption_passphrase').fill(passphrase);
  await setup.locator('#encryption_confirm').fill(passphrase);
  const backup = page.waitForEvent('download');
  await setup.getByRole('button', { name: 'Generate account key' }).click();
  expect((await backup).suggestedFilename()).toBe('objectshare-encrypted-key.json');
  await expect(setup.locator('[role="status"]')).toContainText('Encryption key created');
  await page.goto('/');
  await shell(page);
  await page.locator('#encrypt-files').check();
  await page.locator('#encryption-passphrase').fill(passphrase);
  await page.locator('#file').setInputFiles({ name: 'encrypted-note.txt', mimeType: 'text/plain', buffer: Buffer.from('Authenticated browser encryption fixture\n') });
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page).toHaveURL(/\/file\/[0-9a-f-]+$/);
  await shell(page);
  await page.getByRole('link', { name: 'Sharing & permissions' }).click();
  await shell(page);
  await page.locator('#share-passphrase').fill(passphrase);
  await page.getByRole('button', { name: 'Create sharing link', exact: true }).click();
  await expect(page.locator('#share-url')).toHaveValue(/#key=/);
  const shareURL = await page.locator('#share-url').inputValue();
  const guest = await browser.newContext();
  const recipient = await guest.newPage();
  await recipient.goto(shareURL);
  await shell(recipient);
  await expect(recipient).not.toHaveURL(/#key=/);
  const decrypted = recipient.waitForEvent('download');
  await recipient.getByRole('button', { name: 'Decrypt & download', exact: true }).click();
  const file = await decrypted;
  expect(file.suggestedFilename()).toBe('encrypted-note.txt');
  const stream = await file.createReadStream();
  const chunks = [];
  for await (const chunk of stream!) chunks.push(chunk);
  expect(Buffer.concat(chunks).toString()).toBe('Authenticated browser encryption fixture\n');
  await guest.close();
});

test('MFA enrollment and recovery-code sign-in retain the authentication boundary', async ({ page, browser, baseURL }) => {
  await page.goto('/account/mfa');
  await shell(page);
  await expect(page.locator('[name="current_password"]')).toBeVisible();
  await page.locator('[name="current_password"]').fill(password);
  await page.getByRole('button', { name: 'Set up authenticator app' }).click();
  const secret = (await page.locator('.auth-panel code').textContent())!.trim();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...secret].map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('');
  const key = Buffer.from(bits.match(/.{8}/g)!.map(byte => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const code = ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
  key.fill(0);
  await page.locator('[name="code"]').fill(code);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  const recovery = await page.locator('.auth-panel code').allTextContents();
  expect(recovery).toHaveLength(10);
  const guest = await browser.newContext();
  const loginPage = await guest.newPage();
  await loginPage.goto(baseURL + '/login');
  await shell(loginPage);
  await loginPage.locator('#email').fill(email);
  await loginPage.locator('#password').fill(password);
  await loginPage.getByRole('button', { name: 'Log in', exact: true }).click();
  await expect(loginPage.getByRole('heading', { name: 'Two-step verification' })).toBeVisible();
  await shell(loginPage);
  await loginPage.locator('[name="code"]').fill(recovery[0]);
  await loginPage.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(loginPage).toHaveURL(/\/account$/);
  await guest.close();
  await page.goto('/account/mfa');
  await shell(page);
  await expect(page.getByText('9 recovery codes remain.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disable MFA', exact: true }).click();
  await page.locator('[name="code"]').fill(recovery[1]);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toBeVisible();
});

test('native forms remain usable without JavaScript', async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, storageState: state });
  const page = await context.newPage();
  await page.goto(baseURL + '/');
  await expect(page.locator('form[action="/api/v1/upload"]')).toBeVisible();
  await page.goto(baseURL + '/account');
  await expect(page.locator('form[action="/account/profile"]')).toBeVisible();
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await expect(page.getByText('Profile updated.', { exact: true })).toBeVisible();
  await context.close();
});
