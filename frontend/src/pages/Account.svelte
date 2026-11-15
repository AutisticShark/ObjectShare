<script lang="ts">
  import Form from '../components/Form.svelte';
  import BillingSummary from './BillingSummary.svelte';
  import type { AccountPageData } from '../lib/pages';

  let { data }: { data: AccountPageData } = $props();
  const files = $derived(data.Files ?? []);
  const providers = $derived(data.OAuthProviders ?? []);
  const mfaMethod = $derived(data.User.MFA?.Method ?? '');
</script>

<section class="panel">
  <div class="section-heading"><h2>Email verification</h2></div>
  {#if data.User.EmailVerifiedAt}
    <p class="mb-0"><span class="badge bg-green-lt">Verified</span> {data.User.Email}</p>
  {:else}
    <p><span class="badge bg-yellow-lt">Unverified</span> {data.User.Email}</p>
    <p>Verify your address using the link in your email. Changing your email requires verification again.{data.VerificationPurchases ? ' Verification is required before purchasing a plan.' : ''}{data.VerificationUploads ? ' Verification is required before uploading files to your account.' : ''}</p>
    {#if data.VerificationEnabled}
      <Form action="/account/email/resend" csrf={data.CSRF}>
        <button class="btn btn-primary" type="submit">Send verification email</button>
        <div class="form-hint mt-2">Links expire after 24 hours. Wait one minute between requests; a new link replaces the previous one.</div>
      </Form>
    {:else}
      <p class="text-secondary mb-0">Email verification is not configured. Contact the administrator if you need to verify your account.</p>
    {/if}
  {/if}
</section>

<section class="panel">
  <div class="section-heading"><h2>Multi-factor authentication</h2></div>
  <p>
    {#if mfaMethod}Enabled with {mfaMethod === 'totp' ? 'an authenticator app' : 'email codes'}.{:else}Add a second verification step to password and OAuth sign-ins using email codes or an authenticator app.{/if}
  </p>
  <div class="actions"><a class="btn btn-primary" href="/account/mfa">Manage multi-factor authentication</a></div>
</section>

<BillingSummary {data} />

<section class="panel">
  <div class="section-heading"><h2>Profile</h2></div>
  <Form action="/account/profile" csrf={data.CSRF} class="form-grid">
    <div class="field">
      <label class="form-label" for="display-name">Display name</label>
      <input class="form-control" id="display-name" name="display_name" value={data.User.DisplayName} maxlength="100" required>
    </div>
    <div class="field">
      <label class="form-label" for="email">Email</label>
      <input class="form-control" id="email" name="email" type="email" value={data.User.Email} maxlength="320" required>
    </div>
    {#if data.HasPassword}
      <div class="field">
        <label class="form-label" for="profile-current-password">Current password</label>
        <input class="form-control" id="profile-current-password" name="current_password" type="password" autocomplete="current-password" maxlength="512">
        <small class="form-hint">Required only to change your email address.</small>
      </div>
    {:else}
      <small class="form-hint">To change your email address, sign out and sign in again, then save within five minutes.</small>
    {/if}
    <div class="actions"><button class="btn btn-primary" type="submit">Save profile</button></div>
  </Form>
</section>

<section class="panel">
  <div class="section-heading"><h2>{data.HasPassword ? 'Change password' : 'Set a password'}</h2></div>
  <Form action="/account/password" csrf={data.CSRF} class="form-grid">
    {#if data.HasPassword}
      <div class="field">
        <label class="form-label" for="current-password">Current password</label>
        <input class="form-control" id="current-password" name="current_password" type="password" autocomplete="current-password" required>
      </div>
    {:else}
      <p class="text-secondary">Add a password if you also want to log in with your email address.</p>
    {/if}
    <div class="field">
      <label class="form-label" for="password">New password</label>
      <input class="form-control" id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="512" required>
    </div>
    <div class="field">
      <label class="form-label" for="password-confirm">Confirm new password</label>
      <input class="form-control" id="password-confirm" name="password_confirm" type="password" autocomplete="new-password" minlength="12" maxlength="512" required>
    </div>
    <div class="actions"><button class="btn btn-primary" type="submit">{data.HasPassword ? 'Change password' : 'Set password'}</button></div>
  </Form>
</section>

<section class="panel">
  <div class="section-heading"><h2>Appearance</h2></div>
  <Form action="/account/theme" csrf={data.CSRF} class="form-grid">
    <div class="field">
      <label class="form-label" for="theme">Theme</label>
      <select class="form-select" id="theme" name="theme">
        <option value="light" selected={!data.User.DarkMode}>Light</option>
        <option value="dark" selected={data.User.DarkMode}>Dark</option>
      </select>
      <div class="form-hint">Your choice is saved to your account and follows you across browsers.</div>
    </div>
    <div class="actions"><button class="btn btn-primary" type="submit">Save appearance</button></div>
  </Form>
</section>

{#if providers.length}
  <section class="panel">
    <div class="section-heading"><h2>OAuth login</h2></div>
    <ul class="list-unstyled mb-0">
      {#each providers as provider (provider.Key)}
        <li class="d-flex flex-wrap align-items-center justify-content-between gap-2 py-2">
          <div>
            <div class="fw-bold">{provider.Label}</div>
            <div class="text-secondary small">{provider.Linked ? 'Linked to this account' : provider.Configured ? 'Not linked' : 'Provider is no longer configured'}</div>
          </div>
          {#if provider.Linked}
            <Form action={`/account/oauth/${provider.Key}/unlink`} csrf={data.CSRF} confirm={`Remove ${provider.Label} login from this account?`}>
              <button class="btn btn-outline-danger btn-sm" type="submit">Unlink</button>
            </Form>
          {:else if provider.Configured}
            <a class="btn btn-primary btn-sm" href={`/oauth/${provider.Key}/start`}>Link {provider.Label}</a>
          {/if}
        </li>
      {/each}
    </ul>
  </section>
{/if}

<section class="panel" id="client-encryption">
  <div class="section-heading"><h2>Client-side encryption</h2></div>
  <form id="encryption-setup" class="form-grid" method="post">
    <p>Client-side encryption is optional. Generate a unique account key in your browser to use it, then select <strong>Encrypt files in my browser</strong> on the <a href="/">upload page</a> for any upload or batch you want to encrypt. Leave it unchecked to upload without client-side encryption, even after key setup. Existing files keep their current format and encrypted files still need their key.</p>
    <div class="alert alert-warning">Choose a separate encryption passphrase and save it safely. ObjectShare cannot recover it. Resetting your login password will not unlock encrypted files. Keep the encrypted key backup together with a separately stored copy of your passphrase.</div>
    <div class="field">
      <label class="form-label" for="encryption_passphrase">New encryption passphrase</label>
      <input id="encryption_passphrase" type="password" class="form-control" minlength="16" maxlength="512" autocomplete="off" required>
    </div>
    <div class="field">
      <label class="form-label" for="encryption_confirm">Confirm encryption passphrase</label>
      <input id="encryption_confirm" type="password" class="form-control" minlength="16" maxlength="512" autocomplete="off" required>
    </div>
    <p class="text-secondary">The key and passphrase stay in this page's memory while in use. On another page or device, enter the passphrase again. There is no key replacement or passphrase reset that could make existing files unreadable.</p>
    <div role="status" aria-live="polite"></div>
    <noscript>JavaScript and HTTPS are required to set up encryption.</noscript>
    <div class="actions">
      <button type="submit" class="btn btn-primary" disabled>Generate account key</button>
      <button id="encryption-backup" type="button" class="btn btn-outline-secondary">Download encrypted key backup</button>
    </div>
  </form>
</section>

<section class="panel">
  <div class="section-heading">
    <h2>My uploads</h2>
    <span class="badge bg-blue-lt">{files.length}</span>
  </div>
  {#if data.QuotaLabel}<p class="text-secondary small">{data.QuotaLabel}</p>{/if}
  {#if files.length}
    <div class="table-responsive">
      <table class="table table-vcenter data-table">
        <thead><tr><th>Name</th><th>Size</th><th>Uploaded</th><th></th></tr></thead>
        <tbody>
          {#each files as file (file.ID)}
            <tr>
              <td><a href={`/file/${file.ID}`}>{file.Name}</a></td>
              <td class="text-secondary">{file.Size}</td>
              <td class="text-secondary">{file.CreatedAt}</td>
              <td class="text-end">
                <a class="btn btn-sm" href={`/file/${file.ID}/sharing`}>Share</a>
                <a class="btn btn-sm" href={`/file/${file.ID}`}>Manage</a>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="empty-state">
      <p class="empty-title">No account uploads yet</p>
      <p class="text-secondary">Files uploaded while logged in will appear here.</p>
      <a href="/" class="btn btn-primary">Upload a file</a>
    </div>
  {/if}
</section>
