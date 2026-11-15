<script lang="ts">
  import Form from '../components/Form.svelte';
  import type { MFAPageData } from '../lib/pages';

  let { data }: { data: MFAPageData } = $props();

  const codes = $derived(data.Codes ?? []);
  const action = $derived(data.Action ?? '');
  const method = $derived(data.Method ?? '');
  const recoveryAllowed = $derived(action === 'login' || action === 'disable' || action === 'recovery');
  const enrolled = $derived(data.User?.MFA?.Method ?? '');
</script>

<section class="panel auth-panel">
  {#if data.Error}<div class="alert alert-danger" role="alert">{data.Error}</div>{/if}
  {#if data.Message}<div class="alert alert-info" role="status">{data.Message}</div>{/if}

  {#if codes.length}
    <div class="section-heading"><h2>Save your recovery codes</h2></div>
    <p>Store these somewhere safe, separate from your password and authenticator. Each code can replace your second factor once. Generating new codes invalidates all previous recovery codes.</p>
    <div class="border rounded p-3 mb-3 text-break">
      {#each codes as code (code)}<div><code>{code}</code></div>{/each}
    </div>
    <p class="text-secondary">If you lose your second factor and every recovery code, you cannot sign in. A password reset does not remove MFA.</p>
    <div class="actions"><a href="/account" class="btn btn-primary">I saved my codes — return to account</a></div>
  {:else if action}
    {#if action === 'disable'}
      <p>Confirm your current second factor to disable MFA and sign out other sessions.</p>
    {:else if action === 'recovery'}
      <p>Confirm your current second factor to replace all recovery codes and sign out other sessions.</p>
    {:else if action === 'login'}
      <p>Complete verification to finish signing in.</p>
    {:else}
      <p>Confirm a code before MFA is enabled. Enabling MFA signs out other sessions.</p>
    {/if}

    {#if data.Secret}
      <div class="section-heading"><h2>Set up your authenticator</h2></div>
      <p>In Google Authenticator or a compatible app, choose <strong>Enter a setup key</strong>. Name it ObjectShare, select <strong>Time based</strong>, and enter this key:</p>
      <div class="border rounded p-3 mb-3 text-break"><code>{data.Secret}</code></div>
      <p class="text-secondary">Use six digits, SHA-1, and a 30-second period. Keep this key private. Enter the app's current code below.</p>
    {/if}

    <Form action="/login/mfa" csrf={data.CSRF} autocomplete="off" class="form-grid">
      <div class="field">
        <label for="mfa-code" class="form-label">{method === 'email' ? 'Email verification code' : 'Authenticator code'}{recoveryAllowed ? ' or recovery code' : ''}</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input class="form-control" id="mfa-code" name="code" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="64" required autofocus>
      </div>
      <div class="actions"><button class="btn btn-primary w-100" type="submit">Verify</button></div>
    </Form>
    {#if method === 'email'}
      <Form action="/login/mfa/resend" csrf={data.CSRF} class="mt-3">
        <button class="btn w-100" type="submit">Resend email code</button>
      </Form>
    {/if}
    <p class="text-secondary mt-3">Verification expires after five minutes. Wait one minute between email sends. After five failed codes, wait 15 minutes before starting again. Resending replaces the email code without extending this verification.</p>
    <a href={action === 'login' ? '/login' : '/account/mfa'}>Start again</a>
  {:else if data.User}
    {#if enrolled}
      <p>MFA is enabled using <strong>{enrolled === 'totp' ? 'an authenticator app' : 'email codes'}</strong>. Password and OAuth sign-ins require a second factor.</p>
      <p>{data.RecoveryCount ?? 0} recovery codes remain.</p>
      <Form action="/account/mfa" csrf={data.CSRF}>
        <div class="d-grid gap-2">
          <button class="btn" name="action" value="recovery" type="submit">Generate new recovery codes</button>
          <button class="btn btn-outline-danger" name="action" value="disable" type="submit">Disable MFA</button>
        </div>
      </Form>
      <p class="text-secondary mt-3">Generating new recovery codes or disabling MFA requires a sign-in within the last five minutes. To change methods, disable the current method using a code, then enroll again. Email MFA must be disabled before changing your email address.</p>
    {:else}
      <p>Add a second step to sign-ins. Choose an authenticator app or email verification codes.</p>
      <p class="text-secondary">An authenticator app works offline. Email codes depend on mailbox security and delivery. Both methods include recovery codes.</p>
      <Form action="/account/mfa" csrf={data.CSRF} class="form-grid">
        {#if data.HasPassword}
          <div class="field">
            <label class="form-label" for="mfa-password">Current password</label>
            <input class="form-control" id="mfa-password" name="current_password" type="password" autocomplete="current-password" maxlength="512" required>
          </div>
        {:else}
          <p>For an OAuth-only account, sign in again and start setup within five minutes.</p>
        {/if}
        <div class="d-grid gap-2">
          <button class="btn btn-primary" type="submit" name="action" value="setup-totp">Set up authenticator app</button>
          {#if data.EmailAvailable && data.User.EmailVerifiedAt}
            <button class="btn" type="submit" name="action" value="setup-email">Set up email codes</button>
          {:else}
            <p class="text-secondary">Email codes require a verified account email address and an email provider configured by your administrator.</p>
          {/if}
        </div>
      </Form>
    {/if}
    <a class="d-inline-block mt-3" href="/account">Back to account</a>
  {:else}
    <a class="btn btn-primary" href="/login">Return to sign in</a>
  {/if}
</section>
