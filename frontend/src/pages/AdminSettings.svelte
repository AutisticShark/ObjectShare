<script lang="ts">
  import Form from '../components/Form.svelte';
  import BrandingSettings from './BrandingSettings.svelte';
  import EmailSettings from './EmailSettings.svelte';
  import SettingsField from './SettingsField.svelte';
  import SecretField from './SecretField.svelte';
  import SettingsCheck from './SettingsCheck.svelte';
  import StorageBackend from './StorageBackend.svelte';
  import type { AdminSettingsPageData } from '../lib/pages';

  let { data }: { data: AdminSettingsPageData } = $props();
  const config = $derived(data.Config);
  const secrets = $derived(data.Secrets);
  const oauthProviders = $derived([
    { title: 'Google', prefix: 'google', clear: 'clear_google_oauth_secret', settings: config.Auth.OAuth.Google, configured: secrets.Google },
    { title: 'GitHub', prefix: 'github', clear: 'clear_github_oauth_secret', settings: config.Auth.OAuth.GitHub, configured: secrets.GitHub },
    { title: 'Discord', prefix: 'discord', clear: 'clear_discord_oauth_secret', settings: config.Auth.OAuth.Discord, configured: secrets.Discord },
  ]);
  const storageServices: [string, string][] = [
    ['filesystem', 'Local filesystem'], ['r2', 'Cloudflare R2'], ['s3', 'Amazon S3 / compatible'], ['b2', 'Backblaze B2'],
    ['oss', 'Alibaba OSS'], ['cos', 'Tencent COS'], ['oci', 'Oracle Cloud Object Storage'], ['gcs', 'Google Cloud Storage'],
  ];
</script>

{#if data.ActivationPending}
  <div class="alert alert-warning" role="alert"><strong>Activation pending.</strong> The saved database configuration differs from this replica's active configuration. Each replica activates the saved revision as one snapshot at its next configuration reload, on SIGHUP, or on restart.</div>
{/if}
<div class="alert alert-info" role="status">Secrets are write-only. Empty secret fields preserve the stored value; use the adjacent clear checkbox to remove one. Last saved {data.UpdatedAt} by {data.UpdatedBy}.</div>

<Form action="/admin/settings" csrf={data.CSRF}>
  <input type="hidden" name="revision" value={data.Revision}>

  <BrandingSettings branding={config.Branding} />
  <EmailSettings email={config.Email} {secrets} />

  <section class="panel">
    <div class="section-heading"><h2 id="application-policy">Application policy</h2></div>
    <div class="form-grid">
      <SettingsField label="Maximum file size (MiB)" name="max_file_size" id="max-file-size" type="number" min={1} max={10240} value={config.MaxFileSize} required />
      <SettingsField label="Maximum files per batch" name="max_files_per_batch" id="max-files-per-batch" type="number" min={1} max={100} value={config.Upload.MaxFilesPerBatch} required />
      <SettingsField label="Guest pending direct uploads (MiB)" name="max_pending_guest_mb" id="max-pending-guest-mb" type="number" min={1} max={1048576} value={config.Upload.MaxPendingGuestMiB} required hint="Total size of guest uploads that were authorised but not finished. New guest uploads wait when it is full." />
      <SettingsCheck label="Allow guest uploads" name="guest_enabled" checked={config.Upload.GuestEnabled} />
      <SettingsField label="Guest retention (days)" name="guest_retention_days" id="guest-retention-days" type="number" min={0} max={36500} value={config.Retention.GuestDays} required hint="0 disables automatic deletion for guest files." />
      <SettingsField label="Unpaid retention (days)" name="unpaid_retention_days" id="unpaid-retention-days" type="number" min={0} max={36500} value={config.Retention.UnpaidDays} required hint="Paid accounts are exempt. 0 disables deletion for unpaid accounts." />
      <SettingsCheck label="Allow public account sign-up" name="signup_enabled" checked={config.Auth.SignupEnabled} />
      <fieldset class="form-grid">
        <legend class="form-label">Email verification</legend>
        <SettingsField label="Public site URL" name="verification_public_url" id="verification-public-url" type="url" value={config.Auth.EmailVerification.PublicURL} placeholder="https://files.example.com" />
        <SettingsCheck label="Require verified email to purchase plans" name="verification_require_for_purchases" checked={config.Auth.EmailVerification.RequireForPurchases} />
        <SettingsCheck label="Require verified email for account uploads" name="verification_require_for_uploads" checked={config.Auth.EmailVerification.RequireForUploads} />
        <div class="form-hint">Configure Outgoing email and this URL to send verification links after signup. Restrictions apply to all unverified accounts, including administrators and existing accounts. Guest uploads use the separate switch above; disable them to allow only verified accounts to upload. Saving activates the change in this replica immediately.</div>
      </fieldset>
      <SettingsCheck label="Use Secure __Host- authentication cookies" name="secure_cookies" checked={config.SecureCookies} description="Enable only when the browser-visible site uses HTTPS." />
    </div>
  </section>

  <section class="panel">
    <div class="section-heading"><h2 id="billing-gateways">Billing gateways</h2></div>
    <div class="form-grid">
      <SettingsField label="Public origin" name="billing_public_url" value={config.Billing.PublicURL} placeholder="https://share.example.com" hint="Gateway redirects return to this exact browser-visible origin." />
      <SettingsField label="Credit currency" name="billing_credit_currency" value={config.Billing.CreditCurrency} minlength={3} maxlength={3} required class="text-uppercase" hint="One credit equals one whole currency unit." />
      <SettingsField label="Minimum top-up" name="billing_min_top_up_credits" type="number" min={1} max={1000000} value={config.Billing.MinTopUpCredits} required />
      <SettingsField label="Maximum top-up" name="billing_max_top_up_credits" type="number" min={1} max={1000000} value={config.Billing.MaxTopUpCredits} required />
    </div>
    <div class="form-grid mt-3">
      <fieldset class="border rounded p-3 form-grid">
        <legend class="float-none w-auto px-2 fs-4">Stripe</legend>
        <SettingsCheck label="Enable Stripe Checkout" name="stripe_enabled" checked={config.Billing.Stripe.Enabled} />
        <SecretField label="Secret key" name="stripe_secret_key" clearName="clear_stripe_secret" configured={secrets.StripeSecret} />
        <SecretField label="Webhook signing secret" name="stripe_webhook_secret" clearName="clear_stripe_webhook_secret" configured={secrets.StripeWebhook} />
        <div class="form-hint">Webhook: <code>/api/v1/billing/stripe/webhook</code></div>
      </fieldset>
      <fieldset class="border rounded p-3 form-grid">
        <legend class="float-none w-auto px-2 fs-4">PayPal</legend>
        <SettingsCheck label="Enable PayPal billing" name="paypal_enabled" checked={config.Billing.PayPal.Enabled} />
        <div class="field">
          <label class="form-label" for="paypal_environment">Environment</label>
          <select class="form-select" id="paypal_environment" name="paypal_environment">
            <option value="sandbox" selected={config.Billing.PayPal.Environment === 'sandbox'}>Sandbox</option>
            <option value="live" selected={config.Billing.PayPal.Environment === 'live'}>Live</option>
          </select>
        </div>
        <SettingsField label="Client ID" name="paypal_client_id" value={config.Billing.PayPal.ClientID} />
        <SecretField label="Client secret" name="paypal_client_secret" clearName="clear_paypal_client_secret" configured={secrets.PayPalSecret} />
        <SettingsField label="Webhook ID" name="paypal_webhook_id" value={config.Billing.PayPal.WebhookID} />
        <div class="form-hint">Webhook: <code>/api/v1/billing/paypal/webhook</code></div>
      </fieldset>
    </div>
    <p class="form-hint">Create prepaid plans in <a href="/admin/plans">Plan catalog</a>. Saving activates these settings on this replica; other replicas pick them up at their next configuration reload.</p>
  </section>

  <section class="panel">
    <div class="section-heading"><h2>Request limits</h2></div>
    <div class="form-grid">
      <SettingsCheck label="Enable shared request limits" name="rate_limit_enabled" checked={config.RateLimit.Enabled} />
      <SettingsField label="Window" name="rate_limit_window" value={config.RateLimit.Window} required />
      <SettingsField label="All API requests" name="rate_limit_api" type="number" min={0} value={config.RateLimit.APILimit} required />
      <SettingsField label="Login" name="rate_limit_login" type="number" min={0} value={config.RateLimit.LoginLimit} required />
      <SettingsField label="Sign-up" name="rate_limit_signup" type="number" min={0} value={config.RateLimit.SignupLimit} required />
      <SettingsField label="Upload" name="rate_limit_upload" type="number" min={0} value={config.RateLimit.UploadLimit} required />
      <SettingsField label="Download" name="rate_limit_download" type="number" min={0} value={config.RateLimit.DownloadLimit} required />
      <SettingsField label="Trusted proxy CIDRs" name="trusted_proxy_cidrs" value={data.TrustedProxyCIDRs} placeholder="10.0.0.0/8, 2001:db8::/32" hint="Comma-separated networks operated by you. Forwarded IP and X-Forwarded-Proto headers from other peers remain untrusted." />
    </div>
  </section>

  <section class="panel">
    <div class="section-heading"><h2>Cloudflare Turnstile</h2></div>
    <div class="form-grid">
      <div class="field">
        <label class="form-label" for="captcha_provider">Provider</label>
        <select class="form-select" id="captcha_provider" name="captcha_provider">
          <option value="none" selected={config.Captcha.Provider === 'none'}>Disabled</option>
          <option value="turnstile" selected={config.Captcha.Provider === 'turnstile'}>Turnstile</option>
        </select>
      </div>
      <SettingsField label="Site key" name="captcha_site_key" value={config.Captcha.SiteKey} />
      <SettingsField label="Expected hostname" name="captcha_expected_hostname" value={config.Captcha.ExpectedHostname} placeholder="share.example.com" />
      <SecretField label="Secret key" name="captcha_secret_key" clearName="clear_captcha_secret" configured={secrets.Captcha} />
      <div class="d-flex flex-wrap gap-4">
        <SettingsCheck label="Login" name="captcha_protect_login" checked={config.Captcha.ProtectLogin} />
        <SettingsCheck label="Sign-up" name="captcha_protect_signup" checked={config.Captcha.ProtectSignup} />
        <SettingsCheck label="Upload" name="captcha_protect_upload" checked={config.Captcha.ProtectUpload} />
        <SettingsCheck label="Download" name="captcha_protect_download" checked={config.Captcha.ProtectDownload} />
      </div>
    </div>
  </section>

  <section class="panel">
    <div class="section-heading"><h2>OAuth login</h2></div>
    <div class="form-grid">
      <SettingsField label="Public origin" name="oauth_public_url" value={config.Auth.OAuth.PublicURL} placeholder="https://share.example.com" />
      <div class="form-grid">
        {#each oauthProviders as provider (provider.prefix)}
          <fieldset class="border rounded p-3 form-grid">
            <legend class="float-none w-auto px-2 fs-4">{provider.title}</legend>
            <SettingsCheck label="Enabled" name={`${provider.prefix}_oauth_enabled`} checked={provider.settings.Enabled} />
            <SettingsField label="Client ID" name={`${provider.prefix}_oauth_client_id`} value={provider.settings.ClientID} />
            <SecretField label="Client secret" name={`${provider.prefix}_oauth_client_secret`} clearName={provider.clear} configured={provider.configured} />
          </fieldset>
        {/each}
      </div>
    </div>
  </section>

  <section class="panel">
    <div class="section-heading"><h2>Object storage</h2></div>
    <div class="alert alert-warning" role="alert">Changing the active storage service or its bucket/path does not migrate existing objects. Move or replicate stored objects first; otherwise existing share links can become unavailable once the change is activated.</div>
    <div class="form-grid mb-3">
      <div class="field">
        <label class="form-label" for="storage_service">Active service</label>
        <select class="form-select" id="storage_service" name="storage_service">
          {#each storageServices as [value, label] (value)}<option {value} selected={config.StorageService === value}>{label}</option>{/each}
        </select>
      </div>
      <SettingsField label="Filesystem path" name="storage_path" value={config.StoragePath} hint="Used only when local filesystem is active." />
    </div>

    <StorageBackend prefix="r2" title="Cloudflare R2" open={config.StorageService === 'r2'} settings={config.R2} accessSet={secrets.R2Access} secretSet={secrets.R2Secret} endpointLabel="Endpoint override">
      {#snippet extra()}
        <SettingsField label="Account ID" name="r2_account_id" value={config.R2.AccountID} />
      {/snippet}
    </StorageBackend>
    <StorageBackend prefix="s3" title="Amazon S3 / S3-compatible" open={config.StorageService === 's3'} settings={config.S3} accessSet={secrets.S3Access} secretSet={secrets.S3Secret}>
      {#snippet extra()}
        <SettingsCheck label="Use path-style requests" name="s3_use_path_style" checked={config.S3.UsePathStyle} />
        <SecretField label="Session token" name="s3_session_token" clearName="clear_s3_session_token" configured={secrets.S3Session} clearLabel="Clear token" />
      {/snippet}
    </StorageBackend>
    <StorageBackend prefix="b2" title="Backblaze B2" open={config.StorageService === 'b2'} settings={config.B2} accessSet={secrets.B2Access} secretSet={secrets.B2Secret} />
    <StorageBackend prefix="oss" title="Alibaba OSS" open={config.StorageService === 'oss'} settings={config.OSS} accessSet={secrets.OSSAccess} secretSet={secrets.OSSSecret} />
    <StorageBackend prefix="cos" title="Tencent COS" open={config.StorageService === 'cos'} settings={config.COS} accessSet={secrets.COSAccess} secretSet={secrets.COSSecret} />
    <StorageBackend prefix="oci" title="Oracle Cloud Object Storage" open={config.StorageService === 'oci'} settings={config.OCI} accessSet={secrets.OCIAccess} secretSet={secrets.OCISecret} endpointLabel="Endpoint (required)" />
    <StorageBackend prefix="gcs" title="Google Cloud Storage" open={config.StorageService === 'gcs'} settings={config.GCS} accessSet={secrets.GCSAccess} secretSet={secrets.GCSSecret} endpointLabel="Endpoint (default https://storage.googleapis.com)" />
  </section>

  <section class="panel">
    <div class="section-heading"><h2>Server-side object encryption</h2></div>
    <div class="alert alert-warning" role="alert">Changing or clearing the object-encryption key makes objects encrypted with the earlier key unrecoverable, so saving refuses either while server-side encrypted files exist. Turning encryption off keeps those files readable with the stored key. Back up the key and migrate data before any rotation.</div>
    <div class="form-grid">
      <SettingsCheck label="Encrypt stored objects with AES-256-GCM" name="encryption_enabled" checked={config.Encryption.Enabled} description="Disables direct browser upload and caps files at 128 MiB." />
      <SettingsField label="Method" name="encryption_method" value={config.Encryption.Method} readonly />
      <SecretField label="Encryption key" name="encryption_key" clearName="clear_encryption_key" configured={secrets.Encryption} clearLabel="Clear stored key" />
    </div>
  </section>

  <div class="settings-savebar"><button class="btn btn-primary" type="submit">Save configuration</button></div>
</Form>

<section class="panel">
  <div class="section-heading"><h2>Test active email provider</h2></div>
  <p class="text-secondary">Send a test message to {data.User.Email} using this replica's active configuration. Save before testing new settings; saving activates them in this replica.</p>
  <Form action="/admin/settings/email/test" csrf={data.CSRF} enhance={false}>
    <button class="btn btn-outline-primary" type="submit" disabled={!data.EmailEnabled}>Send test email</button>
  </Form>
</section>
