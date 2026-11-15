<script lang="ts">
  import SettingsField from './SettingsField.svelte';
  import SecretField from './SecretField.svelte';
  import type { EmailSettings, SettingsSecretState } from '../lib/pages';

  let { email, secrets }: { email: EmailSettings; secrets: SettingsSecretState } = $props();
  const alibabaRegions = ['cn-hangzhou', 'ap-southeast-1', 'ap-southeast-2', 'us-east-1', 'eu-central-1'];
</script>

<section class="panel">
  <div class="section-heading"><h2 id="outgoing-email">Email delivery</h2></div>
  <p class="text-secondary">Choose one provider for outgoing email. Saving activates changes in this replica; other replicas pick them up on their next configuration reload.</p>
  <div class="form-grid">
    <div class="field">
      <label class="form-label" for="email_provider">Provider</label>
      <select class="form-select" id="email_provider" name="email_provider">
        <option value="none" selected={email.Provider === 'none'}>Disabled</option>
        <option value="smtp" selected={email.Provider === 'smtp'}>SMTP</option>
        <option value="alibaba" selected={email.Provider === 'alibaba'}>Alibaba Cloud Direct Mail</option>
        <option value="ses" selected={email.Provider === 'ses'}>AWS SES</option>
      </select>
    </div>
    <SettingsField label="Send timeout" name="email_timeout" value={email.Timeout} required />
    <SettingsField label="Sender email address" name="email_from_address" type="email" value={email.FromAddress} />
    <SettingsField label="Sender name" name="email_from_name" value={email.FromName} maxlength={100} />
    <SettingsField label="Reply-to address (optional)" name="email_reply_to" type="email" value={email.ReplyTo} />
  </div>

  <details class="border rounded p-3 mt-3" open={email.Provider === 'smtp'}>
    <summary class="fw-bold">SMTP</summary>
    <div class="form-grid mt-2">
      <SettingsField label="Host" name="email_smtp_host" value={email.SMTP.Host} />
      <SettingsField label="Port" name="email_smtp_port" type="number" value={email.SMTP.Port} min={1} max={65535} required />
      <div class="field">
        <label class="form-label" for="email_smtp_tls_mode">Connection security</label>
        <select class="form-select" id="email_smtp_tls_mode" name="email_smtp_tls_mode">
          <option value="starttls" selected={email.SMTP.TLSMode === 'starttls'}>Required STARTTLS (usually port 587)</option>
          <option value="tls" selected={email.SMTP.TLSMode === 'tls'}>Implicit TLS (usually port 465)</option>
        </select>
      </div>
      <SettingsField label="Username" name="email_smtp_username" value={email.SMTP.Username} />
      <SecretField label="Password" name="email_smtp_password" clearName="clear_email_smtp_password" configured={secrets.SMTPPassword} clearLabel="Clear stored password" />
    </div>
    <p class="form-hint mb-0">Certificates are verified. Authentication uses AUTH PLAIN over TLS; leave both username and password empty for an authenticated network relay that does not require SMTP credentials.</p>
  </details>

  <details class="border rounded p-3 mt-3" open={email.Provider === 'alibaba'}>
    <summary class="fw-bold">Alibaba Cloud Direct Mail</summary>
    <div class="form-grid mt-2">
      <div class="field">
        <label class="form-label" for="email_alibaba_region">Region</label>
        <select class="form-select" id="email_alibaba_region" name="email_alibaba_region">
          {#each alibabaRegions as region (region)}<option value={region} selected={email.Alibaba.Region === region}>{region}</option>{/each}
        </select>
      </div>
      <SecretField label="Access key ID" name="email_alibaba_access_key_id" clearName="clear_email_alibaba_access_key_id" configured={secrets.AlibabaMailAccess} clearLabel="Clear stored access key id" />
      <SecretField label="Access key secret" name="email_alibaba_access_key_secret" clearName="clear_email_alibaba_access_key_secret" configured={secrets.AlibabaMailSecret} clearLabel="Clear stored access key secret" />
    </div>
    <p class="form-hint mb-0">Use a verified sender address in this region and a RAM identity with dm:SingleSendMail permission. Sender names have a 15-character limit.</p>
  </details>

  <details class="border rounded p-3 mt-3" open={email.Provider === 'ses'}>
    <summary class="fw-bold">AWS SES</summary>
    <div class="form-grid mt-2">
      <SettingsField label="Region" name="email_ses_region" value={email.SES.Region} />
      <SettingsField label="Configuration set (optional)" name="email_ses_configuration_set" value={email.SES.ConfigurationSet} />
      <SecretField label="Access key ID" name="email_ses_access_key_id" clearName="clear_email_ses_access_key_id" configured={secrets.SESAccess} clearLabel="Clear stored access key id" />
      <SecretField label="Secret access key" name="email_ses_secret_access_key" clearName="clear_email_ses_secret_access_key" configured={secrets.SESSecret} clearLabel="Clear stored secret access key" />
      <SecretField label="Session token (optional)" name="email_ses_session_token" clearName="clear_email_ses_session_token" configured={secrets.SESSession} clearLabel="Clear stored session token (optional)" />
    </div>
    <p class="form-hint mb-0">Leave all three credentials empty to use the AWS credential chain, including workload IAM roles. The identity needs ses:SendEmail permission. Verify the sender in this region; sandbox accounts also require verified recipients.</p>
  </details>
</section>
