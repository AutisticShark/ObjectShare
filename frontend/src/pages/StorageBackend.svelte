<script lang="ts">
  import type { Snippet } from 'svelte';
  import SettingsField from './SettingsField.svelte';
  import SecretField from './SecretField.svelte';
  import type { StorageBackendSettings } from '../lib/pages';

  // One object-storage provider. `prefix` is the form field prefix (r2, s3, b2, oss, cos, oci, gcs);
  // `extra` adds provider-specific fields (R2 account ID, S3 path style and session token).
  let { prefix, title, open, settings, accessSet, secretSet, endpointLabel = 'Endpoint', extra }: {
    prefix: string; title: string; open: boolean; settings: StorageBackendSettings;
    accessSet: boolean; secretSet: boolean; endpointLabel?: string; extra?: Snippet;
  } = $props();
</script>

<details class="border rounded p-3 mb-3" {open}>
  <summary class="fw-bold">{title}</summary>
  <div class="form-grid mt-2">
    <SettingsField label="Bucket" name={`${prefix}_bucket_name`} value={settings.BucketName} />
    <SettingsField label="Region" name={`${prefix}_region`} value={settings.Region} />
    <SettingsField label={endpointLabel} name={`${prefix}_endpoint`} value={settings.Endpoint} />
    <SecretField label="Access key" name={`${prefix}_access_key_id`} clearName={`clear_${prefix}_access_key`} configured={accessSet} setLabel="set" clearLabel="Clear" />
    <SecretField label="Secret key" name={`${prefix}_secret_access_key`} clearName={`clear_${prefix}_secret_key`} configured={secretSet} setLabel="set" clearLabel="Clear" />
    <SettingsField label="Download presign" name={`${prefix}_presign_timeout`} value={settings.PresignLinkTimeout} />
    <SettingsField label="Upload presign" name={`${prefix}_upload_presign_timeout`} value={settings.PresignUploadTimeout} />
    {#if extra}{@render extra()}{/if}
  </div>
</details>
