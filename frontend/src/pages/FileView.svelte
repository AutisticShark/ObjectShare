<script lang="ts">
  import Form from '../components/Form.svelte';
  import Captcha from '../components/Captcha.svelte';
  import { date } from '../lib/format';
  import type { FileViewPageData } from '../lib/pages';

  let { data }: { data: FileViewPageData } = $props();
  const downloadAction = $derived(`/api/v1/download/${data.FileID}`);
  const formCSRF = $derived(data.User ? data.CSRF : '');
</script>

<div class="actions">
  {#if data.ClientEncryption}
    <a class="btn btn-primary" href="#encrypted-download">Decrypt &amp; download</a>
  {:else if data.CanDirectLink}
    <a class="btn btn-primary" href={downloadAction}>Download</a>
  {:else}
    <Form action={downloadAction} enhance={false} class="d-flex flex-wrap align-items-center gap-2">
      <input type="hidden" name="download_token" value={data.DownloadToken}>
      <Captcha captcha={data.Captcha} />
      <button class="btn btn-primary" type="submit">Download</button>
    </Form>
  {/if}
</div>

<section class="panel">
  {#if data.ClientEncryption}
    <form id="encrypted-download" action={downloadAction} method="post" data-metadata={data.ClientEncryption} data-filename={data.FileName} class="form-grid">
      <input type="hidden" name="download_token" value={data.DownloadToken}>
      <div class="section-heading"><h2>Encrypted in the uploader's browser</h2></div>
      <p>Enter your encryption passphrase if this is your upload, or open the owner's sharing link containing this file's key. File contents are decrypted and authenticated in your browser. Displayed size and checksums describe the encrypted upload.</p>
      <div class="field">
        <label class="form-label" for="encryption_passphrase">Your encryption passphrase (for your own uploads)</label>
        <input class="form-control" id="encryption_passphrase" type="password" autocomplete="off">
      </div>
      <div class="field">
        <label class="form-label" for="encryption-key-backup">Encrypted key backup (optional recovery)</label>
        <input id="encryption-key-backup" type="file" accept=".json,application/json" class="form-control">
        <div class="form-hint">Choose your saved encrypted account key and enter its passphrase to recover a file. The backup stays in this browser.</div>
      </div>
      <Captcha captcha={data.Captcha} />
      <div class="actions">
        <button class="btn btn-primary" type="submit">Decrypt &amp; download</button>
        {#if data.CanManage}<button id="encrypted-share" class="btn btn-outline-primary" type="button">Create sharing link with file key</button>{/if}
      </div>
      {#if data.CanManage}
        <input id="encrypted-share-link" class="form-control" aria-label="Sharing link containing this file's key" readonly hidden>
        <p class="form-hint">Send the generated link only to intended recipients. Access changes cannot revoke keys or copies already received.</p>
      {/if}
      <div role="status" aria-live="polite"></div>
      <noscript>JavaScript and HTTPS are required for browser decryption. A native download returns encrypted bytes.</noscript>
    </form>
  {/if}

  <div class="datagrid">
    <div class="datagrid-item"><div class="datagrid-title">File ID</div><div class="datagrid-content"><code>{data.FileID}</code></div></div>
    <div class="datagrid-item"><div class="datagrid-title">Size</div><div class="datagrid-content">{data.FileSize}</div></div>
    <div class="datagrid-item">
      <div class="datagrid-title">Encryption</div>
      <div class="datagrid-content">
        {#if data.ClientEncryption}<span class="status status-green">Client AES-256-GCM</span>
        {:else if data.Encrypted}<span class="status status-green">AES-256-GCM</span>
        {:else}<span class="status">None</span>{/if}
      </div>
    </div>
    <div class="datagrid-item"><div class="datagrid-title">Created</div><div class="datagrid-content">{date(data.CreatedAt, true)}</div></div>
    <div class="datagrid-item"><div class="datagrid-title">Updated</div><div class="datagrid-content">{date(data.UpdatedAt, true)}</div></div>
    <div class="datagrid-item">
      <div class="datagrid-title">SHA-256</div>
      <div class="datagrid-content text-break">{#if data.ChecksumsVerified}<code>{data.FileSHA256}</code>{:else}<span class="text-secondary">Not calculated for direct upload</span>{/if}</div>
    </div>
    <div class="datagrid-item">
      <div class="datagrid-title">SHA3-256</div>
      <div class="datagrid-content text-break">{#if data.ChecksumsVerified}<code>{data.FileSHA3}</code>{:else}<span class="text-secondary">Not calculated for direct upload</span>{/if}</div>
    </div>
  </div>

  {#if data.CanManage && data.CanDirectLink}
    <div class="alert alert-success mt-3 mb-0"><strong>Direct link enabled:</strong> share <code class="text-break">{data.DirectURL}</code>.{data.PlanDirectLinks ? ' It remains active only while your plan includes direct links.' : ''}</div>
  {/if}
</section>

{#if data.CanManage}
  <section class="panel">
    <div class="actions"><a class="btn btn-primary" href={`/file/${data.FileID}/sharing`}>Sharing &amp; permissions</a></div>
    <div class="d-flex flex-wrap gap-3 align-items-end">
      <Form action={`/api/v1/update/${data.FileID}`} csrf={formCSRF} class="filter-bar">
        <div class="field">
          <label class="form-label" for="name">Rename file</label>
          <input class="form-control" id="name" name="name" value={data.FileName} maxlength="255" required>
        </div>
        <button class="btn btn-secondary" type="submit">Rename</button>
      </Form>
      <Form action={`/api/v1/delete/${data.FileID}`} csrf={formCSRF} confirm="Permanently delete this file? This cannot be undone.">
        <button class="btn btn-danger" type="submit">Delete permanently</button>
      </Form>
    </div>
  </section>
{/if}
