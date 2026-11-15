<script lang="ts">
  import Captcha from '../components/Captcha.svelte';
  import Icon from '../components/Icon.svelte';

  export interface UploadData {
    User?: { ID: string } | null;
    CSRF: string;
    CanUpload: boolean;
    DirectUpload: boolean;
    MaxFileSize: number;
    MaxFiles: number;
    QuotaLabel?: string;
    SignupEnabled?: boolean;
    Captcha?: { SiteKey: string; Action: string } | null;
  }
  let { data }: { data: UploadData } = $props();
</script>

{#if data.CanUpload}
  <form id="upload-form" action="/api/v1/upload" method="post" enctype="multipart/form-data"
    data-max-file-mib={data.MaxFileSize} data-max-files={data.MaxFiles}
    data-direct-upload={data.DirectUpload ? 'true' : undefined}
    hx-post={!data.DirectUpload && !data.User ? '/api/v1/upload' : undefined}
    hx-encoding={!data.DirectUpload && !data.User ? 'multipart/form-data' : undefined}
    hx-disabled-elt={!data.DirectUpload && !data.User ? '#upload-button' : undefined}>
    {#if data.User}<input type="hidden" name="csrf_token" value={data.CSRF}>{/if}
    <div class="upload-layout">
      <section class="panel upload-picker" aria-label="Files to upload">
        <div class="panel-heading">
          <h2>Files</h2>
          <div class="segmented-control" role="group" aria-label="Upload mode">
            <label><input type="radio" name="upload_mode" value="single" checked><span>Single</span></label>
            <label><input type="radio" name="upload_mode" value="multiple"><span>Multiple</span></label>
          </div>
        </div>
        <div id="upload-dropzone" class="upload-dropzone">
          <div class="dropzone-icon"><Icon name="upload" size={28} /></div>
          <label class="dropzone-label" for="file">Drop a file here<span>or choose from your device</span></label>
          <input id="file" class="dropzone-input" type="file" name="file" required aria-describedby="file-limits">
        </div>
        <div id="file-selection" class="upload-file-list" role="status" aria-live="polite"></div>
        <div id="file-limits" class="upload-limits"><span>{data.MaxFileSize} MiB per file</span><span>Up to {data.MaxFiles} files</span></div>
        {#if data.QuotaLabel}<p class="quota-note">{data.QuotaLabel}</p>{/if}
      </section>
      <section class="panel upload-options" aria-label="Upload options">
        <div class="panel-heading"><h2>Sharing</h2></div>
        <div class="field">
          <label class="form-label" for="share-mode">Who can access</label>
          <select class="form-select" id="share-mode" name="share_mode">
            <option value="link">Anyone with the link</option>
            <option value="signed_in">Signed-in users</option>
            <option value="private">Only me</option>
          </select>
          <p id="sharing-explanation" class="form-hint" aria-live="polite">Anyone who receives the link can open the file. Encrypted files also need a file key.</p>
        </div>
        {#if data.User}
          <div class="encryption-option">
            <label class="form-check"><input class="form-check-input" id="encrypt-files" name="encrypt_files" type="checkbox" disabled aria-controls="encryption-fields"><span class="form-check-label">Encrypt files in my browser</span></label>
            <div id="encryption-fields" hidden>
              <div class="field"><label class="form-label" for="encryption-passphrase">Encryption passphrase</label><input class="form-control" id="encryption-passphrase" type="password" autocomplete="off" disabled></div>
              <p class="form-hint">Used only on this page. Losing your passphrase makes encrypted files unrecoverable.</p>
              <a class="small" href="/account#client-encryption">Set up encryption</a>
            </div>
          </div>
        {:else}
          <p class="form-hint owner-note">Keep this browser’s cookies to manage your uploads.</p>
        {/if}
        <p class="form-hint">Add selected recipients after uploading.</p>
        <Captcha captcha={data.Captcha} />
        <button id="upload-button" class="btn btn-primary upload-submit" type="submit"><Icon name="upload" size={18} />Upload</button>
      </section>
    </div>
    <div id="upload-status" class="alert alert-info d-none upload-feedback" role="status" aria-live="polite"></div>
    <div id="upload-progress-wrap" class="progress d-none" aria-hidden="true">
      <div id="upload-progress" class="progress-bar" role="progressbar" aria-label="Upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div>
    </div>
    <div id="upload-recovery" class="panel d-none upload-feedback">
      <p>Keep this page open to retry unfinished files. Completed files will not be uploaded again.</p>
      <ul id="completed-uploads" class="list-unstyled"></ul>
      <div class="actions"><button id="retry-upload" class="btn btn-primary" type="button">Retry unfinished uploads</button><a class="btn" href="/">Start another upload</a>{#if data.User}<a class="btn" href="/files" target="_blank" rel="noopener">My files</a>{/if}</div>
    </div>
  </form>
{:else}
  <section class="panel empty-state">
    <Icon name="lock" size={28} />
    {#if data.User}<h2>Verify your email to upload</h2><a class="btn btn-primary" href="/account">My account</a>
    {:else}<h2>Log in to upload</h2><div class="actions"><a class="btn btn-primary" href="/login">Log in</a>{#if data.SignupEnabled}<a class="btn" href="/signup">Create account</a>{/if}</div>{/if}
  </section>
{/if}
