<script lang="ts">
  import Form from '../components/Form.svelte';
  import type { SharingPageData } from '../lib/pages';

  let { data }: { data: SharingPageData } = $props();
</script>

{#snippet linkControls()}
  <label class="form-label" for="share-url">{data.ClientEncrypted ? 'Sharing link with file key' : 'Share link'}</label>
  <div class="input-group">
    <input class="form-control" id="share-url" value={data.ClientEncrypted ? '' : data.ShareURL} readonly>
    <button class="btn" id="copy-share-link" type="button" hidden>Copy link</button>
    {#if !data.ClientEncrypted}<a class="btn" href={data.ShareURL}>Open</a>{/if}
  </div>
{/snippet}

<div class="actions"><a class="btn" href={`/file/${data.FileID}`}>Back to file</a></div>

<section class="panel">
  <div class="section-heading"><h2>Share this file</h2></div>
  <p id="saved-access">
    <strong>Saved access:</strong>
    {#if data.SavedMode === 'link'}Anyone with the link can download.
    {:else if data.SavedMode === 'signed_in'}Recipients must sign in to download.
    {:else if data.SavedMode === 'selected'}Only the selected accounts can download after signing in.
    {:else}Only you can access this file. Choose another access option below before sending a link.{/if}
  </p>
  <div id="unsaved-sharing" class="alert alert-warning" role="status" hidden>Permissions have unsaved changes. Save permissions below before creating or copying a link.</div>

  {#if data.ClientEncrypted}
    <p>This file is encrypted. Create a link with this file's key so permitted recipients can decrypt it. Never share your account key or encryption passphrase.</p>
    <form id="encrypted-sharing" class="form-grid" data-metadata={data.ClientEncryption} data-share-url={data.ShareURL}>
      <div class="field">
        <label class="form-label" for="share-passphrase">Your encryption passphrase</label>
        <input class="form-control" id="share-passphrase" type="password" autocomplete="off" aria-describedby="share-passphrase-help">
        <div class="form-hint" id="share-passphrase-help">Use the separate passphrase you chose for encryption. It stays in your browser.</div>
      </div>
      <details>
        <summary>Recover with an encrypted key backup</summary>
        <label class="form-label mt-2" for="share-key-backup">Encrypted key backup</label>
        <input class="form-control" id="share-key-backup" type="file" accept=".json,application/json">
        <p class="form-hint">Choose your saved backup and enter its encryption passphrase above.</p>
      </details>
      <div class="actions"><button class="btn btn-primary" id="create-encrypted-link" type="submit" disabled>Create sharing link</button></div>
      <div id="encrypted-link-result" hidden>{@render linkControls()}</div>
      <p class="form-hint">Saved permissions still apply. Access changes cannot revoke keys or copies already received.</p>
      <details>
        <summary>File page address without the key</summary>
        <p class="form-hint mt-2">This address opens the file page but cannot decrypt the file by itself.</p>
        <input class="form-control" aria-label="File page address without decryption key" value={data.ShareURL} readonly>
      </details>
      <noscript>JavaScript and HTTPS are required to create a link containing the file key.</noscript>
    </form>
  {:else}
    {@render linkControls()}
    <div class="form-hint">Recipients use this link to view file details and download. Access follows the saved permissions below.</div>
  {/if}
  <div id="copy-status" class="text-secondary small mt-2" role="status" aria-live="polite"></div>
</section>

<section class="panel">
  <div class="section-heading"><h2>Who can access this file?</h2></div>
  <Form action={`/file/${data.FileID}/sharing`} csrf={data.CSRF} class="form-grid" id="sharing-permissions" data-unsaved={data.Error ? 'true' : 'false'}>
    <div class="field">
      <label class="form-label" for="share-mode">Access</label>
      <select class="form-select" id="share-mode" name="share_mode">
        <option value="link" selected={data.Mode === 'link'}>Anyone with the link</option>
        <option value="signed_in" selected={data.Mode === 'signed_in'}>Signed-in users</option>
        <option value="selected" selected={data.Mode === 'selected'}>Selected accounts</option>
        <option value="private" selected={data.Mode === 'private'}>Private — only me</option>
      </select>
      <div class="form-hint">Only you can change sharing, rename, or delete. Shared recipients can view and download.</div>
    </div>
    <div class="field" id="sharing-recipients">
      <label class="form-label" for="recipients">Selected account email addresses</label>
      <textarea class="form-control" id="recipients" name="recipients" rows="4" maxlength="20000" placeholder="person@example.com" aria-describedby="recipient-help" value={data.Recipients}></textarea>
      <div class="form-hint" id="recipient-help">Used only for Selected accounts. Enter up to 50 existing account addresses, separated by commas or new lines. Recipients must log in; send them the link yourself. Saving another access option clears this list.</div>
    </div>
    {#if !data.User}
      <div class="alert alert-info">This browser's owner cookie controls this guest upload. Keep it to manage the file or open it when private.</div>
    {/if}
    <p class="text-secondary">Changes apply to new requests. Downloads already in progress or copies already saved cannot be recalled. Storage download links issued while sharing with anyone remain usable until they expire.</p>
    <div class="actions"><button class="btn btn-primary" type="submit">Save permissions</button></div>
  </Form>
</section>
