<script lang="ts">
  import Pagination from '../components/Pagination.svelte';
  import type { FilesPageData } from '../lib/pages';

  let { data }: { data: FilesPageData } = $props();
  const files = $derived(data.Files ?? []);
  const filtered = $derived(Boolean(data.Search || data.Filter));
</script>

{#if data.QuotaLabel}
  <p class="d-flex flex-wrap gap-2 justify-content-between">
    <span>{data.QuotaLabel}</span>
    <a href="/plans">Explore storage plans</a>
  </p>
{/if}

<form action="/files" method="get" class="filter-bar" role="search">
  <div class="field">
    <label class="form-label" for="file-search">Search filenames</label>
    <input type="search" class="form-control" name="q" id="file-search" value={data.Search} maxlength="255" placeholder="Find a file…">
  </div>
  <div class="field">
    <label class="form-label" for="access-filter">Access</label>
    <select class="form-select" name="filter" id="access-filter">
      <option value="">All access levels</option>
      <option value="link" selected={data.Filter === 'link'}>Anyone with the link</option>
      <option value="signed_in" selected={data.Filter === 'signed_in'}>Signed-in users</option>
      <option value="selected" selected={data.Filter === 'selected'}>Selected accounts</option>
      <option value="private" selected={data.Filter === 'private'}>Only me</option>
    </select>
  </div>
  <button class="btn btn-primary" type="submit">Search</button>
</form>

<section class="panel">
  {#if files.length}
    <div class="table-responsive">
      <table class="table table-vcenter data-table">
        <caption class="visually-hidden">Your completed uploads, newest first</caption>
        <thead><tr><th scope="col">File</th><th scope="col">Access</th><th scope="col">Size</th><th scope="col">Uploaded</th><th scope="col">Actions</th></tr></thead>
        <tbody>
          {#each files as file (file.ID)}
            <tr>
              <td class="workspace-filename">
                <a class="fw-medium" href={`/file/${file.ID}`}>{file.Name}</a>
                {#if file.Encrypted}<div class="text-secondary small">Encrypted in your browser</div>{/if}
              </td>
              <td>{file.Access}</td>
              <td class="text-nowrap">{file.Size}</td>
              <td class="text-secondary text-nowrap">{file.CreatedAt}</td>
              <td>
                <div class="d-flex gap-2">
                  <a class="btn btn-sm" href={`/file/${file.ID}/sharing`} aria-label={`Share ${file.Name}`}>Share</a>
                  <a class="btn btn-sm" href={`/file/${file.ID}`} aria-label={`Manage ${file.Name}`}>Manage</a>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="empty-state">
      <p class="empty-title">{filtered ? 'No files match your search' : 'Your files will appear here'}</p>
      <p class="text-secondary">{filtered ? 'Try another filename or access level.' : 'Upload while signed in to manage your files from any device.'}</p>
      {#if filtered}<a class="btn" href="/files">Clear filters</a>{:else}<a class="btn btn-primary" href="/">Upload your first file</a>{/if}
    </div>
  {/if}
  <Pagination page={data.Page} previous={data.PreviousURL ?? ''} next={data.NextURL ?? ''} />
</section>

