<script lang="ts">
  import type { UploadResultsPageData } from '../lib/pages';

  let { data }: { data: UploadResultsPageData } = $props();
  const files = $derived(data.Files ?? []);
</script>

<section class="panel">
  <div class="section-heading"><h2>{files.length} {files.length === 1 ? 'file' : 'files'} uploaded</h2></div>
  <ul class="list-group list-group-flush">
    {#each files as file (file.ID)}
      <li class="list-group-item d-flex align-items-center justify-content-between gap-3">
        <div>
          <strong class="text-break">{file.Name}</strong>
        </div>
        <a class="btn btn-sm" href={`/file/${file.ID}`} aria-label={`Open ${file.Name}`}>Open</a>
      </li>
    {/each}
  </ul>
  <div class="actions"><a class="btn btn-primary" href="/">Upload more</a></div>
</section>
