<script lang="ts">
  let { page = 1, previous = '', next = '' }: { page?: number; previous?: string; next?: string } = $props();
</script>
{#if previous || next}
  <nav class="pagination-bar" aria-label="Pagination">
    <span>Page {page}</span>
    <div>{#if previous}<a class="btn" href={previous} rel="prev">Previous</a>{/if}{#if next}<a class="btn" href={next} rel="next">Next</a>{/if}</div>
  </nav>
{/if}
