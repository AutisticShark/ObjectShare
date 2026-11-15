<script lang="ts">
  import BillingSummary from './BillingSummary.svelte';
  import type { BillingPageData } from '../lib/pages';

  let { data }: { data: BillingPageData } = $props();
</script>

{#if data.QuotaLabel}<p class="text-secondary">{data.QuotaLabel} <a href="/files">Manage files</a></p>{/if}
<BillingSummary {data} />
