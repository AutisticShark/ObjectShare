<script lang="ts">
  import type { AdminOverviewPageData } from '../lib/pages';

  let { data }: { data: AdminOverviewPageData } = $props();
  const stats = $derived(data.Stats);
  const checks = $derived(data.Checks ?? []);
</script>

<section class="panel">
  <div class="section-heading"><h2>Site overview</h2></div>
  <div class="table-responsive">
    <table class="table table-vcenter data-table">
      <thead><tr><th scope="col">Measure</th><th scope="col" class="text-end">Count</th><th scope="col">Detail</th></tr></thead>
      <tbody>
        <tr>
          <th scope="row"><a href="/admin/users">Registered users</a></th>
          <td class="text-end">{stats.Users}</td>
          <td class="text-secondary">{stats.DisabledUsers} disabled · {stats.BannedUsers} banned · {stats.ShadowbannedUsers} shadowbanned</td>
        </tr>
        <tr>
          <th scope="row">Stored files</th>
          <td class="text-end">{stats.Files}</td>
          <td class="text-secondary">{data.Storage} · {stats.PendingUploads} pending uploads</td>
        </tr>
        <tr>
          <th scope="row"><a href="/admin/plans">Active plan periods</a></th>
          <td class="text-end">{stats.ActivePlans}</td>
          <td class="text-secondary">Active or trialing, before expiry</td>
        </tr>
        <tr>
          <th scope="row"><a href="/admin/invoices">Paid invoices</a></th>
          <td class="text-end">{stats.PaidInvoices}</td>
          <td class="text-secondary">{stats.PendingInvoices} pending · {stats.UnsentReceipts} unsent receipts</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="text-secondary small mb-0">Active storage backend: <strong>{data.StorageService}</strong>. Counts reflect database records when this page loads; stored size excludes pending uploads and storage-provider overhead.</p>
</section>

<section class="panel">
  <div class="section-heading">
    <h2>Launch configuration</h2>
  </div>
  <p class="text-secondary small">Configuration indicators, not live provider or deployment tests.</p>
  <div class="table-responsive">
    <table class="table table-vcenter data-table">
      <thead><tr><th scope="col">Check</th><th scope="col">Status</th><th scope="col">Detail</th></tr></thead>
      <tbody>
        {#each checks as check (check.Name)}
          <tr>
            <th scope="row"><a href={check.URL}>{check.Name}</a></th>
            <td><span class="badge {check.Configured ? 'bg-green-lt' : 'bg-secondary-lt'}">{check.Configured ? 'Configured' : 'Not enabled'}</span></td>
            <td class="text-secondary">{check.Detail}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
