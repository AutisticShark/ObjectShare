<script lang="ts">
  import Form from '../components/Form.svelte';
  import type { BillingSummaryData } from '../lib/pages';

  let { data }: { data: BillingSummaryData } = $props();
  const gateways = $derived(data.TopUpGateways ?? []);
  const transactions = $derived(data.CreditTransactions ?? []);
</script>

<section class="panel">
  <div class="section-heading">
    <h2>Plan</h2>
    {#if data.PlanActive}
      <span class="badge bg-green-lt">Active</span>
    {:else if data.BillingAccount}
      <span class="badge bg-yellow-lt">{data.PlanStatus}</span>
    {/if}
  </div>
  {#if data.PlanActive}
    <div class="h3 mb-1">{data.PlanName}</div>
    <p class="text-secondary">
      {#if data.CreditPlan}Prepaid plan; benefits remain active until {data.PlanRenews}.
      {:else if data.PlanCanceling}Benefits remain active until {data.PlanRenews}.
      {:else}Current period ends {data.PlanRenews}.{/if}
    </p>
  {:else if data.BillingAccount}
    <div class="h3 mb-1">{data.PlanName}</div>
    <p class="text-secondary">Plan benefits are paused because access is {data.PlanStatus}.{data.CreditPlan ? '' : " Open the gateway's billing settings to review payment or cancellation details."}</p>
  {:else}
    <p class="text-secondary">You are using your account's standard storage and retention settings.</p>
  {/if}
  <div class="actions">
    <a class="btn" href="/invoices">Invoices</a>
    <a class="btn" href="/plans">View plans</a>
    {#if data.BillingAccount && !data.CreditPlan}
      <Form action="/billing/portal" csrf={data.CSRF} enhance={false}>
        <button class="btn btn-primary" type="submit" disabled={!data.BillingEnabled}>Manage billing</button>
      </Form>
    {/if}
  </div>
</section>

{#if data.CreditBalance}
  <section class="panel">
    <div class="section-heading">
      <h2>Account credit</h2>
      <span class="h2 mb-0">{data.CreditBalance}</span>
    </div>
    <p class="text-secondary small">One credit equals one {data.CreditCurrency}. Gateway refunds are not applied automatically; an administrator must adjust the credit balance.</p>
    <div class="form-grid">
      {#each gateways as gateway (gateway.Key)}
        <Form action={`/billing/topup/${gateway.Key}`} csrf={data.CSRF} enhance={false}>
          <label class="form-label" for={`topup-${gateway.Key}`}>Top up with {gateway.Label}</label>
          <div class="input-group">
            <input class="form-control" id={`topup-${gateway.Key}`} name="credits" type="number" min={data.MinTopUpCredits} max={data.MaxTopUpCredits} step="1" value={data.MinTopUpCredits} required>
            <span class="input-group-text">credits</span>
            <button class="btn btn-primary" type="submit">Continue</button>
          </div>
          <div class="form-hint">Whole credits from {data.MinTopUpCredits} to {data.MaxTopUpCredits}.</div>
        </Form>
      {:else}
        <p class="text-secondary mb-0">Top-ups are unavailable until an administrator enables a billing gateway.</p>
      {/each}
    </div>
    {#if transactions.length}
      <div class="table-responsive">
        <table class="table table-vcenter data-table">
          <thead><tr><th>Activity</th><th>Date</th><th class="text-end">Change</th><th class="text-end">Balance</th></tr></thead>
          <tbody>
            {#each transactions as transaction, index (index)}
              <tr>
                <td>{transaction.Description}</td>
                <td class="text-secondary">{transaction.CreatedAt}</td>
                <td class="text-end"><span class="badge {transaction.Positive ? 'bg-green-lt' : 'bg-red-lt'}">{transaction.Delta}</span></td>
                <td class="text-end">{transaction.Balance}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}
