<script lang="ts">
  import Form from '../components/Form.svelte';
  import type { PlansPageData } from '../lib/pages';

  let { data }: { data: PlansPageData } = $props();
  const plans = $derived(data.Plans ?? []);
</script>

{#if data.User}<p class="text-secondary">Balance: <strong class="text-reset">{data.CreditBalance}</strong></p>{/if}
<p class="text-secondary">One payment for a fixed period. Review your invoice before paying; new prepaid plans do not renew automatically.</p>
{#if !data.BillingEnabled}<div class="alert alert-info">No plans are currently available for purchase.</div>{/if}
{#if data.VerificationRequired}<div class="alert alert-warning"><a href="/account">Verify your email from My account</a> before purchasing a plan.</div>{/if}

<div class="plan-grid">
  {#each plans as plan (plan.ID)}
    <section class="panel plan-card">
      <div class="section-heading"><h2>{plan.Name}</h2></div>
      <div class="h1 mb-1">{plan.CurrencyPrice || plan.Price}</div>
      <div class="text-secondary mb-3">{plan.Price} · one-time payment</div>
      {#if plan.Description}<p class="text-secondary">{plan.Description}</p>{/if}
      <ul class="list-unstyled">
        <li><strong>{plan.Storage}</strong> storage</li>
        <li><strong>{plan.Retention}</strong> retention while active</li>
        <li>{plan.DirectLinks ? 'Direct download links included' : 'Downloads use the file details page'}</li>
        <li>Access for <strong>{plan.Duration}</strong></li>
      </ul>
      {#if data.User}
        <Form action={`/billing/invoices/${plan.ID}`} csrf={data.CSRF} enhance={false}>
          <input type="hidden" name="credit_request_id" value={plan.RequestID}>
          <button class="btn btn-outline-primary w-100" type="submit" disabled={data.VerificationRequired}>Review invoice</button>
        </Form>
      {:else}
        <a class="btn btn-primary w-100" href="/login?next=plans">Log in to upgrade</a>
      {/if}
    </section>
  {:else}
    <div class="empty-state">
      <p class="empty-title">No paid plans are available yet</p>
      <p class="text-secondary">An administrator can configure the plan catalog.</p>
    </div>
  {/each}
</div>
