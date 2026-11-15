<script lang="ts">
  import PlanForm from './PlanForm.svelte';
  import type { AdminPlansPageData } from '../lib/pages';

  let { data }: { data: AdminPlansPageData } = $props();
  const plans = $derived(data.Plans ?? []);
</script>

<p class="text-secondary">Each plan has one price, paid from an invoice using account credit or an available payment gateway. Set its access duration and benefits here.</p>
<div class="alert alert-info">A plan raises a finite per-account quota but never reduces an account whose standard quota is <strong>0 (unlimited)</strong>. Set finite standard quotas in <a href="/admin/users">Users</a> before advertising storage as an upgrade.</div>

<section class="panel">
  <div class="section-heading"><h2>Add plan</h2></div>
  <PlanForm action="/admin/plans" csrf={data.CSRF} idPrefix="new-plan" submitLabel="Add plan" />
</section>

{#each plans as plan (plan.ID)}
  <section class="panel">
    <div class="section-heading">
      <h2>{plan.Name}</h2>
      {#if plan.Active}<span class="badge bg-green-lt">Available</span>{:else}<span class="badge">Hidden</span>{/if}
    </div>
    {#if plan.Price <= 0 || plan.DurationDays <= 0}
      <div class="alert alert-warning">Set a price and access duration to make this existing plan purchasable.</div>
    {/if}
    <PlanForm action={`/admin/plans/${plan.ID}`} csrf={data.CSRF} idPrefix={`plan-${plan.ID}`} submitLabel="Save plan" {plan} />
  </section>
{/each}
