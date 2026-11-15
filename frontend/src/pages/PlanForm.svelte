<script lang="ts">
  import Form from '../components/Form.svelte';
  import type { AdminPlanRow } from '../lib/pages';

  // Create (no plan) and edit forms share one set of fields. Both post natively.
  let { action, csrf, idPrefix, submitLabel, plan }: {
    action: string; csrf: string; idPrefix: string; submitLabel: string; plan?: AdminPlanRow;
  } = $props();
</script>

<Form {action} {csrf} enhance={false} class="form-grid">
  <div class="field">
    <label class="form-label" for={`${idPrefix}-name`}>Name</label>
    <input class="form-control" id={`${idPrefix}-name`} name="name" maxlength="80" value={plan?.Name ?? ''} required>
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-description`}>Description</label>
    <input class="form-control" id={`${idPrefix}-description`} name="description" maxlength="500" value={plan?.Description ?? ''}>
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-storage`}>Storage quota (GiB)</label>
    <input class="form-control" id={`${idPrefix}-storage`} name="storage_quota_gib" type="number" min="0.01" max="10240" step="0.01" value={plan?.StorageQuotaGiB ?? ''} required>
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-retention`}>Retention days</label>
    <input class="form-control" id={`${idPrefix}-retention`} name="retention_days" type="number" min="0" max="36500" value={plan?.RetentionDays ?? 0} required>
    {#if !plan}<div class="form-hint">0 means no age-based deletion while active.</div>{/if}
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-price`}>Price</label>
    <input class="form-control" id={`${idPrefix}-price`} name="price" type="number" min="1" max="1000000000" value={plan?.Price ?? 1} required>
    {#if !plan}<div class="form-hint">Charged to the account balance in credits.</div>{/if}
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-duration`}>Access duration (days)</label>
    <input class="form-control" id={`${idPrefix}-duration`} name="duration_days" type="number" min="1" max="36500" value={plan?.DurationDays ?? 30} required>
    {#if !plan}<div class="form-hint">How long the plan lasts after purchase.</div>{/if}
  </div>
  <div class="field">
    <label class="form-label" for={`${idPrefix}-sort`}>Sort order</label>
    <input class="form-control" id={`${idPrefix}-sort`} name="sort_order" type="number" min="-10000" max="10000" value={plan?.SortOrder ?? 0} required>
  </div>
  <label class="form-check">
    <input class="form-check-input" name="direct_links" type="checkbox" checked={plan?.DirectLinks ?? false}>
    <span class="form-check-label">Direct download links</span>
  </label>
  <label class="form-check">
    <input class="form-check-input" name="active" type="checkbox" checked={plan?.Active ?? true}>
    <span class="form-check-label">Available for purchase</span>
  </label>
  <div class="actions"><button class="btn btn-primary" type="submit">{submitLabel}</button></div>
</Form>
