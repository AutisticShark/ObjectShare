<script lang="ts">
  let { label, name, checked, description }: { label: string; name: string; checked: boolean; description?: string } = $props();
</script>

<label class="form-check">
  <input class="form-check-input" {name} type="checkbox" {checked}>
  <span class="form-check-label">{label}</span>
  {#if description}<span class="form-check-description">{description}</span>{/if}
</label>
