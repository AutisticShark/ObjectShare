<script lang="ts">
  // A write-only secret: empty preserves the stored value, the checkbox clears it.
  let { label, name, clearName, configured, id = name, setLabel = 'configured', clearLabel = 'Clear stored secret' }: {
    label: string; name: string; clearName: string; configured: boolean;
    id?: string; setLabel?: string; clearLabel?: string;
  } = $props();
</script>

<div class="field">
  <label class="form-label" for={id}>{label} <span class="text-secondary small">· {configured ? setLabel : 'not set'}</span></label>
  <input class="form-control" {id} {name} type="password" autocomplete="new-password">
  <label class="form-check mt-1">
    <input class="form-check-input" name={clearName} type="checkbox">
    <span class="form-check-label">{clearLabel}</span>
  </label>
</div>
