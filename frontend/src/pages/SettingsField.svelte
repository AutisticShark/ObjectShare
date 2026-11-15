<script lang="ts">
  // One labelled input of the configuration form. Secrets use SecretField.
  let { label, name, value = '', id = name, type = 'text', hint, placeholder, min, max, step, minlength, maxlength, required = false, readonly = false, class: className = '' }: {
    label: string; name: string; value?: string | number; id?: string; type?: string; hint?: string; placeholder?: string;
    min?: number; max?: number; step?: number; minlength?: number; maxlength?: number;
    required?: boolean; readonly?: boolean; class?: string;
  } = $props();
</script>

<div class="field">
  <label class="form-label" for={id}>{label}</label>
  <input class={`form-control ${className}`.trim()} {id} {name} {type} {value} {placeholder} {min} {max} {step} {minlength} {maxlength} {required} {readonly}>
  {#if hint}<div class="form-hint">{hint}</div>{/if}
</div>
