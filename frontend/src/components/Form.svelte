<script lang="ts">
  import type { Snippet } from 'svelte';
  let { action, csrf = '', children, class: className = '', confirm, enhance = true, ...rest }: {
    action: string; csrf?: string; children: Snippet; class?: string;
    confirm?: string; enhance?: boolean; [key: string]: unknown;
  } = $props();
</script>

<form {action} method="post" class={className}
  hx-post={enhance ? action : undefined}
  hx-select={enhance ? '.page' : undefined}
  hx-target={enhance ? '.page' : undefined}
  hx-swap={enhance ? 'outerHTML' : undefined}
  hx-disabled-elt={enhance ? 'button[type="submit"]' : undefined}
  hx-confirm={confirm} {...rest}>
  {#if csrf}<input type="hidden" name="csrf_token" value={csrf}>{/if}
  {@render children()}
</form>
