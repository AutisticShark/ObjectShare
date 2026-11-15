<script lang="ts">
  import type { Snippet } from 'svelte';
  let { action, csrf = '', children, class: className = '', confirm, enhance = true, ...rest }: {
    action: string; csrf?: string; children: Snippet; class?: string;
    confirm?: string; enhance?: boolean; [key: string]: unknown;
  } = $props();
</script>

<form {action} method="post" class={className} data-enhance={enhance ? '' : undefined} data-confirm={confirm} {...rest}>
  {#if csrf}<input type="hidden" name="csrf_token" value={csrf}>{/if}
  {@render children()}
</form>
