<script lang="ts">
  let { captcha }: { captcha?: { SiteKey: string; Action: string } | null } = $props();
</script>
{#if captcha}
  <div class="captcha-field"><div class="objectshare-turnstile" data-sitekey={captcha.SiteKey} data-action={captcha.Action}></div></div>
{/if}
