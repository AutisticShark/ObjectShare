<script lang="ts">
  import Form from '../components/Form.svelte';
  import type {
    BillingProblemPageData,
    MessagePageName,
    OAuthContinuePageData,
    OAuthErrorPageData,
    VerifyEmailPageData,
  } from '../lib/pages';

  let { data, page }: {
    data: VerifyEmailPageData | OAuthErrorPageData | OAuthContinuePageData | BillingProblemPageData;
    page: MessagePageName;
  } = $props();

  const verify = $derived(data as VerifyEmailPageData);
  const oauthError = $derived(data as OAuthErrorPageData);
  const oauthContinue = $derived(data as OAuthContinuePageData);
  const problem = $derived(data as BillingProblemPageData);
  const siteName = $derived(data.Branding?.SiteName || 'ObjectShare');
</script>

<svelte:head>
  {#if page === 'oauth_continue'}<meta http-equiv="refresh" content={`0;url=${oauthContinue.Location}`}>{/if}
</svelte:head>

{#if page === 'verify_email'}
  <section class="panel auth-panel">
    {#if verify.Success}
      <div class="alert alert-success" role="status">Your email address is verified. You can return to your account, or log in if needed.</div>
    {:else if data.Error}
      <div class="alert alert-danger" role="alert">{data.Error}</div>
    {:else}
      <p>Confirm that you requested email verification for your {siteName} account.</p>
      <Form action="/verify-email" csrf={data.CSRF} enhance={false}>
        <input type="hidden" name="user" value={verify.UserID ?? ''}>
        <input type="hidden" name="token" value={verify.Token ?? ''}>
        <button class="btn btn-primary w-100" type="submit">Verify email</button>
      </Form>
    {/if}
    <div class="actions"><a class="btn w-100" href="/account">My account</a></div>
  </section>
{:else if page === 'oauth_error'}
  <section class="panel auth-panel">
    <div class="alert alert-danger" role="alert">{data.Error}</div>
    <div class="actions"><a class="btn btn-primary w-100" href={oauthError.Back}>{oauthError.BackLabel}</a></div>
  </section>
{:else if page === 'oauth_continue'}
  <section class="panel auth-panel text-center">
    <p class="text-secondary">Taking you back to {siteName}.</p>
    <div class="actions"><a class="btn btn-primary w-100" href={oauthContinue.Location}>Continue</a></div>
  </section>
{:else if page === 'billing_problem'}
  <section class="panel">
    <div class="alert alert-warning" role="alert">{data.Message}</div>
    <div class="actions">
      {#if problem.InvoiceURL}
        <a class="btn btn-primary" href={problem.InvoiceURL}>Return to invoice</a>
      {:else}
        <a class="btn btn-primary" href="/invoices">View your invoices</a>
      {/if}
      <a class="btn" href="/billing">Billing overview</a>
      <a class="btn" href="/plans">View plans</a>
    </div>
  </section>
{/if}
