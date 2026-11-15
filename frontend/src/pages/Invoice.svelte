<script lang="ts">
  import Form from '../components/Form.svelte';
  import { date } from '../lib/format';
  import { invoiceTotal } from '../lib/pages';
  import type { InvoicePageData } from '../lib/pages';

  let { data }: { data: InvoicePageData } = $props();
  const invoice = $derived(data.Invoice);
  const gateways = $derived(data.Gateways ?? []);
  const paid = $derived(invoice.Status === 'paid');
  const insufficient = $derived(data.User.CreditBalance < invoice.Credits);
</script>

<div class="actions">
  <a href="/invoices">All invoices</a>
  <a class="btn btn-outline-primary" href={`/invoices/${invoice.ID}/pdf`}>Download PDF</a>
</div>

<section class="panel invoice-document">
  <div class="section-heading">
    <div>
      <h2>{data.Branding?.SiteName || 'ObjectShare'}</h2>
      <div class="text-break">Invoice {invoice.ID}</div>
      <div class="text-secondary">Issued {date(invoice.CreatedAt, true)}</div>
    </div>
    <div class="text-md-end">
      <span class="badge {paid ? 'bg-green-lt' : 'bg-yellow-lt'}">{invoice.Status}</span>
      <div class="mt-2 text-break">Billed to {invoice.Email}</div>
    </div>
  </div>

  <div class="table-responsive">
    <table class="table data-table">
      <thead><tr><th>Purchase</th><th>Quantity</th><th class="text-end">Total</th></tr></thead>
      <tbody>
        <tr>
          <td>
            <strong>{invoice.Name}</strong>
            <div class="text-secondary text-break">{invoice.Description}</div>
            {#if invoice.Kind === 'plan'}<div class="mt-2">{invoice.DurationDays} days of access · {invoice.Credits} credits</div>{/if}
          </td>
          <td>1</td>
          <td class="text-end text-nowrap">{invoiceTotal(invoice)}</td>
        </tr>
      </tbody>
    </table>
  </div>

  {#if paid}
    <div class="alert alert-success mt-4">Payment confirmed{invoice.PaidAt ? ` on ${date(invoice.PaidAt, true)}` : ''}. {invoice.Kind === 'topup' ? 'Your account credit has been added.' : 'Your plan purchase has been recorded.'}</div>
    <p>Payment method: {invoice.Gateway}</p>
    <p class="text-break">Payment reference: {invoice.PaymentID}</p>
    <p class="text-secondary">
      {#if invoice.EmailSentAt}The payment confirmation and invoice PDF were accepted by the email provider.
      {:else if data.ReceiptEnabled}Your payment confirmation and invoice PDF are queued for email delivery.
      {:else}Email receipts are not enabled on this website. Your payment is confirmed; download the invoice PDF here for your records.{/if}
    </p>
  {:else}
    <p class="text-secondary mt-4">Payment window ends {date(invoice.ExpiresAt, true)}. Your purchase is activated only after payment is confirmed.</p>
    {#if invoice.Gateway}
      {#if data.CheckoutExpired}
        <div class="alert alert-info">The {invoice.Gateway} checkout started for this invoice has expired without a confirmed payment, so it can no longer be completed.{data.CanPay && gateways.length ? ' Pay again below to open a new checkout.' : ''} If you already paid, refresh this page to check payment status, and contact the site administrator if it does not update.</div>
      {:else}
        <div class="alert alert-info">A {invoice.Gateway} payment is in progress. Complete the original checkout, then refresh this page to check payment status. If you canceled or the payment window has ended, contact the site administrator to reconcile the payment.</div>
      {/if}
    {/if}
  {/if}

  {#if data.CanPay}
    <div class="actions">
      {#if invoice.Kind === 'plan' && invoice.Gateway === ''}
        <Form action={`/invoices/${invoice.ID}/pay`} csrf={data.CSRF} enhance={false}>
          <input type="hidden" name="gateway" value="credit">
          <button class="btn btn-primary" type="submit" disabled={insufficient}>Pay {invoice.Credits} credits from account</button>
          <div class="form-hint">Account balance: {data.User.CreditBalance} credits.{#if insufficient} <a href="/billing">Add credit</a> or choose another payment method.{/if}</div>
        </Form>
      {/if}
      {#each gateways as gateway (gateway.Key)}
        <Form action={`/invoices/${invoice.ID}/pay`} csrf={data.CSRF} enhance={false}>
          <input type="hidden" name="gateway" value={gateway.Key}>
          <button class="btn btn-outline-primary" type="submit">Pay with {gateway.Label}</button>
        </Form>
      {/each}
    </div>
  {:else if data.VerificationRequired}
    <div class="alert alert-warning"><a href="/account">Verify your email from My account</a> before paying for this plan.</div>
  {:else if invoice.Status === 'pending'}
    <div class="alert alert-warning">This invoice’s payment window has ended. Any payment already received will still be reconciled. <a href="/plans">Return to plans</a>.</div>
  {/if}
</section>
