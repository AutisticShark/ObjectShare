<script lang="ts">
  import Pagination from '../components/Pagination.svelte';
  import { date } from '../lib/format';
  import { invoiceTotal } from '../lib/pages';
  import type { AdminInvoicesPageData, InvoicesPageData, PageInvoice } from '../lib/pages';

  let { data, admin = false }: { data: InvoicesPageData | AdminInvoicesPageData; admin?: boolean } = $props();

  const invoices: PageInvoice[] = $derived(data.Invoices ?? []);
  const own = $derived(data as InvoicesPageData);
  const directory = $derived(data as AdminInvoicesPageData);
</script>

{#if admin}
  <form action="/admin/invoices" method="get" class="filter-bar" role="search">
    <div class="field">
      <label class="form-label" for="invoice-search">Customer, purchase, invoice ID, or payment reference</label>
      <input type="search" class="form-control" name="q" id="invoice-search" value={directory.Search} maxlength="255" placeholder="Search invoices…">
    </div>
    <div class="field">
      <label class="form-label" for="invoice-filter">Status</label>
      <select class="form-select" name="filter" id="invoice-filter">
        <option value="">All invoices</option>
        <option value="pending" selected={directory.Filter === 'pending'}>Pending payment</option>
        <option value="paid" selected={directory.Filter === 'paid'}>Paid</option>
        <option value="unsent" selected={directory.Filter === 'unsent'}>Paid · receipt unsent</option>
      </select>
    </div>
    <button class="btn btn-primary" type="submit">Search</button>
  </form>

  <section class="panel">
    <div class="table-responsive">
      <table class="table table-vcenter data-table">
        <caption class="visually-hidden">Customer invoices, newest first</caption>
        <thead><tr><th scope="col">Purchase / invoice</th><th scope="col">Customer</th><th scope="col">Total</th><th scope="col">Payment</th><th scope="col">Receipt</th></tr></thead>
        <tbody>
          {#each invoices as invoice (invoice.ID)}
            <tr>
              <td class="workspace-filename">
                <strong>{invoice.Name}</strong>
                <div class="small text-secondary text-break">{invoice.ID}</div>
                <div class="small text-secondary">{date(invoice.CreatedAt, true)}</div>
              </td>
              <td class="text-break">{invoice.Email}</td>
              <td class="text-nowrap">{invoiceTotal(invoice)}</td>
              <td class="workspace-filename">
                <span class="badge {invoice.Status === 'paid' ? 'bg-green-lt' : 'bg-yellow-lt'}">{invoice.Status}</span>
                {#if invoice.Gateway}<div class="small mt-1">{invoice.Gateway}</div>{/if}
                {#if invoice.PaymentID}<div class="small text-secondary text-break">{invoice.PaymentID}</div>{/if}
                {#if invoice.Status === 'pending'}<div class="small text-secondary mt-1">Window ends {date(invoice.ExpiresAt, true)}</div>{/if}
              </td>
              <td>
                {#if invoice.Status === 'paid'}
                  {#if invoice.EmailSentAt}<span class="badge bg-green-lt">Provider accepted</span>{:else}<span class="badge bg-yellow-lt">Unsent</span>{/if}
                {:else}
                  <span class="text-secondary">After payment</span>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="5">
              <div class="empty-state">
                <p class="empty-title">No invoices found</p>
                <p class="text-secondary">Invoices appear when customers choose a plan or start a top-up.</p>
                {#if directory.Search || directory.Filter}<a class="btn" href="/admin/invoices">Clear filters</a>{/if}
              </div>
            </td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    <Pagination page={directory.Page} previous={directory.PreviousURL ?? ''} next={directory.NextURL ?? ''} />
  </section>
  <p class="text-secondary">Pending invoices may include expired payment windows. Unsent receipts include queued messages and invoices waiting for email configuration. Confirm ambiguous payments with the payment provider before adjusting an account. Refunds are not applied automatically.</p>
{:else}
  <section class="panel">
    {#if invoices.length}
      <div class="table-responsive">
        <table class="table table-vcenter data-table">
          <thead><tr><th>Invoice</th><th>Purchase</th><th>Total</th><th>Status</th><th>Issued (UTC)</th><th></th></tr></thead>
          <tbody>
            {#each invoices as invoice (invoice.ID)}
              <tr>
                <td><a href={`/invoices/${invoice.ID}`}>{invoice.ID}</a></td>
                <td>{invoice.Name}</td>
                <td>
                  {invoiceTotal(invoice)}
                  {#if invoice.Credits > 0}<div class="text-secondary">{invoice.Credits} credits</div>{/if}
                </td>
                <td><span class="badge {invoice.Status === 'paid' ? 'bg-green-lt' : 'bg-yellow-lt'}">{invoice.Status}</span></td>
                <td>{date(invoice.CreatedAt, true)}</td>
                <td><a href={`/invoices/${invoice.ID}/pdf`}>PDF</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty-state">
        {#if own.Page > 0}
          <p class="empty-title">No invoices on this page</p>
          <p class="text-secondary">Return to the first page to see your latest invoices.</p>
          <a class="btn" href="/invoices">View latest invoices</a>
        {:else}
          <p class="empty-title">You have no invoices yet</p>
          <p class="text-secondary">Choose a plan to review your first invoice. Payment comes afterward.</p>
          <a class="btn btn-primary" href="/plans">Choose a plan</a>
        {/if}
      </div>
    {/if}
    <Pagination
      page={own.Page + 1}
      previous={own.Page > 0 ? `/invoices?page=${own.PreviousPage}` : ''}
      next={own.HasNext ? `/invoices?page=${own.NextPage}` : ''} />
  </section>
{/if}
