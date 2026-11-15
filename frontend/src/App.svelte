<script lang="ts">
  import { onMount } from 'svelte';
  import Form from './components/Form.svelte';
  import Icon from './components/Icon.svelte';
  import Upload from './pages/Upload.svelte';
  import type { UploadData } from './pages/Upload.svelte';
  import Auth from './pages/Auth.svelte';
  import MFA from './pages/MFA.svelte';
  import Account from './pages/Account.svelte';
  import Billing from './pages/Billing.svelte';
  import Plans from './pages/Plans.svelte';
  import Invoices from './pages/Invoices.svelte';
  import Invoice from './pages/Invoice.svelte';
  import Files from './pages/Files.svelte';
  import FileView from './pages/FileView.svelte';
  import Sharing from './pages/Sharing.svelte';
  import UploadResults from './pages/UploadResults.svelte';
  import AdminOverview from './pages/AdminOverview.svelte';
  import AdminUsers from './pages/AdminUsers.svelte';
  import AdminPlans from './pages/AdminPlans.svelte';
  import AdminSettings from './pages/AdminSettings.svelte';
  import Message from './pages/Message.svelte';
  import type { Bootstrap } from './lib/bootstrap';
  import type {
    BasePage, AuthPageData, MFAPageData, AccountPageData, BillingPageData, PlansPageData,
    InvoicesPageData, AdminInvoicesPageData, InvoicePageData, FilesPageData, FileViewPageData,
    SharingPageData, UploadResultsPageData, AdminOverviewPageData, AdminUsersPageData,
    AdminPlansPageData, AdminSettingsPageData, MessagePageData, MessagePageName,
  } from './lib/pages';

  let { boot }: { boot: Bootstrap } = $props();
  const data = $derived({ ...boot.Data, Branding: boot.Branding } as unknown as BasePage);
  const user = $derived(data.User);
  const page = $derived(boot.Page);
  const admin = $derived(page.startsWith('admin_'));
  const auth = $derived(['login', 'signup', 'setup', 'mfa', 'oauth_error', 'oauth_continue', 'verify_email'].includes(page));
  const billing = $derived(['billing', 'plans', 'invoices', 'invoice'].includes(page));
  let menuOpen = $state(false);
  let dark = $state(false);
  let themeError = $state('');
  let menuButton: HTMLButtonElement;
  const titles: Record<string, string> = {
    index: 'Upload', files: 'My files', account: 'My account', billing: 'Billing',
    plans: 'Plans', invoices: 'Invoices', invoice: 'Invoice', upload_results: 'Upload complete',
    login: 'Log in', signup: 'Create account', setup: 'Create administrator', mfa: 'Two-step verification',
    admin_dashboard: 'Overview', admin_users: 'Users', admin_plans: 'Plan catalog',
    admin_invoices: 'Invoices', admin_settings: 'Configuration', verify_email: 'Verify email',
    oauth_error: 'Unable to sign in', oauth_continue: 'Continue', billing_problem: 'Payment could not be completed',
  };
  const title = $derived(page === 'file_view' ? String(boot.Data.FileName || 'File') : page === 'sharing' ? `Share ${String(boot.Data.FileName || 'file')}` : titles[page] || boot.Branding.SiteName);
  const showBanner = $derived(!['login', 'signup', 'setup', 'mfa', 'oauth_error', 'oauth_continue', 'verify_email', 'billing_problem'].includes(page));
  const adminLinks = [
    { href: '/admin', page: 'admin_dashboard', label: 'Overview' },
    { href: '/admin/users', page: 'admin_users', label: 'Users' },
    { href: '/admin/plans', page: 'admin_plans', label: 'Plan catalog' },
    { href: '/admin/invoices', page: 'admin_invoices', label: 'Invoices' },
    { href: '/admin/settings', page: 'admin_settings', label: 'Configuration' },
  ];

  onMount(() => {
    const preference = matchMedia('(prefers-color-scheme: dark)');
    const apply = (value: boolean) => {
      dark = value;
      document.documentElement.dataset.bsTheme = value ? 'dark' : 'light';
      document.documentElement.dataset.themePreference = user ? 'account' : 'system';
      const meta = document.querySelector('meta[name="theme-color"]');
      meta?.setAttribute('content', value ? '#1a1e25' : '#ffffff');
    };
    apply(user ? user.DarkMode : preference.matches);
    const systemTheme = () => { if (!user) apply(preference.matches); };
    const accountTheme = (event: Event) => {
      const theme = (event as CustomEvent<{ theme: string }>).detail?.theme;
      if (theme !== 'light' && theme !== 'dark') return;
      apply(theme === 'dark');
      themeError = '';
      const selection = document.querySelector<HTMLSelectElement>('select[name="theme"]');
      if (selection) selection.value = theme;
    };
    const failed = (event: Event) => {
      const detail = (event as CustomEvent<{ elt?: Element }>).detail;
      if (detail?.elt?.closest('[data-theme-toggle]')) themeError = 'Theme could not be saved. Try again.';
    };
    preference.addEventListener('change', systemTheme);
    document.addEventListener('objectshare:theme', accountTheme);
    document.addEventListener('htmx:responseError', failed);
    document.addEventListener('htmx:sendError', failed);
    return () => {
      preference.removeEventListener('change', systemTheme);
      document.removeEventListener('objectshare:theme', accountTheme);
      document.removeEventListener('htmx:responseError', failed);
      document.removeEventListener('htmx:sendError', failed);
    };
  });
</script>

<svelte:head>
  <title>{title === boot.Branding.SiteName ? title : `${title} · ${boot.Branding.SiteName}`}</title>
  <meta name="theme-color" content="#ffffff">
</svelte:head>
<svelte:window onkeydown={(event) => { if (event.key === 'Escape' && menuOpen) { menuOpen = false; menuButton?.focus(); } }} />

{#snippet brand()}
  <a class="brand-link" href="/">
    {#if boot.Branding.LogoURL}<img class="brand-logo" src={boot.Branding.LogoURL} alt="" referrerpolicy="no-referrer">
    {:else}<span class="brand-mark"><Icon name="files" size={20} /></span>{/if}
    <span class="brand-name">{boot.Branding.SiteName}</span>
  </a>
{/snippet}

<div class="page app-shell">
  <a href="#main-content" class="skip-link">Skip to content</a>
  <header class="mobile-header">
    {@render brand()}
    <button class="icon-button" type="button" bind:this={menuButton} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen} aria-controls="workspace-sidebar" onclick={() => menuOpen = !menuOpen}><Icon name={menuOpen ? 'close' : 'menu'} /></button>
  </header>
  {#if menuOpen}<button class="menu-backdrop" type="button" aria-label="Close navigation" onclick={() => { menuOpen = false; menuButton?.focus(); }}></button>{/if}
  <aside class:is-open={menuOpen} class="app-sidebar" id="workspace-sidebar">
    {@render brand()}
    <nav class="sidebar-nav" aria-label="Main navigation">
      <a class="sidebar-link" href="/" aria-current={page === 'index' ? 'page' : undefined}><Icon name="upload" />Upload</a>
      {#if user}
        <a class="sidebar-link" href="/files" aria-current={['files', 'file_view', 'sharing', 'upload_results'].includes(page) ? 'page' : undefined}><Icon name="files" />My files</a>
        <a class="sidebar-link" href="/billing" aria-current={billing ? 'page' : undefined}><Icon name="billing" />Billing</a>
        {#if user.Role === 'admin'}<a class="sidebar-link" href="/admin" aria-current={admin ? 'page' : undefined}><Icon name="admin" />Administration</a>{/if}
      {:else}
        <a class="sidebar-link" href="/plans" aria-current={page === 'plans' ? 'page' : undefined}><Icon name="billing" />Plans</a>
      {/if}
    </nav>
    <div class="sidebar-bottom">
      {#if user}
        <a class="sidebar-link" href="/account" aria-current={['account', 'mfa'].includes(page) ? 'page' : undefined}><Icon name="account" />My account</a>
        <div class="sidebar-divider"></div>
        <a class="sidebar-account" href="/account"><span class="account-avatar">{user.DisplayName.slice(0, 1).toLocaleUpperCase()}</span><span class="account-name" title={user.DisplayName}>{user.DisplayName}</span></a>
        <div class="sidebar-utilities">
          <Form action="/logout" csrf={data.CSRF}><button class="logout-button" type="submit"><Icon name="logout" size={16} />Log out</button></Form>
          <form action="/account/theme" method="post" data-theme-toggle hx-post="/account/theme" hx-swap="none" hx-disabled-elt="button">
            <input type="hidden" name="csrf_token" value={data.CSRF}>
            <input type="hidden" name="theme_toggle" value="true">
            <input type="hidden" name="theme" value={dark ? 'light' : 'dark'}>
            <button class="icon-button" type="submit" aria-label={`Switch to ${dark ? 'light' : 'dark'} theme`} title={`Switch to ${dark ? 'light' : 'dark'} theme`}><Icon name={dark ? 'sun' : 'moon'} size={18} /></button>
          </form>
        </div>
        {#if themeError}<p class="small text-danger" data-theme-status role="status">{themeError}</p>{/if}
      {:else}
        <a class="sidebar-link" href="/login" aria-current={page === 'login' ? 'page' : undefined}><Icon name="account" />Log in</a>
        {#if boot.Data.SignupEnabled}<a class="sidebar-link" href="/signup" aria-current={page === 'signup' ? 'page' : undefined}><Icon name="plus" />Create account</a>{/if}
      {/if}
    </div>
  </aside>
  <div class="app-main">
    <main id="main-content" class:auth-content={auth} class="workspace-content" tabindex="-1">
      {#if page === 'index' && boot.Branding.HeaderImageURL}<img class="site-banner" src={boot.Branding.HeaderImageURL} alt={`${boot.Branding.SiteName} header`} referrerpolicy="no-referrer">{/if}
      <div class="page-heading"><h1>{title}</h1>{#if page === 'files'}<a class="btn btn-primary" href="/"><Icon name="upload" size={17} />Upload</a>{/if}</div>
      {#if page === 'index' && boot.Branding.Tagline}<p class="site-tagline">{boot.Branding.Tagline}</p>{/if}
      {#if admin}
        <nav class="admin-tabs" aria-label="Administration">{#each adminLinks as link}<a href={link.href} aria-current={page === link.page ? 'page' : undefined}>{link.label}</a>{/each}</nav>
      {:else if billing && user}
        <nav class="admin-tabs" aria-label="Billing"><a href="/billing" aria-current={page === 'billing' ? 'page' : undefined}>Overview</a><a href="/plans" aria-current={page === 'plans' ? 'page' : undefined}>Plans</a><a href="/invoices" aria-current={['invoices', 'invoice'].includes(page) ? 'page' : undefined}>Invoices</a></nav>
      {/if}
      {#if showBanner && data.Error && page !== 'admin_users'}<div class="alert alert-danger status-banner" role="alert">{data.Error}</div>{/if}
      {#if showBanner && data.Message}<div class="alert alert-success status-banner" role="status">{data.Message}</div>{/if}
      {#if page === 'index'}<Upload data={data as unknown as UploadData} />
      {:else if page === 'login' || page === 'signup' || page === 'setup'}<Auth data={data as AuthPageData} {page} />
      {:else if page === 'mfa'}<MFA data={data as MFAPageData} />
      {:else if page === 'account'}<Account data={data as AccountPageData} />
      {:else if page === 'billing'}<Billing data={data as BillingPageData} />
      {:else if page === 'plans'}<Plans data={data as PlansPageData} />
      {:else if page === 'invoices'}<Invoices data={data as InvoicesPageData} />
      {:else if page === 'invoice'}<Invoice data={data as InvoicePageData} />
      {:else if page === 'files'}<Files data={data as FilesPageData} />
      {:else if page === 'file_view'}<FileView data={data as FileViewPageData} />
      {:else if page === 'sharing'}<Sharing data={data as SharingPageData} />
      {:else if page === 'upload_results'}<UploadResults data={data as UploadResultsPageData} />
      {:else if page === 'admin_dashboard'}<AdminOverview data={data as AdminOverviewPageData} />
      {:else if page === 'admin_users'}<AdminUsers data={data as AdminUsersPageData} />
      {:else if page === 'admin_plans'}<AdminPlans data={data as AdminPlansPageData} />
      {:else if page === 'admin_invoices'}<Invoices data={data as AdminInvoicesPageData} admin />
      {:else if page === 'admin_settings'}<AdminSettings data={data as AdminSettingsPageData} />
      {:else}<Message data={data as MessagePageData} page={page as MessagePageName} />{/if}
    </main>
    <footer class="app-footer">
      {#if boot.Branding.FooterMessage}<div class="footer-custom">{boot.Branding.FooterMessage}</div>{/if}
      {#if boot.Branding.FooterLinkURL}<a href={boot.Branding.FooterLinkURL}>{boot.Branding.FooterLinkText}</a>{/if}
      <span>ObjectShare {data.Version}</span>
      <span class="footer-credit">Made with <span role="img" aria-label="love"><Icon name="heart" size={13} /></span> by Cat</span>
    </footer>
  </div>
</div>
