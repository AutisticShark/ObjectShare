<script lang="ts">
  import Form from '../components/Form.svelte';
  import Captcha from '../components/Captcha.svelte';
  import type { AuthPageData, AuthPageName } from '../lib/pages';

  let { data, page }: { data: AuthPageData; page: AuthPageName } = $props();
  const providers = $derived(data.OAuthProviders ?? []);
</script>

<section class="panel auth-panel">
  <Form action={`/${page}`} csrf={data.CSRF} class="form-grid">
    {#if page === 'login'}
      <input type="hidden" name="next" value={data.Next ?? ''}>
    {/if}
    {#if page === 'setup'}
      <p class="text-secondary">This one-time step secures the management panel. Additional administrators can be created later from the user directory.</p>
    {/if}
    {#if data.Error}<div class="alert alert-danger" role="alert">{data.Error}</div>{/if}

    {#if page === 'setup' && data.SetupTokenRequired}
      <div class="field">
        <label class="form-label" for="setup-token">Setup token</label>
        <input class="form-control" id="setup-token" name="setup_token" type="password" autocomplete="off" maxlength="512" required>
        <small class="form-hint">Enter the OBJECTSHARE_SETUP_TOKEN value configured for this server.</small>
      </div>
    {/if}

    {#if page !== 'login'}
      <div class="field">
        <label class="form-label" for="display-name">Display name</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input class="form-control" id="display-name" name="display_name" value={data.DisplayName ?? ''} autocomplete="name" maxlength="100" required autofocus>
      </div>
    {/if}

    <div class="field">
      <label class="form-label" for="email">Email address</label>
      {#if page === 'login'}
        <!-- svelte-ignore a11y_autofocus -->
        <input class="form-control" id="email" name="email" type="email" value={data.Email ?? ''} autocomplete="email" maxlength="320" required autofocus>
      {:else}
        <input class="form-control" id="email" name="email" type="email" value={data.Email ?? ''} autocomplete="email" maxlength="320" required>
      {/if}
    </div>

    {#if page === 'login'}
      <div class="field">
        <label class="form-label" for="password">Password</label>
        <input class="form-control" id="password" name="password" type="password" autocomplete="current-password" maxlength="512" required>
      </div>
    {:else}
      <div class="field">
        <label class="form-label" for="password">Password</label>
        <input class="form-control" id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="512" required>
        <small class="form-hint">{page === 'setup' ? 'Use 12 to 128 characters and store it in a password manager.' : 'Use 12 to 128 characters.'}</small>
      </div>
      <div class="field">
        <label class="form-label" for="password-confirm">Confirm password</label>
        <input class="form-control" id="password-confirm" name="password_confirm" type="password" autocomplete="new-password" minlength="12" maxlength="512" required>
      </div>
    {/if}

    {#if page !== 'setup'}<Captcha captcha={data.Captcha} />{/if}

    <div class="actions">
      <button class="btn btn-primary w-100" type="submit">{page === 'login' ? 'Log in' : page === 'signup' ? 'Create account' : 'Finish setup'}</button>
    </div>

    {#if page === 'login' && providers.length}
      <div class="hr-text my-2">or</div>
      <div class="d-grid gap-2">
        {#each providers as provider (provider.Key)}
          {#if data.Captcha}
            <button class="btn" type="submit" formaction={provider.URL} formmethod="post" formnovalidate hx-post={provider.URL}>Continue with {provider.Label}</button>
          {:else}
            <a class="btn" href={provider.URL}>Continue with {provider.Label}</a>
          {/if}
        {/each}
      </div>
    {/if}
  </Form>

  {#if page === 'login' && data.SignupEnabled}
    <p class="text-secondary text-center mt-3 mb-0">New here? <a href="/signup">Create an account</a></p>
  {:else if page === 'signup'}
    <p class="text-secondary text-center mt-3 mb-0">Already registered? <a href="/login">Log in</a></p>
  {/if}
</section>
