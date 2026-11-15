<script lang="ts">
  import Form from '../components/Form.svelte';
  import Icon from '../components/Icon.svelte';
  import Pagination from '../components/Pagination.svelte';
  import type { AdminUsersPageData } from '../lib/pages';

  let { data }: { data: AdminUsersPageData } = $props();
  const users = $derived(data.Users ?? []);
  const suffix = $derived(data.QuerySuffix ?? '');
</script>

<div class="directory-toolbar">
  <form action="/admin/users" method="get" class="filter-bar" role="search">
    <input class="form-control" type="search" name="q" value={data.Search} maxlength="255" placeholder="Search users" aria-label="Search by name, email, or account ID">
    <select class="form-select" name="filter" aria-label="Filter users">
      <option value="">All accounts</option>
      <option value="admin" selected={data.Filter === 'admin'}>Administrators</option>
      <option value="disabled" selected={data.Filter === 'disabled'}>Disabled</option>
      <option value="banned" selected={data.Filter === 'banned'}>Banned</option>
      <option value="shadowbanned" selected={data.Filter === 'shadowbanned'}>Shadowbanned</option>
      <option value="verified" selected={data.Filter === 'verified'}>Email verified</option>
      <option value="unverified" selected={data.Filter === 'unverified'}>Email unverified</option>
    </select>
    <button class="btn" type="submit">Search</button>
    {#if data.Search || data.Filter}<a class="btn" href="/admin/users">Clear</a>{/if}
  </form>
  <button class="btn btn-primary" type="button" data-user-dialog-open="create-user" aria-haspopup="dialog" aria-controls="create-user"><Icon name="plus" size={17} />Create user</button>
</div>

<section class="panel directory-panel">
  <div class="directory-summary"><span>{data.TotalUsers} accounts</span><span>{data.TotalStorageUsed} stored</span></div>
  <div class="table-responsive">
    <table class="data-table">
      <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Storage</th><th scope="col">Credit</th><th scope="col">Last login</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody>
        {#each users as user (user.ID)}
          <tr>
            <td class="user-identity"><div class="fw-medium">{user.DisplayName}{#if user.IsCurrent}<span class="text-secondary small"> · You</span>{/if}</div><div class="text-secondary small">{user.Email}</div></td>
            <td>{user.Role === 'admin' ? 'Admin' : 'User'}</td>
            <td><span class:status-warning={!user.Active || !!user.ModerationStatus} class="status-label">{user.ModerationStatus === 'banned' ? 'Banned' : user.ModerationStatus === 'shadowbanned' ? 'Shadowbanned' : user.Active ? 'Active' : 'Disabled'}</span></td>
            <td class="nowrap">{user.StorageUsed}</td><td class="nowrap">{user.CreditBalance}</td><td class="text-secondary nowrap">{user.LastLogin}</td>
            <td><button class="btn btn-sm" type="button" data-user-dialog-open={`user-actions-${user.ID}`} aria-haspopup="dialog" aria-controls={`user-actions-${user.ID}`} aria-label={`Manage ${user.Email}`}>Manage</button></td>
          </tr>
        {:else}<tr><td colspan="7"><div class="empty-state"><h2>No users found</h2>{#if data.Search || data.Filter}<a href="/admin/users">Clear filters</a>{/if}</div></td></tr>{/each}
      </tbody>
    </table>
  </div>
  <Pagination page={data.Page} previous={data.PreviousURL ?? ''} next={data.NextURL ?? ''} />
</section>

<dialog class="admin-user-dialog" id="create-user" aria-labelledby="create-user-title">
  <div class="dialog-header"><h2 id="create-user-title">Create user</h2><button class="icon-button" type="button" data-user-dialog-close aria-label="Close"><Icon name="close" /></button></div>
  {#if data.Error}<div class="alert alert-danger" role="alert">{data.Error}</div>{/if}
  <Form action={`/admin/users${suffix}`} csrf={data.CSRF} data-user-dialog-form="create-user">
    <div class="form-grid">
      <div class="field"><label class="form-label" for="new-display-name">Display name</label><input class="form-control" id="new-display-name" name="display_name" maxlength="100" required></div>
      <div class="field"><label class="form-label" for="new-email">Email</label><input class="form-control" id="new-email" name="email" type="email" maxlength="320" required></div>
      <div class="field"><label class="form-label" for="new-role">Role</label><select class="form-select" id="new-role" name="role"><option value="user">User</option><option value="admin">Administrator</option></select></div>
      <div class="field"><label class="form-label" for="new-upload-quota">Storage quota (MiB)</label><input class="form-control" id="new-upload-quota" name="upload_quota_mib" type="number" min="0" step="1" value="0" required><div class="form-hint">0 means unlimited.</div></div>
      <div class="field"><label class="form-label" for="new-password">Password</label><input class="form-control" id="new-password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="512" required></div>
      <div class="field"><label class="form-label" for="new-password-confirm">Confirm password</label><input class="form-control" id="new-password-confirm" name="password_confirm" type="password" autocomplete="new-password" minlength="12" maxlength="512" required></div>
    </div>
    <label class="form-check mt-3"><input class="form-check-input" name="is_paid" type="checkbox"><span class="form-check-label">Exempt from unpaid file retention</span></label>
    <div class="actions"><button class="btn btn-primary" type="submit">Create user</button></div>
  </Form>
</dialog>

{#each users as user (user.ID)}
  {@const dialogID = `user-actions-${user.ID}`}
  <dialog class="admin-user-dialog" id={dialogID} aria-labelledby={`user-title-${user.ID}`}>
    <div class="dialog-header"><div><h2 id={`user-title-${user.ID}`}>{user.DisplayName}</h2><div class="text-secondary small break-anywhere">{user.Email} · {user.EmailVerified ? 'Verified' : 'Unverified'}</div></div><button class="icon-button" type="button" data-user-dialog-close aria-label="Close"><Icon name="close" /></button></div>
    <p class="text-secondary small">Created {user.CreatedAt} · {user.StorageUsed} stored</p>
    {#if data.Error}<div class="alert alert-danger" role="alert">{data.Error}</div>{/if}
    <Form action={`/admin/users/${user.ID}/access${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <div class="form-grid">
        <div class="field"><label class="form-label" for={`role-${user.ID}`}>Role</label><select class="form-select" id={`role-${user.ID}`} name="role"><option value="user" selected={user.Role === 'user'}>User</option><option value="admin" selected={user.Role === 'admin'}>Administrator</option></select></div>
        <div class="field"><label class="form-label" for={`active-${user.ID}`}>Account status</label><select class="form-select" id={`active-${user.ID}`} name="active"><option value="true" selected={user.Active}>Active</option><option value="false" selected={!user.Active}>Disabled</option></select></div>
      </div>
      <div class="actions"><button class="btn" type="submit">Save access</button></div>
    </Form>
    <Form action={`/admin/users/${user.ID}/moderation${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <label class="form-label" for={`moderation-${user.ID}`}>Moderation</label>
      <select class="form-select" id={`moderation-${user.ID}`} name="moderation_status"><option value="" selected={!user.ModerationStatus}>No ban</option><option value="banned" selected={user.ModerationStatus === 'banned'}>Banned</option><option value="shadowbanned" selected={user.ModerationStatus === 'shadowbanned'}>Shadowbanned</option></select>
      <p class="form-hint">Bans block sign-in and hide owned files. Shadowbanned users can sign in, but only they can see their files. Your own account and the final available administrator are protected.</p>
      <button class="btn" type="submit">Save moderation</button>
    </Form>
    <Form action={`/admin/users/${user.ID}/quota${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <label class="form-label" for={`quota-${user.ID}`}>Storage quota (MiB)</label><input class="form-control" id={`quota-${user.ID}`} name="upload_quota_mib" type="number" min="0" step="1" value={user.UploadQuotaMiB} required><div class="form-hint">0 means unlimited. This does not delete existing files.</div>
      <div class="actions"><button class="btn" type="submit">Save quota</button></div>
    </Form>
    <Form action={`/admin/users/${user.ID}/paid${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <label class="form-label" for={`retention-${user.ID}`}>Unpaid file retention</label><select class="form-select" id={`retention-${user.ID}`} name="is_paid"><option value="false" selected={!user.IsPaid}>Apply retention policy</option><option value="true" selected={user.IsPaid}>Exempt</option></select>
      <p class="form-hint">Independent of paid plans and storage quota. Removing an exemption can make older files eligible for deletion.</p><button class="btn" type="submit">Save retention</button>
    </Form>
    <Form action={`/admin/users/${user.ID}/credit${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <h3>Account credit · {user.CreditBalance}</h3><input type="hidden" name="credit_request_id" value={user.CreditRequestID}>
      <div class="form-grid"><div class="field"><label class="form-label" for={`credit-${user.ID}`}>Adjustment</label><input class="form-control" id={`credit-${user.ID}`} name="credit_delta" type="number" min="-1000000000" max="1000000000" step="1" required></div><div class="field"><label class="form-label" for={`reason-${user.ID}`}>Reason</label><input class="form-control" id={`reason-${user.ID}`} name="credit_description" maxlength="200" required></div></div>
      <div class="actions"><button class="btn" type="submit">Record adjustment</button></div>
    </Form>
    <Form action={`/admin/users/${user.ID}/password${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID}>
      <h3>Reset password</h3>
      <div class="form-grid"><div class="field"><label class="form-label" for={`password-${user.ID}`}>New password</label><input class="form-control" id={`password-${user.ID}`} name="password" type="password" autocomplete="new-password" minlength="12" maxlength="512" required></div><div class="field"><label class="form-label" for={`password-confirm-${user.ID}`}>Confirm password</label><input class="form-control" id={`password-confirm-${user.ID}`} name="password_confirm" type="password" autocomplete="new-password" minlength="12" maxlength="512" required></div></div>
      {#if data.HasPassword}<div class="field mt-3"><label class="form-label" for={`admin-password-${user.ID}`}>Your current password</label><input class="form-control" id={`admin-password-${user.ID}`} name="admin_password" type="password" autocomplete="current-password" maxlength="512" required></div>{:else}<p class="form-hint">Sign in again within five minutes before resetting a password.</p>{/if}
      <p class="form-hint">All existing login tokens for this account will be invalidated.</p><button class="btn" type="submit">Reset password</button>
    </Form>
    <Form action={`/admin/users/${user.ID}/delete${suffix}`} csrf={data.CSRF} data-user-dialog-form={dialogID} confirm={`Delete ${user.Email}? Their uploads will remain available but become anonymous.`}>
      <p class="form-hint">Remove any ban first. Existing uploads remain available as guest files.</p><button class="btn btn-outline-danger" type="submit">Delete user</button>
    </Form>
  </dialog>
{/each}
