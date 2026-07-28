<script lang="ts">
  import { goto } from '$app/navigation';
  import { createQuery, createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { auth } from '$lib/api';
  import { authStore } from '$lib/stores/auth.svelte';
  import QrModal from '$lib/components/QrModal.svelte';
  import { startRegistration } from '@simplewebauthn/browser';
  import { Trash2, Plus } from 'lucide-svelte';

  const qc = useQueryClient();

  type Tab = 'security' | '2fa' | 'passkeys' | 'sessions';
  let activeTab = $state<Tab>('security');

  /**
   * The security endpoints (change password, TOTP enable/disable, passkey
   * add/remove) revoke ALL sessions server-side and answer { logout: true }.
   * Honour it: clear local auth state and return to the login screen —
   * otherwise the page keeps a dead session where every next request 401s.
   * Returns true when a logout redirect happened.
   */
  function handleLogoutResponse(res: { logout?: boolean } | void): boolean {
    if (res && res.logout) {
      authStore.clearToken();
      goto('/login?reason=reauth');
      return true;
    }
    return false;
  }

  // Security tab
  let oldPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let pwToast = $state('');
  let pwError = $state(false);

  const changePwMut = createMutation({
    mutationFn: () => auth.changePassword(oldPassword, newPassword),
    onSuccess: (res) => {
      if (handleLogoutResponse(res)) return;
      pwToast = 'Password changed';
      pwError = false;
      oldPassword = ''; newPassword = ''; confirmPassword = '';
      setTimeout(() => { pwToast = ''; }, 3000);
    },
    onError: (e: Error) => { pwToast = e.message; pwError = true; setTimeout(() => { pwToast = ''; }, 4000); },
  });

  // 2FA tab
  let totpUri = $state('');
  let totpCode = $state('');
  let totpToast = $state('');
  let totpQrOpen = $state(false);
  let totpEnabled = $state(false);

  // Seed the 2FA state from the server — it always started as false, so for
  // a user who already had TOTP enabled the tab offered "Enable 2FA" (which
  // 409s) and the Disable button was unreachable.
  const meQuery = createQuery({ queryKey: ['me'], queryFn: () => auth.me() });
  $effect(() => {
    if ($meQuery.data) totpEnabled = $meQuery.data.totp_enabled;
  });

  const totpSetupMut = createMutation({
    mutationFn: () => auth.totpSetup(),
    onSuccess: (data) => { totpUri = data.otpauth_url; totpQrOpen = true; },
    onError: (e: Error) => { totpToast = e.message; setTimeout(() => { totpToast = ''; }, 4000); },
  });

  const totpVerifyMut = createMutation({
    mutationFn: () => auth.totpVerify(totpCode),
    onSuccess: (res) => {
      if (handleLogoutResponse(res)) return;
      totpEnabled = true; totpUri = ''; totpCode = ''; totpQrOpen = false; totpToast = '2FA enabled'; setTimeout(() => { totpToast = ''; }, 3000);
    },
    onError: (e: Error) => { totpToast = e.message; setTimeout(() => { totpToast = ''; }, 4000); },
  });

  const totpDeleteMut = createMutation({
    mutationFn: () => auth.totpDelete(),
    onSuccess: (res) => {
      if (handleLogoutResponse(res)) return;
      totpEnabled = false; totpToast = '2FA disabled'; setTimeout(() => { totpToast = ''; }, 3000);
    },
    onError: (e: Error) => { totpToast = e.message; setTimeout(() => { totpToast = ''; }, 4000); },
  });

  // Passkeys tab
  const passkeysQuery = createQuery({ queryKey: ['passkeys'], queryFn: () => auth.passkeys() });
  let passkeyName = $state('');
  let passkeyToast = $state('');

  const passkeyRegMut = createMutation({
    mutationFn: async () => {
      const options = await auth.passkeyRegistrationOptions();
      const credential = await startRegistration({ optionsJSON: options as Parameters<typeof startRegistration>[0]['optionsJSON'] });
      return auth.passkeyRegister(credential, passkeyName);
    },
    onSuccess: (res) => {
      if (handleLogoutResponse(res)) return;
      qc.invalidateQueries({ queryKey: ['passkeys'] }); passkeyName = ''; passkeyToast = 'Passkey added'; setTimeout(() => { passkeyToast = ''; }, 3000);
    },
    onError: (e: Error) => { passkeyToast = e.message; setTimeout(() => { passkeyToast = ''; }, 4000); },
  });

  const passkeyDelMut = createMutation({
    mutationFn: (id: string) => auth.passkeyDelete(id),
    onSuccess: (res) => {
      if (handleLogoutResponse(res)) return;
      qc.invalidateQueries({ queryKey: ['passkeys'] });
    },
    onError: (e: Error) => { passkeyToast = e.message; setTimeout(() => { passkeyToast = ''; }, 4000); },
  });

  // Sessions tab
  const sessionsQuery = createQuery({ queryKey: ['sessions'], queryFn: () => auth.sessions() });
  // Revoking a session is a security action: a failure that shows nothing
  // reads as success, leaving the operator believing an attacker's session
  // is gone when it is still live. Report it like every other mutation here.
  let sessionToast = $state('');

  const sessionDelMut = createMutation({
    mutationFn: (id: string) => auth.sessionDelete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
    onError: (e: Error) => { sessionToast = e.message; setTimeout(() => { sessionToast = ''; }, 4000); },
  });

  const sessionsDelAllMut = createMutation({
    mutationFn: () => auth.sessionsDeleteAll(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
    onError: (e: Error) => { sessionToast = e.message; setTimeout(() => { sessionToast = ''; }, 4000); },
  });

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'security', label: 'Security' },
    { id: '2fa', label: '2FA' },
    { id: 'passkeys', label: 'Passkeys' },
    { id: 'sessions', label: 'Sessions' },
  ];
</script>

<div class="max-w-2xl space-y-6">
  <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>

  <div class="border-b border-gray-200 dark:border-gray-700">
    <nav class="flex gap-6">
      {#each tabs as tab}
        <button
          onclick={() => { activeTab = tab.id; }}
          class="pb-3 text-sm font-medium border-b-2 transition-colors
            {activeTab === tab.id
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}"
        >
          {tab.label}
        </button>
      {/each}
    </nav>
  </div>

  {#if activeTab === 'security'}
    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Change Password</h2>
      {#if pwToast}
        <div class="p-3 rounded-lg text-sm {pwError ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200' : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200'}">
          {pwToast}
        </div>
      {/if}
      <form onsubmit={(e) => { e.preventDefault(); if (newPassword !== confirmPassword) { pwToast = 'Passwords do not match'; pwError = true; return; } $changePwMut.mutate(); }} class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="old-pw">Current Password</label>
          <input id="old-pw" type="password" bind:value={oldPassword} required class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="new-pw">New Password</label>
          <input id="new-pw" type="password" bind:value={newPassword} required class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="confirm-pw">Confirm Password</label>
          <input id="confirm-pw" type="password" bind:value={confirmPassword} required class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        </div>
        <button type="submit" disabled={$changePwMut.isPending} class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
          {$changePwMut.isPending ? 'Saving...' : 'Change Password'}
        </button>
      </form>
    </div>

  {:else if activeTab === '2fa'}
    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Two-Factor Authentication</h2>
      {#if totpToast}
        <div class="p-3 rounded-lg text-sm bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200">{totpToast}</div>
      {/if}
      {#if !totpEnabled}
        {#if !totpUri}
          <p class="text-sm text-gray-600 dark:text-gray-400">2FA is not enabled. Enable it for additional security.</p>
          <button
            onclick={() => $totpSetupMut.mutate()}
            disabled={$totpSetupMut.isPending}
            class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
          >
            {$totpSetupMut.isPending ? 'Loading...' : 'Enable 2FA'}
          </button>
        {:else}
          <p class="text-sm text-gray-600 dark:text-gray-400">Scan the QR code, then enter the code to confirm.</p>
          <button onclick={() => { totpQrOpen = true; }} class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700">
            Show QR Code
          </button>
          <form onsubmit={(e) => { e.preventDefault(); $totpVerifyMut.mutate(); }} class="flex gap-3">
            <input
              type="text"
              inputmode="numeric"
              bind:value={totpCode}
              maxlength="6"
              placeholder="000000"
              required
              class="w-32 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 text-center tracking-widest"
            />
            <button type="submit" disabled={$totpVerifyMut.isPending} class="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
              Verify
            </button>
          </form>
        {/if}
      {:else}
        <p class="text-sm text-green-600 dark:text-green-400 font-medium">2FA is enabled.</p>
        <button
          onclick={() => { if (confirm('Disable 2FA?')) $totpDeleteMut.mutate(); }}
          class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium"
        >
          Disable 2FA
        </button>
      {/if}
    </div>

  {:else if activeTab === 'passkeys'}
    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Passkeys</h2>
      {#if passkeyToast}
        <div class="p-3 rounded-lg text-sm bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200">{passkeyToast}</div>
      {/if}
      {#if $passkeysQuery.data}
        <ul class="space-y-2">
          {#each $passkeysQuery.data as pk (pk.id)}
            <li class="flex items-center justify-between p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
              <div>
                <p class="text-sm font-medium text-gray-900 dark:text-white">{pk.name}</p>
                <p class="text-xs text-gray-400">Created {new Date(pk.created_at).toLocaleDateString()}{pk.last_used_at ? ` · Last used ${new Date(pk.last_used_at).toLocaleDateString()}` : ''}</p>
              </div>
              <button
                onclick={() => { if (confirm('Delete passkey?')) $passkeyDelMut.mutate(pk.id); }}
                class="p-1.5 text-gray-400 hover:text-red-600 rounded"
              >
                <Trash2 size={15} />
              </button>
            </li>
          {/each}
          {#if $passkeysQuery.data.length === 0}
            <p class="text-sm text-gray-400">No passkeys registered.</p>
          {/if}
        </ul>
      {/if}
      <form onsubmit={(e) => { e.preventDefault(); $passkeyRegMut.mutate(); }} class="flex gap-3">
        <input
          type="text"
          bind:value={passkeyName}
          placeholder="Passkey name"
          required
          class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <button type="submit" disabled={$passkeyRegMut.isPending} class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
          <Plus size={16} />
          Add
        </button>
      </form>
    </div>

  {:else if activeTab === 'sessions'}
    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
      <div class="flex items-center justify-between">
        <h2 class="text-base font-semibold text-gray-900 dark:text-white">Active Sessions</h2>
        <button
          onclick={() => { if (confirm('Revoke all other sessions?')) $sessionsDelAllMut.mutate(); }}
          disabled={$sessionsDelAllMut.isPending}
          class="text-xs text-red-600 hover:underline disabled:opacity-50"
        >
          Revoke all others
        </button>
      </div>
      {#if sessionToast}
        <div class="p-3 rounded-lg text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800">{sessionToast}</div>
      {/if}
      {#if $sessionsQuery.data}
        <ul class="space-y-2">
          {#each $sessionsQuery.data as session (session.id)}
            <li class="flex items-center justify-between p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
              <div>
                <p class="text-sm text-gray-700 dark:text-gray-300">
                  Created {new Date(session.created_at).toLocaleString()}
                  {#if session.current}<span class="ml-2 text-xs text-indigo-500 font-medium">(current)</span>{/if}
                </p>
                <p class="text-xs text-gray-400">Expires {new Date(session.expires_at).toLocaleString()}</p>
              </div>
              {#if !session.current}
                <button
                  onclick={() => $sessionDelMut.mutate(session.id)}
                  class="p-1.5 text-gray-400 hover:text-red-600 rounded"
                >
                  <Trash2 size={15} />
                </button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</div>

<QrModal open={totpQrOpen} data={totpUri} title="Scan with authenticator app" onClose={() => { totpQrOpen = false; }} />
