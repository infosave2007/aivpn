<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores/auth.svelte';
  import { auth } from '$lib/api';
  import { startAuthentication } from '@simplewebauthn/browser';

  let username = $state('');
  let password = $state('');

  // Settings redirects here with ?reason=reauth after a security change
  // (password/2FA/passkey) revokes every session — explain the forced logout.
  const reauthNotice = $derived($page.url.searchParams.get('reason') === 'reauth');
  let totpCode = $state('');
  let requiresTotp = $state(false);
  let loading = $state(false);
  let error = $state('');

  type OidcMode = 'disabled' | 'enabled' | 'exclusive';
  let oidcMode = $state<OidcMode>('disabled');

  onMount(async () => {
    try {
      const r = await fetch('/web/auth/oidc/config');
      if (r.ok) {
        const data = await r.json() as { mode: OidcMode };
        oidcMode = data.mode ?? 'disabled';
      }
    } catch { /* OIDC not configured */ }
  });

  async function handleLogin() {
    loading = true;
    error = '';
    try {
      const res = await auth.login(username, password);
      if (res.totp_required) {
        requiresTotp = true;
      } else if (res.access_token) {
        authStore.setToken(res.access_token);
        const user = await auth.me();
        authStore.setUser(user);
        goto('/dashboard');
      }
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'Login failed';
    } finally {
      loading = false;
    }
  }

  async function handleTotpLogin() {
    loading = true;
    error = '';
    try {
      const res = await auth.loginTotp(username, password, totpCode);
      authStore.setToken(res.access_token);
      const user = await auth.me();
      authStore.setUser(user);
      goto('/dashboard');
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'Invalid code';
    } finally {
      loading = false;
    }
  }

  async function handlePasskeyLogin() {
    loading = true;
    error = '';
    try {
      const options = await auth.passkeyAuthOptions();
      const credential = await startAuthentication({ optionsJSON: options as Parameters<typeof startAuthentication>[0]['optionsJSON'] });
      const res = await auth.passkeyAuthenticate(credential);
      authStore.setToken(res.access_token);
      const user = await auth.me();
      authStore.setUser(user);
      goto('/dashboard');
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'Passkey authentication failed';
    } finally {
      loading = false;
    }
  }
</script>

<div class="min-h-screen flex items-center justify-center px-4" style="background: #160F2F">
  <div class="w-full max-w-sm">
    <!-- Logo -->
    <div class="text-center mb-8">
      <img src="/aivpn-icon.svg" alt="aiVPN" class="w-16 h-16 mx-auto mb-4 drop-shadow-lg" />
      <h1 class="text-2xl font-bold text-white">aiVPN Admin</h1>
      <p class="text-sm mt-1" style="color: rgba(123,97,255,0.75)">Sign in to your account</p>
    </div>

    <!-- Card -->
    <div class="rounded-2xl p-6" style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(12px)">
      {#if reauthNotice && !error}
        <div class="mb-4 p-3 rounded-lg text-sm" style="background: rgba(123,97,255,0.12); border: 1px solid rgba(123,97,255,0.4); color: #c4b5fd">
          Security settings were changed — all sessions were signed out. Please sign in again.
        </div>
      {/if}
      {#if error}
        <div class="mb-4 p-3 rounded-lg text-sm" style="background: rgba(220,38,38,0.15); border: 1px solid rgba(220,38,38,0.4); color: #fca5a5">
          {error}
        </div>
      {/if}

      <!-- OIDC exclusive: only SSO button -->
      {#if oidcMode === 'exclusive'}
        <div class="space-y-3">
          <p class="text-center text-sm" style="color: rgba(255,255,255,0.5)">Authentication via your organization SSO</p>
          <a
            href="/web/auth/oidc/start"
            class="flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg text-sm font-semibold transition-colors"
            style="background: #7B61FF; color: #fff"
          >
            Sign in with SSO
          </a>
        </div>

      {:else if !requiresTotp}
        <!-- Password form (disabled in exclusive mode) -->
        <form onsubmit={(e) => { e.preventDefault(); handleLogin(); }} class="space-y-4">
          <div>
            <label class="block text-sm font-medium mb-1" style="color: rgba(255,255,255,0.7)" for="username">Username</label>
            <input
              id="username"
              type="text"
              autocomplete="username"
              bind:value={username}
              required
              class="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2"
              style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; --tw-ring-color: #7B61FF"
              placeholder="admin"
            />
          </div>
          <div>
            <label class="block text-sm font-medium mb-1" style="color: rgba(255,255,255,0.7)" for="password">Password</label>
            <input
              id="password"
              type="password"
              bind:value={password}
              required
              class="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2"
              style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; --tw-ring-color: #7B61FF"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            class="w-full py-2 px-4 rounded-lg text-sm font-semibold transition-colors disabled:opacity-50"
            style="background: #7B61FF; color: #fff"
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <div class="mt-4 relative">
          <div class="absolute inset-0 flex items-center">
            <div class="w-full" style="border-top: 1px solid rgba(255,255,255,0.1)"></div>
          </div>
          <div class="relative flex justify-center">
            <span class="px-2 text-xs" style="background: transparent; color: rgba(255,255,255,0.35)">or</span>
          </div>
        </div>

        <div class="mt-4 space-y-2">
          <button
            onclick={handlePasskeyLogin}
            disabled={loading}
            class="w-full py-2 px-4 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            style="border: 1px solid rgba(255,255,255,0.2); color: rgba(255,255,255,0.7)"
          >
            Sign in with Passkey
          </button>

          {#if oidcMode === 'enabled'}
            <a
              href="/web/auth/oidc/start"
              class="flex items-center justify-center w-full py-2 px-4 rounded-lg text-sm font-medium transition-colors"
              style="border: 1px solid rgba(123,97,255,0.5); color: #7B61FF"
            >
              Sign in with SSO
            </a>
          {/if}
        </div>

      {:else}
        <!-- TOTP step -->
        <form onsubmit={(e) => { e.preventDefault(); handleTotpLogin(); }} class="space-y-4">
          <p class="text-sm" style="color: rgba(255,255,255,0.5)">Enter your 2FA verification code.</p>
          <div>
            <label class="block text-sm font-medium mb-1" style="color: rgba(255,255,255,0.7)" for="totp">Authentication Code</label>
            <input
              id="totp"
              type="text"
              inputmode="numeric"
              bind:value={totpCode}
              required
              maxlength="6"
              class="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 tracking-widest text-center text-lg"
              style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); color: #fff; --tw-ring-color: #7B61FF"
              placeholder="000000"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            class="w-full py-2 px-4 rounded-lg text-sm font-semibold transition-colors disabled:opacity-50"
            style="background: #7B61FF; color: #fff"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </button>
          <button type="button" onclick={() => { requiresTotp = false; error = ''; }} class="w-full text-sm" style="color: rgba(255,255,255,0.4)">
            Back
          </button>
        </form>
      {/if}
    </div>
  </div>
</div>
