<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount, onDestroy } from 'svelte';
  import { QueryClient, QueryClientProvider } from '@tanstack/svelte-query';
  import { authStore } from '$lib/stores/auth.svelte';
  import { themeStore } from '$lib/stores/theme.svelte';
  import { auth, refreshAccessToken } from '$lib/api';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';

  let { children } = $props();

  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: 1, staleTime: 30_000 },
    },
  });
  const unsubscribeSession = authStore.onSessionChange(() => queryClient.clear());
  onDestroy(unsubscribeSession);

  const isLoginPage = $derived($page.url.pathname === '/login');

  onMount(async () => {
    if (isLoginPage) return;
    if (!authStore.accessToken) {
      // The access token is memory-only (never persisted); re-mint it from
      // the httpOnly refresh cookie. This also completes the OIDC landing
      // flow, which only sets the refresh cookie. refreshAccessToken is
      // coalesced with any concurrent 401-triggered refresh from page queries
      // — parallel refreshes would rotate the cookie out from under each other.
      try {
        await refreshAccessToken();
      } catch {
        goto('/login');
        return;
      }
    }
    // Always revalidate the identity/role against the server — the user
    // object is memory-only and must never be trusted from a previous state
    // (an admin demotion has to show up on the next page load).
    try {
      const user = await auth.me();
      authStore.setUser(user);
    } catch {
      authStore.clearToken();
      goto('/login');
    }
  });

  $effect(() => {
    if (themeStore.theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  });
</script>

<QueryClientProvider client={queryClient}>
  {#if isLoginPage}
    {@render children()}
  {:else}
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Sidebar />
      <div class="ml-60 min-h-screen">
        <header class="sticky top-0 z-10 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-3 flex items-center justify-end">
          <ThemeToggle />
        </header>
        <main class="p-6">
          {@render children()}
        </main>
      </div>
    </div>
  {/if}
</QueryClientProvider>
