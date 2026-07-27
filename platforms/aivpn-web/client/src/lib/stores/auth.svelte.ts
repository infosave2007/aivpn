interface User {
  id: number;
  username: string;
  role: string;
}

// Legacy keys — neither access tokens nor the user object are persisted any
// more (see below); purge anything written to localStorage by older builds.
const LEGACY_TOKEN_KEY = 'aivpn_access_token'
const LEGACY_USER_KEY = 'aivpn_user'

function removeFromStorage(key: string): void {
  if (typeof localStorage === 'undefined') return
  try { localStorage.removeItem(key) } catch { /* ignore */ }
}

function createAuthStore() {
  // The access token is kept in memory ONLY — never in localStorage, where
  // any XSS payload could exfiltrate it. On page reload it is re-minted from
  // the httpOnly refresh cookie (+layout.svelte bootstrap and the 401 path
  // in api.ts both call POST /web/auth/refresh).
  //
  // The user object (incl. role) is likewise memory-only: a persisted role
  // would survive an admin demotion until manually cleared, and localStorage
  // is trivially editable. +layout.svelte re-fetches /web/auth/me on every
  // mount, so the displayed identity/role is always server-validated. (The
  // role here is display-only — every privileged action is enforced
  // server-side by requireAuth/requireAdmin regardless.)
  let accessToken = $state<string | null>(null);
  let user = $state<User | null>(null);

  removeFromStorage(LEGACY_TOKEN_KEY)
  removeFromStorage(LEGACY_USER_KEY)

  function setToken(token: string) {
    accessToken = token;
  }

  function clearToken() {
    accessToken = null;
    user = null;
    removeFromStorage(LEGACY_TOKEN_KEY)
    removeFromStorage(LEGACY_USER_KEY)
  }

  function setUser(u: User) {
    user = u;
  }

  return {
    get accessToken() { return accessToken; },
    get user() { return user; },
    setToken,
    clearToken,
    setUser,
  };
}

export const authStore = createAuthStore();
