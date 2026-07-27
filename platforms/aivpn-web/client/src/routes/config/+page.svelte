<script lang="ts">
  import { createQuery, createMutation } from '@tanstack/svelte-query';
  import { config as configApi, reload } from '$lib/api';
  import { Info } from 'lucide-svelte';

  interface FieldDef {
    key: string;
    label: string;
    type: 'text' | 'number' | 'checkbox';
    hint: string;
    placeholder?: string;
  }

  const FIELDS: FieldDef[] = [
    { key: 'listen_addr', label: 'Listen Address', type: 'text', hint: 'UDP address:port the server binds to (e.g. 0.0.0.0:443)', placeholder: '0.0.0.0:443' },
    { key: 'tun_name', label: 'TUN Interface Name', type: 'text', hint: 'Kernel TUN device created at startup', placeholder: 'aivpn0' },
    { key: 'tun_addr', label: 'TUN IP Address', type: 'text', hint: 'Server-side VPN IP assigned to the TUN interface', placeholder: '10.8.0.1' },
    { key: 'tun_netmask', label: 'TUN Netmask', type: 'text', hint: 'Subnet mask for the VPN network', placeholder: '255.255.255.0' },
    { key: 'mask_dir', label: 'Mask Directory', type: 'text', hint: 'Path to traffic mimicry mask JSON files', placeholder: '/var/lib/aivpn/masks' },
    { key: 'session_timeout_secs', label: 'Session Timeout (s)', type: 'number', hint: 'Max session lifetime in seconds. 0 = unlimited.' },
    { key: 'idle_timeout_secs', label: 'Idle Timeout (s)', type: 'number', hint: 'Disconnect idle sessions after N seconds. 0 = disabled.' },
    { key: 'tun_mtu', label: 'TUN MTU', type: 'number', hint: 'TUN interface MTU. Default 1420. Reduce if downstream links fragment packets.' },
    { key: 'allow_peer_routing', label: 'Allow Peer Routing', type: 'checkbox', hint: 'Route traffic between VPN peers (site-to-site mesh). Disable to isolate peers.' },
  ];

  // Complex sub-objects editable as raw JSON. bootstrap_publish is a valid
  // server key (management_api.rs CONFIG_KNOWN_KEYS) with no dedicated form
  // section — without it here it was impossible to edit AND (before the
  // merge-based apply below) got silently destroyed on every Apply.
  const ADVANCED_KEYS = ['network_config', 'site_to_site', 'mtls', 'dns', 'bootstrap_publish'];

  // Simple field values
  let fv = $state<Record<string, string | number | boolean>>({});

  // Pool section
  let poolEnabled = $state(false);
  let poolPeers = $state('');
  let poolSyncKey = $state('');
  let showSyncKey = $state(false); // sync_key is a shared secret — masked by default
  let poolExitNode = $state('');

  // Bootstrap mask files
  let bootstrapMasks = $state('');

  // Advanced JSON for complex sub-objects
  let advancedJson = $state('{}');
  let advancedError = $state('');
  let showAdvanced = $state(false);

  // UI
  let toast = $state('');
  let toastError = $state(false);
  let openTip = $state<string | null>(null);
  let initialized = $state(false);

  const query = createQuery({ queryKey: ['config'], queryFn: () => configApi.get() });

  $effect(() => {
    if ($query.data && !initialized) {
      initialized = true;
      const cfg = $query.data as Record<string, unknown>;
      for (const f of FIELDS) {
        if (cfg[f.key] !== undefined) fv[f.key] = cfg[f.key] as string | number | boolean;
      }
      const pool = cfg['pool'] as { peers?: string[]; sync_key?: string; exit_node?: string } | undefined;
      if (pool) {
        poolEnabled = true;
        poolPeers = (pool.peers ?? []).join('\n');
        poolSyncKey = pool.sync_key ?? '';
        poolExitNode = pool.exit_node ?? '';
      }
      const bm = cfg['bootstrap_mask_files'];
      if (Array.isArray(bm)) bootstrapMasks = bm.join('\n');
      const adv: Record<string, unknown> = {};
      for (const k of ADVANCED_KEYS) if (cfg[k] !== undefined) adv[k] = cfg[k];
      if (Object.keys(adv).length > 0) advancedJson = JSON.stringify(adv, null, 2);
    }
  });

  /**
   * Build the config to PUT by merging the form over `base` — the config the
   * server currently has. PUT /api/v1/config REPLACES the whole file, so any
   * key the form does not manage (or a key added server-side after this UI
   * shipped) must round-trip verbatim; the old whitelist-rebuild silently
   * destroyed such keys (that was the bootstrap_publish wipe) on every Apply.
   */
  function buildConfig(base: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = { ...base };
    for (const f of FIELDS) {
      const v = fv[f.key];
      if (v !== undefined && v !== '') out[f.key] = v;
      else delete out[f.key];
    }
    if (poolEnabled) {
      const peers = poolPeers.split('\n').map(s => s.trim()).filter(Boolean);
      const pool: Record<string, unknown> = { peers };
      if (poolSyncKey.trim()) pool['sync_key'] = poolSyncKey.trim();
      if (poolExitNode.trim()) pool['exit_node'] = poolExitNode.trim();
      out['pool'] = pool;
    } else {
      delete out['pool'];
    }
    const masks = bootstrapMasks.split('\n').map(s => s.trim()).filter(Boolean);
    if (masks.length) out['bootstrap_mask_files'] = masks;
    else delete out['bootstrap_mask_files'];
    try {
      const adv = JSON.parse(advancedJson) as Record<string, unknown>;
      // Only whitelisted sub-objects may come from the advanced editor —
      // a stray "listen_addr" pasted in here must not silently override
      // the corresponding form field above.
      const unknown = Object.keys(adv).filter((k) => !ADVANCED_KEYS.includes(k));
      if (unknown.length > 0) {
        advancedError = `Unsupported key(s) in advanced JSON: ${unknown.join(', ')}. Allowed: ${ADVANCED_KEYS.join(', ')}. Use the form fields above for everything else.`;
        throw new Error(advancedError);
      }
      for (const k of ADVANCED_KEYS) {
        if (adv[k] !== undefined) out[k] = adv[k];
        else delete out[k];
      }
      advancedError = '';
    } catch (e: unknown) {
      if (!advancedError) {
        advancedError = e instanceof Error ? e.message : 'Invalid JSON';
      }
      // Always an Error object — onError reads .message (a thrown string has none).
      throw e instanceof Error ? e : new Error(advancedError);
    }
    return out;
  }

  const updateMut = createMutation({
    // Re-fetch the CURRENT server config right before applying, so unknown
    // keys are merged from fresh state (not a possibly-stale cached query).
    mutationFn: async () => configApi.update(buildConfig(await configApi.get())),
    onSuccess: () => showToast('Configuration saved'),
    onError: (e: Error) => showToast(e.message, true),
  });

  const reloadMut = createMutation({
    mutationFn: () => reload.trigger(),
    onSuccess: () => showToast('Server reloaded'),
    onError: (e: Error) => showToast(e.message, true),
  });

  function showToast(msg: string, err = false) {
    toast = msg; toastError = err;
    setTimeout(() => { toast = ''; }, 3500);
  }

  function tip(key: string) { openTip = openTip === key ? null : key; }
</script>

<svelte:window onclick={(e) => { if (!(e.target as Element)?.closest('[data-tip]')) openTip = null; }} />

<div class="max-w-2xl space-y-5">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Server Config</h1>
    <div class="flex gap-2">
      <button onclick={() => $reloadMut.mutate()} disabled={$reloadMut.isPending}
        class="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50">
        {$reloadMut.isPending ? 'Reloading…' : 'Reload Server'}
      </button>
      <button onclick={() => { try { $updateMut.mutate(); } catch { /* advancedError shown inline */ } }}
        disabled={$updateMut.isPending || !!advancedError}
        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
        {$updateMut.isPending ? 'Applying…' : 'Apply'}
      </button>
    </div>
  </div>

  {#if toast}
    <div class="p-3 rounded-lg text-sm {toastError
      ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
      : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'}">
      {toast}
    </div>
  {/if}

  {#if $query.isLoading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  {:else if $query.error}
    <!-- Surface access/load errors instead of rendering an empty form a
         viewer could "Apply" (wiping the config they cannot even read). -->
    <div class="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-xl text-sm text-amber-800 dark:text-amber-300">
      {($query.error as Error).message.includes('403') || ($query.error as Error).message.toLowerCase().includes('forbidden')
        ? 'Your role does not have access to the server config (admin only).'
        : ($query.error as Error).message}
    </div>
  {:else}

  <!-- Simple fields -->
  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-700">
    {#each FIELDS as f (f.key)}
      <div class="px-4 py-3">
        <div class="flex items-center gap-1.5 mb-1.5">
          <label class="text-sm font-medium text-gray-900 dark:text-white" for={f.key}>{f.label}</label>
          <div class="relative" data-tip>
            <button type="button" onclick={() => tip(f.key)} class="text-gray-400 hover:text-indigo-500 flex items-center" aria-label="Info">
              <Info size={13} />
            </button>
            {#if openTip === f.key}
              <div class="absolute left-0 top-5 z-20 w-60 bg-gray-900 dark:bg-gray-700 text-white text-xs rounded-lg px-3 py-2 shadow-xl leading-relaxed">
                {f.hint}
              </div>
            {/if}
          </div>
        </div>

        {#if f.type === 'checkbox'}
          <label class="flex items-center gap-2 cursor-pointer select-none">
            <input id={f.key} type="checkbox"
              checked={!!(fv[f.key] ?? false)}
              onchange={(e) => { fv[f.key] = (e.target as HTMLInputElement).checked; }}
              class="rounded text-indigo-600 focus:ring-indigo-500" />
            <span class="text-sm text-gray-600 dark:text-gray-400">{fv[f.key] ? 'Enabled' : 'Disabled'}</span>
          </label>
        {:else if f.type === 'number'}
          <input id={f.key} type="number"
            value={fv[f.key] as number ?? ''}
            oninput={(e) => { fv[f.key] = Number((e.target as HTMLInputElement).value); }}
            class="w-36 px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        {:else}
          <input id={f.key} type="text"
            value={(fv[f.key] as string) ?? ''}
            oninput={(e) => { fv[f.key] = (e.target as HTMLInputElement).value; }}
            placeholder={f.placeholder ?? ''}
            class="w-full px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        {/if}
      </div>
    {/each}
  </div>

  <!-- Pool sync -->
  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
    <div class="px-4 py-3 flex items-center gap-2">
      <input type="checkbox" id="pool-enabled" bind:checked={poolEnabled} class="rounded text-indigo-600" />
      <label class="text-sm font-medium text-gray-900 dark:text-white flex-1 cursor-pointer" for="pool-enabled">Pool Sync</label>
      <div class="relative" data-tip>
        <button type="button" onclick={() => tip('pool')} class="text-gray-400 hover:text-indigo-500"><Info size={13} /></button>
        {#if openTip === 'pool'}
          <div class="absolute right-0 top-5 z-20 w-72 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl leading-relaxed">
            Multi-node pool: replicates the client database across nodes via in-protocol PoolSync packets. All nodes must share the same sync_key.
          </div>
        {/if}
      </div>
    </div>

    {#if poolEnabled}
      <div class="border-t border-gray-100 dark:border-gray-700 px-4 py-3 space-y-3">
        <div>
          <div class="flex items-center gap-1.5 mb-1">
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400" for="pool-peers">Peers (one per line)</label>
            <div class="relative" data-tip>
              <button type="button" onclick={() => tip('pool-peers')} class="text-gray-400 hover:text-indigo-500"><Info size={12} /></button>
              {#if openTip === 'pool-peers'}
                <div class="absolute left-0 top-5 z-20 w-56 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl">host:port of each peer node, e.g. node2.example.com:443</div>
              {/if}
            </div>
          </div>
          <textarea id="pool-peers" bind:value={poolPeers} rows={3}
            placeholder={"node2.example.com:443\nnode3.example.com:443"}
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y"></textarea>
        </div>
        <div>
          <div class="flex items-center gap-1.5 mb-1">
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400" for="pool-sync-key">Sync Key (base64)</label>
            <div class="relative" data-tip>
              <button type="button" onclick={() => tip('pool-sync-key')} class="text-gray-400 hover:text-indigo-500"><Info size={12} /></button>
              {#if openTip === 'pool-sync-key'}
                <div class="absolute left-0 top-5 z-20 w-60 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl">32-byte BLAKE3 key, base64-encoded. All nodes must share the same key. Generate: openssl rand -base64 32</div>
              {/if}
            </div>
          </div>
          <div class="relative">
            <input id="pool-sync-key" type={showSyncKey ? 'text' : 'password'} value={poolSyncKey}
              oninput={(e) => { poolSyncKey = (e.target as HTMLInputElement).value; }}
              placeholder="base64-encoded 32-byte key" autocomplete="off"
              class="w-full pl-3 pr-16 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            <button type="button" onclick={() => { showSyncKey = !showSyncKey; }}
              class="absolute right-2 top-1/2 -translate-y-1/2 text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:underline"
              aria-label={showSyncKey ? 'Hide sync key' : 'Show sync key'}>
              {showSyncKey ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        <div>
          <div class="flex items-center gap-1.5 mb-1">
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400" for="pool-exit-node">Exit Node (optional)</label>
            <div class="relative" data-tip>
              <button type="button" onclick={() => tip('pool-exit-node')} class="text-gray-400 hover:text-indigo-500"><Info size={12} /></button>
              {#if openTip === 'pool-exit-node'}
                <div class="absolute left-0 top-5 z-20 w-64 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl">Multi-hop: forward all client traffic to this exit node (host:port). Leave empty for single-node operation.</div>
              {/if}
            </div>
          </div>
          <input id="pool-exit-node" type="text" bind:value={poolExitNode} placeholder="exit.example.com:443"
            class="w-full px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        </div>
      </div>
    {/if}
  </div>

  <!-- Bootstrap mask files -->
  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 px-4 py-3">
    <div class="flex items-center gap-1.5 mb-1.5">
      <label class="text-sm font-medium text-gray-900 dark:text-white" for="bootstrap-masks">Bootstrap Mask Files</label>
      <div class="relative" data-tip>
        <button type="button" onclick={() => tip('bootstrap-masks')} class="text-gray-400 hover:text-indigo-500"><Info size={13} /></button>
        {#if openTip === 'bootstrap-masks'}
          <div class="absolute left-0 top-5 z-20 w-64 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl">Absolute paths to mask JSON files bundled with the server binary. Loaded before scanning mask_dir. One path per line.</div>
        {/if}
      </div>
    </div>
    <textarea id="bootstrap-masks" bind:value={bootstrapMasks} rows={2}
      placeholder="/var/lib/aivpn/masks/zoom-webrtc.json"
      class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y"></textarea>
  </div>

  <!-- Advanced raw JSON -->
  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <button type="button" onclick={() => { showAdvanced = !showAdvanced; }}
      class="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
      <span>Advanced — raw JSON (<code class="font-mono text-xs">network_config</code>, <code class="font-mono text-xs">dns</code>, <code class="font-mono text-xs">site_to_site</code>, <code class="font-mono text-xs">mtls</code>, <code class="font-mono text-xs">bootstrap_publish</code>)</span>
      <span>{showAdvanced ? '▲' : '▼'}</span>
    </button>
    {#if showAdvanced}
      <div class="border-t border-gray-100 dark:border-gray-700 px-4 py-3">
        {#if advancedError}
          <div class="mb-2 p-2 text-xs bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-red-600 dark:text-red-400">{advancedError}</div>
        {/if}
        <textarea bind:value={advancedJson}
          oninput={() => { try { JSON.parse(advancedJson); advancedError = ''; } catch (e: unknown) { advancedError = e instanceof Error ? e.message : 'Invalid JSON'; } }}
          rows={12} spellcheck="false"
          class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y"></textarea>
      </div>
    {/if}
  </div>

  {/if}
</div>
