<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { createQuery, createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { clients as clientsApi, masks as masksApi } from '$lib/api';
  import type { Client, ClientQos } from '$lib/api';
  import QrModal from '$lib/components/QrModal.svelte';
  import ConnectionKeyModal from '$lib/components/ConnectionKeyModal.svelte';
  import { ArrowLeft, Key, QrCode } from 'lucide-svelte';

  // Route params are always populated when this component is mounted (the
  // [id] segment matched); the `string | undefined` from the index-signature
  // typing is a tsconfig strictness artifact, not a real possibility here.
  const id = $derived($page.params.id as string);
  const qc = useQueryClient();

  const query = createQuery({
    queryKey: ['client', id],
    queryFn: () => clientsApi.get(id),
  });

  let form = $state<Partial<Client> & { qos: ClientQos }>({ qos: {} });
  let toast = $state('');
  let toastError = $state(false);

  $effect(() => {
    if ($query.data) {
      form = { ...$query.data, qos: { ...($query.data.qos ?? {}) } };
    }
  });

  /** Normalise a QoS form value: only positive finite numbers are limits. */
  function qosNum(v: unknown): number | undefined {
    return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : undefined;
  }

  /**
   * Send ONLY changed fields. PATCH semantics on the server: an omitted `qos`
   * leaves QoS untouched, `null` clears it — the old code spread the ENTIRE
   * client object (id, stats, …) into the body and always sent a `qos` object
   * (an empty `{}` when the form was untouched), silently wiping any existing
   * QoS limits on every unrelated save.
   */
  function buildPatch(orig: Client): Parameters<typeof clientsApi.update>[1] {
    const patch: Parameters<typeof clientsApi.update>[1] = {};
    if (form.name !== undefined && form.name !== orig.name) patch.name = form.name;
    if (form.enabled !== undefined && form.enabled !== orig.enabled) patch.enabled = form.enabled;
    if (form.one_time !== undefined && form.one_time !== orig.one_time) patch.one_time = form.one_time;

    const newQos: ClientQos = {};
    const up = qosNum(form.qos.bandwidth_limit_up);
    const down = qosNum(form.qos.bandwidth_limit_down);
    if (up !== undefined) newQos.bandwidth_limit_up = up;
    if (down !== undefined) newQos.bandwidth_limit_down = down;
    if (orig.qos?.dscp_class !== undefined) newQos.dscp_class = orig.qos.dscp_class; // not editable here — preserve

    const origQos: ClientQos = {
      ...(qosNum(orig.qos?.bandwidth_limit_up) !== undefined ? { bandwidth_limit_up: orig.qos!.bandwidth_limit_up } : {}),
      ...(qosNum(orig.qos?.bandwidth_limit_down) !== undefined ? { bandwidth_limit_down: orig.qos!.bandwidth_limit_down } : {}),
      ...(orig.qos?.dscp_class !== undefined ? { dscp_class: orig.qos.dscp_class } : {}),
    };
    if (JSON.stringify(newQos) !== JSON.stringify(origQos)) {
      patch.qos = Object.keys(newQos).length > 0 ? newQos : null; // null clears QoS server-side
    }
    return patch;
  }

  const updateMut = createMutation({
    mutationFn: (data: Parameters<typeof clientsApi.update>[1]) => clientsApi.update(id, data),
    onSuccess: (updated) => {
      qc.setQueryData(['client', id], updated);
      toast = 'Saved successfully';
      toastError = false;
      setTimeout(() => { toast = ''; }, 3000);
    },
    onError: (e: Error) => {
      toast = e.message;
      toastError = true;
      setTimeout(() => { toast = ''; }, 4000);
    },
  });

  const resetMut = createMutation({
    mutationFn: () => clientsApi.resetDevice(id),
    onSuccess: () => { toast = 'Device reset'; toastError = false; setTimeout(() => { toast = ''; }, 3000); },
  });

  // Per-client active-mask override (server: POST /api/v1/masks/active,
  // CLI: --set-mask). Writes a <mask_dir>/.overrides/<client-id>.mask file —
  // there is no GET endpoint to read the current override back, so the
  // dropdown is write-only (select + apply), same as the CLI.
  const masksQuery = createQuery({ queryKey: ['masks'], queryFn: () => masksApi.list() });
  let selectedMask = $state('');

  const setMaskMut = createMutation({
    mutationFn: (mask: string) => masksApi.setActive(id, mask),
    onSuccess: (res) => {
      toast = `Active mask set to "${res.mask}"`;
      toastError = false;
      setTimeout(() => { toast = ''; }, 3000);
    },
    onError: (e: Error) => {
      toast = e.message;
      toastError = true;
      setTimeout(() => { toast = ''; }, 4000);
    },
  });

  let qrOpen = $state(false);
  let qrData = $state('');
  let connKeyOpen = $state(false);
  let connKey = $state('');

  async function loadKey() {
    const res = await clientsApi.connectionKey(id);
    return res.connection_key;
  }

  async function showKey() {
    connKey = await loadKey();
    connKeyOpen = true;
  }

  async function showQr() {
    qrData = await loadKey();
    qrOpen = true;
  }

  function formatBytes(b: number): string {
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
    return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }
</script>

<div class="max-w-2xl space-y-6">
  <div class="flex items-center gap-3">
    <button onclick={() => goto('/clients')} class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
      <ArrowLeft size={20} />
    </button>
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
      {$query.data?.name ?? 'Client'}
    </h1>
  </div>

  {#if toast}
    <div class="p-3 rounded-lg text-sm {toastError ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800' : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'}">
      {toast}
    </div>
  {/if}

  {#if $query.isLoading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  {:else if $query.data}
    <form
      onsubmit={(e) => { e.preventDefault(); if ($query.data) $updateMut.mutate(buildPatch($query.data)); }}
      class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-5"
    >
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Edit Client</h2>

      <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="cname">Name</label>
        <input
          id="cname"
          type="text"
          bind:value={form.name}
          class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>

      <div class="flex items-center gap-6">
        <label class="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" bind:checked={form.enabled} class="rounded" />
          <span class="text-sm text-gray-700 dark:text-gray-300">Enabled</span>
        </label>
        <label class="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" bind:checked={form.one_time} class="rounded" />
          <span class="text-sm text-gray-700 dark:text-gray-300">One-time use</span>
        </label>
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="bw-up">Upload limit (kbps)</label>
          <input
            id="bw-up"
            type="number"
            bind:value={form.qos.bandwidth_limit_up}
            min="0"
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            placeholder="unlimited"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" for="bw-dn">Download limit (kbps)</label>
          <input
            id="bw-dn"
            type="number"
            bind:value={form.qos.bandwidth_limit_down}
            min="0"
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            placeholder="unlimited"
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={$updateMut.isPending}
        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
      >
        {$updateMut.isPending ? 'Saving...' : 'Save'}
      </button>
    </form>

    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white mb-4">Statistics</h2>
      <dl class="grid grid-cols-2 gap-4 text-sm">
        <div>
          <dt class="text-gray-500 dark:text-gray-400">Bytes In</dt>
          <dd class="font-medium text-gray-900 dark:text-white mt-0.5">{formatBytes($query.data.stats.bytes_in)}</dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-gray-400">Bytes Out</dt>
          <dd class="font-medium text-gray-900 dark:text-white mt-0.5">{formatBytes($query.data.stats.bytes_out)}</dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-gray-400">Total Connections</dt>
          <dd class="font-medium text-gray-900 dark:text-white mt-0.5">{$query.data.stats.total_connections}</dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-gray-400">Last Connected</dt>
          <dd class="font-medium text-gray-900 dark:text-white mt-0.5">
            {$query.data.stats.last_connected ? new Date($query.data.stats.last_connected).toLocaleString() : '—'}
          </dd>
        </div>
      </dl>
    </div>

    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Connection Key</h2>
      <div class="flex gap-3">
        <button
          onclick={showKey}
          class="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
        >
          <Key size={16} />
          Show Key
        </button>
        <button
          onclick={showQr}
          class="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
        >
          <QrCode size={16} />
          QR Code
        </button>
      </div>
    </div>

    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-3">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Active Mask Override</h2>
      <p class="text-sm text-gray-500 dark:text-gray-400">Force this client's traffic-mimicry mask, overriding its normal selection.</p>
      <div class="flex gap-3">
        <select
          bind:value={selectedMask}
          class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="" disabled selected>Select mask…</option>
          {#each ($masksQuery.data ?? []) as mask (mask.id)}
            <option value={mask.id}>{mask.id}{mask.generated ? ' (auto)' : ''}</option>
          {/each}
        </select>
        <button
          onclick={() => { if (selectedMask) $setMaskMut.mutate(selectedMask); }}
          disabled={!selectedMask || $setMaskMut.isPending}
          class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
        >
          {$setMaskMut.isPending ? 'Applying…' : 'Apply'}
        </button>
      </div>
    </div>

    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 border-red-200 dark:border-red-900">
      <h2 class="text-base font-semibold text-red-600 dark:text-red-400 mb-2">Danger Zone</h2>
      <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">Reset device binding — the next device to connect will be bound.</p>
      <button
        onclick={() => { if (confirm('Reset device binding?')) $resetMut.mutate(); }}
        disabled={$resetMut.isPending}
        class="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
      >
        {$resetMut.isPending ? 'Resetting...' : 'Reset Device'}
      </button>
    </div>
  {/if}
</div>

<QrModal open={qrOpen} data={qrData} title="Connection QR" onClose={() => { qrOpen = false; }} />
<ConnectionKeyModal open={connKeyOpen} connectionKey={connKey} onClose={() => { connKeyOpen = false; }} />
