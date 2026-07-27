<script lang="ts">
  import { createQuery, createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { pool as poolApi, config as configApi, type PoolNodeInfo, type PoolLinkInfo, type PoolHealth } from '$lib/api';
  import MetricCard from '$lib/components/MetricCard.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { authStore } from '$lib/stores/auth.svelte';
  import { RefreshCw, Network, Server, ShieldCheck, AlertTriangle, Link2 } from 'lucide-svelte';

  const qc = useQueryClient();

  // Global default exit node (admin-only) — same "field presence selects
  // HeavySetting::ExitNode" contract as the per-client override on the
  // client detail page, but writes `pool.exit_node` in server.json via
  // apply-with-rollback instead of a live PATCH. UNLIKE the per-client
  // override, this does NOT take effect until the server is restarted.
  const isAdmin = $derived(authStore.user?.role === 'admin');
  let globalExitInput = $state('');
  let globalExitToast = $state('');
  let globalExitToastError = $state(false);

  function showGlobalExitToast(msg: string, err = false) {
    globalExitToast = msg;
    globalExitToastError = err;
    setTimeout(() => { globalExitToast = ''; }, 4000);
  }

  const applyExitMut = createMutation({
    mutationFn: async (addr: string | null) => {
      const { token } = await configApi.applyExit(addr);
      await configApi.confirm(token);
      return addr;
    },
    onSuccess: (addr) => {
      showGlobalExitToast(
        addr ? `Global default exit node set to "${addr}". Restart the server to apply.` : 'Global default exit node disabled. Restart the server to apply.',
      );
    },
    onError: (e: Error) => showGlobalExitToast(e.message, true),
  });

  // Live topology: refetch every 7s so link/health state stays current
  // without hammering the mgmt socket (dashboard uses a similar range,
  // 5-30s, for its non-SSE polled panels).
  const nodesQuery = createQuery({ queryKey: ['pool', 'nodes'], queryFn: () => poolApi.nodes(), refetchInterval: 7_000 });
  const linksQuery = createQuery({ queryKey: ['pool', 'links'], queryFn: () => poolApi.links(), refetchInterval: 7_000 });
  const healthQuery = createQuery({ queryKey: ['pool', 'health'], queryFn: () => poolApi.health(), refetchInterval: 7_000 });

  function refreshAll() {
    qc.invalidateQueries({ queryKey: ['pool'] });
  }

  // ─── Radial graph layout ───────────────────────────────────────────────
  // Deterministic, self-contained SVG layout: pool member nodes placed on a
  // ring around a "This node" hub. The hub-and-spoke shape matches what the
  // data actually represents — PoolLinkInfo is this node's own dial-set
  // status per peer, not a full inter-peer mesh view — so drawing edges
  // between arbitrary peers would imply topology info the API doesn't have.
  interface NodeLayout {
    node: PoolNodeInfo;
    x: number;
    y: number;
  }

  const SIZE = 440;
  const CENTER = SIZE / 2;
  const NODE_R = 15;
  const RING_R = CENTER - NODE_R - 34;
  const HUB_R = 20;

  function layoutNodes(nodes: PoolNodeInfo[]): NodeLayout[] {
    const n = nodes.length;
    if (n === 0) return [];
    return nodes.map((node, i) => {
      const angle = (2 * Math.PI * i) / n - Math.PI / 2;
      return {
        node,
        x: CENTER + RING_R * Math.cos(angle),
        y: CENTER + RING_R * Math.sin(angle),
      };
    });
  }

  function linkFor(links: PoolLinkInfo[], nodeId: string): PoolLinkInfo | undefined {
    return links.find((l) => l.peer === nodeId);
  }

  function edgeClass(link: PoolLinkInfo | undefined): string {
    if (!link || !link.connected) return 'stroke-gray-300 dark:stroke-gray-700';
    if (!link.converged) return 'stroke-amber-500';
    return 'stroke-green-500';
  }

  function edgeDash(link: PoolLinkInfo | undefined): string | undefined {
    return !link || !link.connected ? '4 4' : undefined;
  }

  function nodeStrokeClass(node: PoolNodeInfo): string {
    if (node.revoked) return 'stroke-red-500';
    if (node.verified) return 'stroke-green-500';
    return 'stroke-gray-400 dark:stroke-gray-600';
  }

  function nodeFillClass(node: PoolNodeInfo): string {
    if (node.revoked) return 'fill-red-50 dark:fill-red-950';
    return node.connected
      ? 'fill-indigo-100 dark:fill-indigo-900'
      : 'fill-white dark:fill-gray-800';
  }

  function formatLastSeen(ts: number | null): string {
    if (ts === null) return 'never';
    return new Date(ts * 1000).toLocaleString();
  }

  function formatLastConverged(ts: number | null): string {
    if (ts === null) return 'never';
    return new Date(ts * 1000).toLocaleString();
  }

  function nodeTooltip(node: PoolNodeInfo): string {
    const lines = [
      node.node_id,
      node.address ? `address: ${node.address}` : 'address: unknown',
      `verified: ${node.verified ? 'yes' : 'no'}`,
      `revoked: ${node.revoked ? 'yes' : 'no'}`,
      `connected: ${node.connected ? 'yes' : 'no'}`,
      `last seen: ${formatLastSeen(node.last_seen_unix)}`,
    ];
    return lines.join('\n');
  }

  function transportLabel(t: PoolHealth['transport']): string {
    if (t === 'masked') return 'Masked (live link state)';
    if (t === 'legacy') return 'Legacy (no link state)';
    return 'None (single-node)';
  }
</script>

<div class="space-y-4">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Pool Topology</h1>
    <button
      onclick={refreshAll}
      class="flex items-center gap-2 px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
    >
      <RefreshCw size={16} />
      Refresh
    </button>
  </div>

  {#if isAdmin}
    <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 space-y-3">
      <h2 class="text-base font-semibold text-gray-900 dark:text-white">Global Default Exit Node</h2>
      <p class="text-sm text-gray-500 dark:text-gray-400">
        The pool-wide default exit node clients fall back to when they have no per-client override
        (set on a client's detail page). Persists with rollback protection, but takes effect only
        after the server is restarted — unlike the per-client override, which is live.
      </p>
      {#if globalExitToast}
        <div class="p-2.5 rounded-lg text-sm {globalExitToastError
          ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
          : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'}">
          {globalExitToast}
        </div>
      {/if}
      <div class="flex gap-3">
        <input
          type="text"
          bind:value={globalExitInput}
          placeholder="exit.example.com:443"
          class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <button
          onclick={() => { if (globalExitInput.trim()) $applyExitMut.mutate(globalExitInput.trim()); }}
          disabled={!globalExitInput.trim() || $applyExitMut.isPending}
          class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
        >
          {$applyExitMut.isPending ? 'Applying…' : 'Set'}
        </button>
        <button
          onclick={() => { globalExitInput = ''; $applyExitMut.mutate(null); }}
          disabled={$applyExitMut.isPending}
          class="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
        >
          Disable
        </button>
      </div>
    </div>
  {/if}

  {#if $nodesQuery.isError || $linksQuery.isError || $healthQuery.isError}
    <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">
      Failed to load pool topology.
      {#if $nodesQuery.error instanceof Error}{$nodesQuery.error.message}{/if}
      {#if $linksQuery.error instanceof Error}{$linksQuery.error.message}{/if}
      {#if $healthQuery.error instanceof Error}{$healthQuery.error.message}{/if}
    </div>
  {/if}

  {#if $nodesQuery.isLoading || $linksQuery.isLoading || $healthQuery.isLoading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  {:else if $healthQuery.data}
    {@const health = $healthQuery.data}
    {@const nodes = $nodesQuery.data ?? []}
    {@const links = $linksQuery.data ?? []}

    <!-- Health summary -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <MetricCard title="Transport" value={transportLabel(health.transport)} icon={Network} />
      <MetricCard title="Total nodes" value={health.total_nodes} icon={Server} />
      <MetricCard title="Connected peers" value={`${health.connected_peers} / ${health.total_nodes}`} icon={Link2} />
      <MetricCard title="Converged peers" value={`${health.converged_peers} / ${health.total_nodes}`} icon={ShieldCheck} />
    </div>

    {#if health.diverged}
      <div class="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg text-amber-800 dark:text-amber-400 text-sm">
        <AlertTriangle size={16} class="shrink-0" />
        <span>Divergence detected: at least one connected peer's anti-entropy state doesn't match ours.</span>
        <StatusBadge status="diverged" variant="warning" />
      </div>
    {/if}

    {#if health.transport === 'none' || nodes.length === 0}
      <!-- Empty state: no pool configured -->
      <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-12 text-center">
        <Network size={32} class="mx-auto text-gray-300 dark:text-gray-600 mb-3" />
        <p class="text-gray-500 dark:text-gray-400 font-medium">No pool configured (single-node)</p>
        <p class="text-gray-400 dark:text-gray-500 text-sm mt-1">This server isn't part of a multi-node pool.</p>
      </div>
    {:else}
      <!-- Graph -->
      <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <svg viewBox="0 0 {SIZE} {SIZE}" class="w-full max-w-lg mx-auto" role="img" aria-label="Pool topology graph">
          {#each layoutNodes(nodes) as { node, x, y } (node.node_id)}
            {@const link = linkFor(links, node.node_id)}
            <line
              x1={CENTER} y1={CENTER} x2={x} y2={y}
              class={edgeClass(link)}
              stroke-width="2"
              stroke-dasharray={edgeDash(link)}
            />
          {/each}

          <!-- Hub: this node -->
          <circle cx={CENTER} cy={CENTER} r={HUB_R} class="fill-indigo-600 stroke-indigo-700" stroke-width="2" />
          <text x={CENTER} y={CENTER + HUB_R + 16} text-anchor="middle" class="fill-gray-600 dark:fill-gray-300 text-[11px] font-medium">This node</text>

          {#each layoutNodes(nodes) as { node, x, y } (node.node_id)}
            <g>
              <title>{nodeTooltip(node)}</title>
              <circle
                cx={x} cy={y} r={NODE_R}
                class="{nodeFillClass(node)} {nodeStrokeClass(node)}"
                stroke-width="2.5"
                stroke-dasharray={node.connected ? undefined : '3 3'}
              />
              <text
                x={x} y={y + NODE_R + 14}
                text-anchor="middle"
                class="fill-gray-700 dark:fill-gray-300 text-[10px] {node.revoked ? 'line-through' : ''}"
              >
                {node.node_id.length > 12 ? `${node.node_id.slice(0, 12)}…` : node.node_id}
              </text>
            </g>
          {/each}
        </svg>

        <div class="flex flex-wrap items-center justify-center gap-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
          <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full border-2 border-green-500 inline-block"></span> Verified</span>
          <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full border-2 border-red-500 inline-block"></span> Revoked</span>
          <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full border-2 border-gray-400 inline-block"></span> Unverified</span>
          <span class="flex items-center gap-1.5"><span class="w-4 h-0 border-t-2 border-green-500 inline-block"></span> Link up &amp; converged</span>
          <span class="flex items-center gap-1.5"><span class="w-4 h-0 border-t-2 border-amber-500 inline-block"></span> Link up, diverged</span>
          <span class="flex items-center gap-1.5"><span class="w-4 h-0 border-t-2 border-gray-300 dark:border-gray-700 inline-block" style="border-style: dashed"></span> Disconnected</span>
        </div>
      </div>

      <!-- Node table (accessible fallback / dense-graph detail) -->
      <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
            <tr>
              <th class="px-4 py-3 text-left font-medium">Node ID</th>
              <th class="px-4 py-3 text-left font-medium">Address</th>
              <th class="px-4 py-3 text-left font-medium">Verified</th>
              <th class="px-4 py-3 text-left font-medium">Connected</th>
              <th class="px-4 py-3 text-left font-medium">Converged</th>
              <th class="px-4 py-3 text-left font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
            {#each nodes as node (node.node_id)}
              {@const link = linkFor(links, node.node_id)}
              <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                <td class="px-4 py-3 font-mono text-xs text-gray-700 dark:text-gray-300 {node.revoked ? 'line-through text-gray-400' : ''}">
                  {node.node_id}
                </td>
                <td class="px-4 py-3 text-gray-600 dark:text-gray-400 font-mono text-xs">{node.address ?? '—'}</td>
                <td class="px-4 py-3">
                  {#if node.revoked}
                    <StatusBadge status="revoked" variant="error" />
                  {:else if node.verified}
                    <StatusBadge status="verified" variant="success" />
                  {:else}
                    <StatusBadge status="unverified" variant="info" />
                  {/if}
                </td>
                <td class="px-4 py-3">
                  <StatusBadge status={node.connected ? 'connected' : 'disconnected'} variant={node.connected ? 'success' : 'warning'} />
                </td>
                <td class="px-4 py-3 text-gray-600 dark:text-gray-400">
                  {#if link}
                    <span class="{link.converged ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400'}">
                      {link.converged ? 'yes' : 'no'}
                    </span>
                    <span class="text-gray-400 text-xs block">{formatLastConverged(link.last_converged_unix)}</span>
                  {:else}
                    <span class="text-gray-400">—</span>
                  {/if}
                </td>
                <td class="px-4 py-3 text-gray-600 dark:text-gray-400">{formatLastSeen(node.last_seen_unix)}</td>
              </tr>
            {/each}
            {#if nodes.length === 0}
              <tr>
                <td colspan="6" class="px-4 py-8 text-center text-gray-400">No pool nodes known.</td>
              </tr>
            {/if}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>
