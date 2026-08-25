<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { createQuery } from '@tanstack/svelte-query';
  import { status, clients, kernel, metrics, events } from '$lib/api';
  import MetricCard from '$lib/components/MetricCard.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { Activity, Users, Cpu, Server } from 'lucide-svelte';
  import { Chart, Svg, Area, Line, Axis, Spline } from 'layerchart';
  import { scaleTime, scaleLinear } from 'd3-scale';

  const statusQuery = createQuery({ queryKey: ['status'], queryFn: () => status.get(), refetchInterval: 10_000 });
  const clientsQuery = createQuery({ queryKey: ['clients-count'], queryFn: () => clients.list({ limit: 1 }), refetchInterval: 30_000 });
  const kernelQuery = createQuery({ queryKey: ['kernel'], queryFn: () => kernel.get(), refetchInterval: 60_000 });
  const metricsQuery = createQuery({ queryKey: ['metrics'], queryFn: () => metrics.get(), refetchInterval: 5_000 });

  interface DataPoint { ts: Date; value: number }
  /** Two-series point sharing one timestamp (e.g. in/out, p50/p95). */
  interface DualPoint { ts: Date; a: number; b: number }

  /** Shape of the `state` SSE event emitted by /api/v1/events (management_api.rs
   *  sse_events()). The aivpn_* fields are only present when the server was
   *  built with `--features metrics` AND a collector was wired up — every
   *  field below (besides the always-present base fields) must be treated as
   *  optional so the dashboard degrades gracefully on a metrics-less server. */
  interface LiveStateEvent {
    ts?: string;
    uptime_secs?: number;
    clients_total?: number;
    clients_enabled?: number;
    clients_connected?: number;
    kernel_module?: boolean;
    active_sessions?: number;
    bytes_received_total?: number;
    bytes_sent_total?: number;
    packets_received_total?: number;
    packets_sent_total?: number;
    mask_rotations_total?: number;
    key_rotations_total?: number;
    neural_checks_total?: number;
    neural_checks_failed_total?: number;
    dpi_attacks_detected_total?: number;
    packet_processing_p50_ms?: number;
    packet_processing_p95_ms?: number;
    // §2 crowdsourced mask feedback (mask_feedback.rs) — only present when the
    // feedback collector is wired up on top of the base `metrics` feature.
    mask_feedback_received_total?: number;
    regional_hints_sent_total?: number;
    feedback_buckets?: number;
    feedback_regions?: number;
    // §3 polymorphic mask distribution — same optionality caveat.
    mask_preference_requests_total?: number;
    polymorphic_variants_pushed_total?: number;
    polymorphic_sessions_active?: number;
  }

  /** Keep ~10 minutes of history at the server's 5s SSE tick rate. */
  const MAX_POINTS = 120;

  let chartData = $state<DataPoint[]>([]);

  // Live Prometheus metrics ring buffers. Populated only once the server
  // sends the enriched fields (metrics feature on server + client both on).
  let metricsAvailable = $state(false);
  let activeSessionsData = $state<DataPoint[]>([]);
  let bandwidthData = $state<DualPoint[]>([]); // a = bytes/s in, b = bytes/s out
  let packetRateData = $state<DualPoint[]>([]); // a = pkt/s in, b = pkt/s out
  let latencyData = $state<DualPoint[]>([]); // a = p50 ms, b = p95 ms

  // §2 crowdsourced feedback ring buffers.
  let feedbackGaugeData = $state<DualPoint[]>([]); // a = feedback_buckets, b = feedback_regions
  let feedbackRateData = $state<DualPoint[]>([]); // a = feedback recv/s, b = regional hints sent/s

  // §3 polymorphic mask ring buffers.
  let polySessionsData = $state<DataPoint[]>([]); // gauge: sessions currently on a polymorphic mask

  // Event markers: cumulative totals + a short "pulse" flag on increment.
  let maskRotationsTotal = $state<number | null>(null);
  let keyRotationsTotal = $state<number | null>(null);
  let dpiAttacksTotal = $state<number | null>(null);
  let maskPulse = $state(false);
  let keyPulse = $state(false);
  let dpiPulse = $state(false);

  // §3 polymorphic mask event markers.
  let polyRequestsTotal = $state<number | null>(null);
  let polyPushedTotal = $state<number | null>(null);
  let polyReqPulse = $state(false);
  let polyPushPulse = $state(false);

  // Previous tick's cumulative counters + wall-clock time, for computing
  // per-second deltas (bandwidth/packet rate) between consecutive SSE ticks.
  let prevTick: {
    atMs: number;
    bytesIn: number;
    bytesOut: number;
    pktIn: number;
    pktOut: number;
    feedbackRecv: number;
    hintsSent: number;
  } | null = null;

  let es: EventSource | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;

  function pushCapped<T>(arr: T[], point: T): T[] {
    return [...arr.slice(-(MAX_POINTS - 1)), point];
  }

  /** Bump a "total since start" counter and flash its pulse indicator when it
   *  increases. Returns the new total. The very first observation just seeds
   *  the baseline — it should not pulse (there's no known "before" state). */
  function bumpEventCounter(
    newTotal: number,
    prevTotal: number | null,
    setPulse: (v: boolean) => void,
  ): number {
    if (prevTotal !== null && newTotal > prevTotal) {
      setPulse(true);
      setTimeout(() => setPulse(false), 1500);
    }
    return newTotal;
  }

  async function connectSSE() {
    // Mint a short-lived single-use SSE ticket over an authenticated POST —
    // the general access token must never appear in a URL. apiFetch handles
    // the memory-only-token bootstrap (401 → coalesced refresh) for us.
    let ticket: string;
    try {
      ticket = await events.ticket();
    } catch {
      if (!destroyed) reconnectTimer = setTimeout(connectSSE, 5000);
      return;
    }
    if (destroyed) return;
    es = new EventSource(`/web/events?ticket=${encodeURIComponent(ticket)}`);
    // The server publishes a *named* SSE event ("state"); EventSource.onmessage
    // only fires for unnamed ("message") events, so we must listen by name.
    es.addEventListener("state", (e) => {
      try {
        const parsed = JSON.parse(e.data) as LiveStateEvent;
        // `ts` is an RFC3339 string (chrono's `to_rfc3339()`), not epoch
        // seconds — parse via Date directly.
        //
        // Repair `atMs` itself (not just the display `at`): a malformed/
        // missing `ts` must never leave `atMs` as NaN, or every future
        // `dtSecs = (atMs - prevTick.atMs) / 1000` comparison against it
        // permanently fails and the rate charts freeze forever.
        const rawAtMs = parsed.ts ? new Date(parsed.ts).getTime() : NaN;
        const atMs = Number.isFinite(rawAtMs) ? rawAtMs : Date.now();
        const at = new Date(atMs);

        if (parsed.clients_connected !== undefined) {
          chartData = pushCapped(chartData, { ts: at, value: parsed.clients_connected });
        }

        if (parsed.active_sessions === undefined) {
          // Server built without `--features metrics` (or collector not
          // wired) — nothing further to parse this tick.
          return;
        }
        metricsAvailable = true;

        activeSessionsData = pushCapped(activeSessionsData, { ts: at, value: parsed.active_sessions });

        if (parsed.packet_processing_p50_ms !== undefined && parsed.packet_processing_p95_ms !== undefined) {
          latencyData = pushCapped(latencyData, {
            ts: at,
            a: parsed.packet_processing_p50_ms,
            b: parsed.packet_processing_p95_ms,
          });
        }

        // §2 crowdsourced feedback gauges (current bucket/region counts).
        if (parsed.feedback_buckets !== undefined && parsed.feedback_regions !== undefined) {
          feedbackGaugeData = pushCapped(feedbackGaugeData, {
            ts: at,
            a: parsed.feedback_buckets,
            b: parsed.feedback_regions,
          });
        }

        // §3 polymorphic mask gauge (sessions currently on a polymorphic mask).
        if (parsed.polymorphic_sessions_active !== undefined) {
          polySessionsData = pushCapped(polySessionsData, { ts: at, value: parsed.polymorphic_sessions_active });
        }

        // Cumulative counters → per-second rates via delta against the
        // previous tick. Guard against counter resets (server restart)
        // by clamping negative deltas to 0 instead of showing a spike.
        const bytesIn = parsed.bytes_received_total ?? 0;
        const bytesOut = parsed.bytes_sent_total ?? 0;
        const pktIn = parsed.packets_received_total ?? 0;
        const pktOut = parsed.packets_sent_total ?? 0;
        const feedbackRecv = parsed.mask_feedback_received_total ?? 0;
        const hintsSent = parsed.regional_hints_sent_total ?? 0;
        if (prevTick) {
          const dtSecs = (atMs - prevTick.atMs) / 1000;
          if (dtSecs > 0) {
            bandwidthData = pushCapped(bandwidthData, {
              ts: at,
              a: Math.max(0, bytesIn - prevTick.bytesIn) / dtSecs,
              b: Math.max(0, bytesOut - prevTick.bytesOut) / dtSecs,
            });
            packetRateData = pushCapped(packetRateData, {
              ts: at,
              a: Math.max(0, pktIn - prevTick.pktIn) / dtSecs,
              b: Math.max(0, pktOut - prevTick.pktOut) / dtSecs,
            });
            if (parsed.mask_feedback_received_total !== undefined || parsed.regional_hints_sent_total !== undefined) {
              feedbackRateData = pushCapped(feedbackRateData, {
                ts: at,
                a: Math.max(0, feedbackRecv - prevTick.feedbackRecv) / dtSecs,
                b: Math.max(0, hintsSent - prevTick.hintsSent) / dtSecs,
              });
            }
          }
        }
        prevTick = { atMs, bytesIn, bytesOut, pktIn, pktOut, feedbackRecv, hintsSent };

        if (parsed.mask_rotations_total !== undefined) {
          maskRotationsTotal = bumpEventCounter(parsed.mask_rotations_total, maskRotationsTotal, (v) => (maskPulse = v));
        }
        if (parsed.key_rotations_total !== undefined) {
          keyRotationsTotal = bumpEventCounter(parsed.key_rotations_total, keyRotationsTotal, (v) => (keyPulse = v));
        }
        if (parsed.dpi_attacks_detected_total !== undefined) {
          dpiAttacksTotal = bumpEventCounter(parsed.dpi_attacks_detected_total, dpiAttacksTotal, (v) => (dpiPulse = v));
        }
        if (parsed.mask_preference_requests_total !== undefined) {
          polyRequestsTotal = bumpEventCounter(parsed.mask_preference_requests_total, polyRequestsTotal, (v) => (polyReqPulse = v));
        }
        if (parsed.polymorphic_variants_pushed_total !== undefined) {
          polyPushedTotal = bumpEventCounter(parsed.polymorphic_variants_pushed_total, polyPushedTotal, (v) => (polyPushPulse = v));
        }
      } catch { /* ignore */ }
    });
    // Capture this instance so a stale connection's error can't close a newer
    // one created by a later reconnect.
    const thisEs = es;
    thisEs.onerror = () => {
      thisEs.close();
      // Only schedule a reconnect if this is still the live connection and the
      // component hasn't been destroyed (reconnectTimer is cleared in onDestroy).
      if (es === thisEs && !destroyed) {
        reconnectTimer = setTimeout(connectSSE, 5000);
      }
    };
  }

  onMount(connectSSE);
  onDestroy(() => {
    destroyed = true;
    if (reconnectTimer !== null) clearTimeout(reconnectTimer);
    es?.close();
  });

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function formatRate(bytesPerSec: number): string {
    if (bytesPerSec >= 1024 * 1024) return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
    if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
    return `${bytesPerSec.toFixed(0)} B/s`;
  }

  // /api/v1/status has NO connected-clients field — live connection counts
  // only exist on the SSE `state` event (`clients_connected`), which already
  // feeds chartData. The "Connected" card reads the latest sample from there.
  let liveConnected = $derived(chartData.at(-1)?.value ?? null);

  let latestBandwidthIn = $derived(bandwidthData.at(-1)?.a ?? 0);
  let latestBandwidthOut = $derived(bandwidthData.at(-1)?.b ?? 0);
  let latestPacketRateIn = $derived(packetRateData.at(-1)?.a ?? 0);
  let latestPacketRateOut = $derived(packetRateData.at(-1)?.b ?? 0);
  let latestP50 = $derived(latencyData.at(-1)?.a ?? 0);
  let latestP95 = $derived(latencyData.at(-1)?.b ?? 0);
  let latestFeedbackRate = $derived(feedbackRateData.at(-1)?.a ?? 0);
  let latestHintsRate = $derived(feedbackRateData.at(-1)?.b ?? 0);
</script>

<div class="space-y-6">
  <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>

  <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
    <MetricCard
      title="Uptime"
      value={$statusQuery.data ? formatUptime($statusQuery.data.uptime_secs) : '—'}
      subtitle={$statusQuery.data?.version ?? ''}
      icon={Server}
    />
    <MetricCard
      title="Total Clients"
      value={$statusQuery.data?.clients_total ?? '—'}
      subtitle="registered"
      icon={Users}
    />
    <MetricCard
      title="Connected"
      value={liveConnected ?? '—'}
      subtitle="active sessions"
      icon={Activity}
    />
    <MetricCard
      title="CPU"
      value={$metricsQuery.data ? `${$metricsQuery.data.cpu_percent.toFixed(1)}%` : '—'}
      subtitle={$metricsQuery.data ? `RAM ${$metricsQuery.data.ram_used_mb}/${$metricsQuery.data.ram_total_mb} MB` : ''}
      icon={Cpu}
    />
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
    <div class="xl:col-span-2 bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700">
      <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Connected Clients (live)</h2>
      {#if chartData.length > 1}
        <div class="h-48">
          <Chart
            data={chartData}
            x={(d: DataPoint) => d.ts}
            y={(d: DataPoint) => d.value}
            xScale={scaleTime()}
            yScale={scaleLinear()}
            padding={{ top: 10, bottom: 30, left: 30, right: 10 }}
          >
            <Svg>
              <Area class="fill-indigo-500/20" />
              <Line class="stroke-indigo-500 stroke-2" />
              <Axis placement="bottom" />
              <Axis placement="left" />
            </Svg>
          </Chart>
        </div>
      {:else}
        <div class="h-48 flex items-center justify-center text-gray-400 text-sm">
          Waiting for live data...
        </div>
      {/if}
    </div>

    <div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700">
      <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">System Status</h2>
      <div class="space-y-3">
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-600 dark:text-gray-400">Server</span>
          <StatusBadge status="running" variant="success" />
        </div>
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-600 dark:text-gray-400">Kernel Module</span>
          {#if $kernelQuery.data}
            <StatusBadge
              status={$kernelQuery.data.loaded ? 'loaded' : 'not loaded'}
              variant={$kernelQuery.data.loaded ? 'success' : 'warning'}
            />
          {:else}
            <span class="text-gray-400 text-sm">—</span>
          {/if}
        </div>
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-600 dark:text-gray-400">Load Avg</span>
          <span class="text-sm font-medium text-gray-800 dark:text-gray-200">
            {$metricsQuery.data?.load_avg.toFixed(2) ?? '—'}
          </span>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-sm text-gray-600 dark:text-gray-400">Version</span>
          <span class="text-sm font-medium text-gray-800 dark:text-gray-200">
            {$statusQuery.data?.version ?? '—'}
          </span>
        </div>
      </div>
    </div>
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700">
    <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Live Server Metrics</h2>

    {#if !metricsAvailable}
      <div class="h-24 flex items-center justify-center text-gray-400 text-sm text-center">
        Waiting for Prometheus metrics — either the server was built without
        <code class="mx-1 px-1 bg-gray-100 dark:bg-gray-700 rounded">--features metrics</code>,
        or the first tick hasn't arrived yet.
      </div>
    {:else}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Active Sessions
            <span class="ml-2 font-semibold text-gray-700 dark:text-gray-300">
              {activeSessionsData.at(-1)?.value ?? '—'}
            </span>
          </h3>
          {#if activeSessionsData.length > 1}
            <div class="h-36">
              <Chart
                data={activeSessionsData}
                x={(d: DataPoint) => d.ts}
                y={(d: DataPoint) => d.value}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 30, right: 10 }}
              >
                <Svg>
                  <Area class="fill-emerald-500/20" line={{ class: 'stroke-emerald-500 stroke-2' }} />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>

        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Bandwidth
            <span class="ml-2 text-blue-500">▲ in {formatRate(latestBandwidthIn)}</span>
            <span class="ml-2 text-amber-500">▼ out {formatRate(latestBandwidthOut)}</span>
          </h3>
          {#if bandwidthData.length > 1}
            <div class="h-36">
              <Chart
                data={bandwidthData}
                x={(d: DualPoint) => d.ts}
                y={(d: DualPoint) => Math.max(d.a, d.b)}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 40, right: 10 }}
              >
                <Svg>
                  <Spline y={(d: DualPoint) => d.a} class="stroke-blue-500 stroke-2" />
                  <Spline y={(d: DualPoint) => d.b} class="stroke-amber-500 stroke-2" />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>

        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Packet Rate
            <span class="ml-2 text-purple-500">▲ in {latestPacketRateIn.toFixed(0)}/s</span>
            <span class="ml-2 text-pink-500">▼ out {latestPacketRateOut.toFixed(0)}/s</span>
          </h3>
          {#if packetRateData.length > 1}
            <div class="h-36">
              <Chart
                data={packetRateData}
                x={(d: DualPoint) => d.ts}
                y={(d: DualPoint) => Math.max(d.a, d.b)}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 40, right: 10 }}
              >
                <Svg>
                  <Spline y={(d: DualPoint) => d.a} class="stroke-purple-500 stroke-2" />
                  <Spline y={(d: DualPoint) => d.b} class="stroke-pink-500 stroke-2" />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>

        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Packet Processing Latency
            <span class="ml-2 text-teal-500">p50 {latestP50.toFixed(2)}ms</span>
            <span class="ml-2 text-rose-500">p95 {latestP95.toFixed(2)}ms</span>
          </h3>
          {#if latencyData.length > 1}
            <div class="h-36">
              <Chart
                data={latencyData}
                x={(d: DualPoint) => d.ts}
                y={(d: DualPoint) => Math.max(d.a, d.b)}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 40, right: 10 }}
              >
                <Svg>
                  <Spline y={(d: DualPoint) => d.a} class="stroke-teal-500 stroke-2" />
                  <Spline y={(d: DualPoint) => d.b} class="stroke-rose-500 stroke-2" />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>
      </div>

      <div class="mt-5 pt-4 border-t border-gray-200 dark:border-gray-700 flex flex-wrap gap-3">
        <div
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-50 dark:bg-indigo-900/30 transition-shadow"
          class:ring-2={maskPulse}
          class:ring-indigo-400={maskPulse}
        >
          <span class="w-2 h-2 rounded-full bg-indigo-500" class:animate-ping={maskPulse}></span>
          <span class="text-xs text-gray-600 dark:text-gray-300">Mask rotations</span>
          <span class="text-xs font-semibold text-gray-900 dark:text-white">{maskRotationsTotal ?? '—'}</span>
        </div>
        <div
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-50 dark:bg-emerald-900/30 transition-shadow"
          class:ring-2={keyPulse}
          class:ring-emerald-400={keyPulse}
        >
          <span class="w-2 h-2 rounded-full bg-emerald-500" class:animate-ping={keyPulse}></span>
          <span class="text-xs text-gray-600 dark:text-gray-300">Key rotations</span>
          <span class="text-xs font-semibold text-gray-900 dark:text-white">{keyRotationsTotal ?? '—'}</span>
        </div>
        <div
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-50 dark:bg-red-900/30 transition-shadow"
          class:ring-2={dpiPulse}
          class:ring-red-400={dpiPulse}
        >
          <span class="w-2 h-2 rounded-full bg-red-500" class:animate-ping={dpiPulse}></span>
          <span class="text-xs text-gray-600 dark:text-gray-300">DPI attacks detected</span>
          <span class="text-xs font-semibold text-gray-900 dark:text-white">{dpiAttacksTotal ?? '—'}</span>
        </div>
      </div>
    {/if}
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700">
    <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Crowdsourced feedback (§2)</h2>

    {#if !metricsAvailable}
      <div class="h-24 flex items-center justify-center text-gray-400 text-sm text-center">
        Waiting for Prometheus metrics — either the server was built without
        <code class="mx-1 px-1 bg-gray-100 dark:bg-gray-700 rounded">--features metrics</code>,
        or the first tick hasn't arrived yet.
      </div>
    {:else if feedbackGaugeData.length === 0 && feedbackRateData.length === 0}
      <div class="h-24 flex items-center justify-center text-gray-400 text-sm text-center">
        No crowdsourced-feedback metrics received yet — the mask-feedback collector may not be wired up on this server.
      </div>
    {:else}
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-5">
        <MetricCard
          title="Feedback Buckets"
          value={feedbackGaugeData.at(-1)?.a ?? '—'}
          subtitle="(country, mask) pairs"
          icon={Activity}
        />
        <MetricCard
          title="Feedback Regions"
          value={feedbackGaugeData.at(-1)?.b ?? '—'}
          subtitle="distinct countries"
          icon={Users}
        />
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Feedback Store Size
            <span class="ml-2 text-cyan-500">buckets {feedbackGaugeData.at(-1)?.a ?? '—'}</span>
            <span class="ml-2 text-fuchsia-500">regions {feedbackGaugeData.at(-1)?.b ?? '—'}</span>
          </h3>
          {#if feedbackGaugeData.length > 1}
            <div class="h-36">
              <Chart
                data={feedbackGaugeData}
                x={(d: DualPoint) => d.ts}
                y={(d: DualPoint) => Math.max(d.a, d.b)}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 40, right: 10 }}
              >
                <Svg>
                  <Spline y={(d: DualPoint) => d.a} class="stroke-cyan-500 stroke-2" />
                  <Spline y={(d: DualPoint) => d.b} class="stroke-fuchsia-500 stroke-2" />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>

        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Feedback / Hints Rate
            <span class="ml-2 text-lime-500">▲ recv {latestFeedbackRate.toFixed(2)}/s</span>
            <span class="ml-2 text-orange-500">▼ sent {latestHintsRate.toFixed(2)}/s</span>
          </h3>
          {#if feedbackRateData.length > 1}
            <div class="h-36">
              <Chart
                data={feedbackRateData}
                x={(d: DualPoint) => d.ts}
                y={(d: DualPoint) => Math.max(d.a, d.b)}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 40, right: 10 }}
              >
                <Svg>
                  <Spline y={(d: DualPoint) => d.a} class="stroke-lime-500 stroke-2" />
                  <Spline y={(d: DualPoint) => d.b} class="stroke-orange-500 stroke-2" />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>
      </div>
    {/if}
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700">
    <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Polymorphic masks (§3)</h2>

    {#if !metricsAvailable}
      <div class="h-24 flex items-center justify-center text-gray-400 text-sm text-center">
        Waiting for Prometheus metrics — either the server was built without
        <code class="mx-1 px-1 bg-gray-100 dark:bg-gray-700 rounded">--features metrics</code>,
        or the first tick hasn't arrived yet.
      </div>
    {:else if polySessionsData.length === 0 && polyRequestsTotal === null && polyPushedTotal === null}
      <div class="h-24 flex items-center justify-center text-gray-400 text-sm text-center">
        No polymorphic-mask metrics received yet — the polymorphic distribution collector may not be wired up on this server.
      </div>
    {:else}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h3 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Active Polymorphic Sessions
            <span class="ml-2 font-semibold text-gray-700 dark:text-gray-300">
              {polySessionsData.at(-1)?.value ?? '—'}
            </span>
          </h3>
          {#if polySessionsData.length > 1}
            <div class="h-36">
              <Chart
                data={polySessionsData}
                x={(d: DataPoint) => d.ts}
                y={(d: DataPoint) => d.value}
                xScale={scaleTime()}
                yScale={scaleLinear()}
                padding={{ top: 10, bottom: 24, left: 30, right: 10 }}
              >
                <Svg>
                  <Area class="fill-violet-500/20" line={{ class: 'stroke-violet-500 stroke-2' }} />
                  <Axis placement="bottom" />
                  <Axis placement="left" />
                </Svg>
              </Chart>
            </div>
          {:else}
            <div class="h-36 flex items-center justify-center text-gray-400 text-xs">Waiting for data...</div>
          {/if}
        </div>

        <div class="flex flex-col justify-center gap-3">
          <MetricCard
            title="Sessions on Polymorphic Mask"
            value={polySessionsData.at(-1)?.value ?? '—'}
            subtitle="gauge"
            icon={Cpu}
          />
        </div>
      </div>

      <div class="mt-5 pt-4 border-t border-gray-200 dark:border-gray-700 flex flex-wrap gap-3">
        <div
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-violet-50 dark:bg-violet-900/30 transition-shadow"
          class:ring-2={polyReqPulse}
          class:ring-violet-400={polyReqPulse}
        >
          <span class="w-2 h-2 rounded-full bg-violet-500" class:animate-ping={polyReqPulse}></span>
          <span class="text-xs text-gray-600 dark:text-gray-300">Mask preference requests</span>
          <span class="text-xs font-semibold text-gray-900 dark:text-white">{polyRequestsTotal ?? '—'}</span>
        </div>
        <div
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-sky-50 dark:bg-sky-900/30 transition-shadow"
          class:ring-2={polyPushPulse}
          class:ring-sky-400={polyPushPulse}
        >
          <span class="w-2 h-2 rounded-full bg-sky-500" class:animate-ping={polyPushPulse}></span>
          <span class="text-xs text-gray-600 dark:text-gray-300">Variants pushed</span>
          <span class="text-xs font-semibold text-gray-900 dark:text-white">{polyPushedTotal ?? '—'}</span>
        </div>
      </div>
    {/if}
  </div>
</div>
