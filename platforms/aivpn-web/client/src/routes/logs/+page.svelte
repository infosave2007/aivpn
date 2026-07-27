<script lang="ts">
  import { createQuery } from '@tanstack/svelte-query';
  import { auditLog, isAuditResultOk } from '$lib/api';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { Search } from 'lucide-svelte';

  // No SSE here: the /web/events stream only carries named `state` status
  // ticks — the server emits no audit events at all, so the previous
  // live-tail listener could never fire. Poll the audit log instead.
  const query = createQuery({
    queryKey: ['audit-log'],
    queryFn: () => auditLog.list(200),
    refetchInterval: 10_000,
  });

  let search = $state('');
  let filterResult = $state<'' | 'ok' | 'fail'>('');

  const filtered = $derived(($query.data ?? []).filter((e) => {
    const matchSearch = !search || [e.actor, e.action, e.target].some((f) => f?.toLowerCase().includes(search.toLowerCase()));
    // Server emits "ok"/"accepted" (success) and "fail"/"rejected"/"denied"
    // (failure) — map the two filter buckets onto those real values.
    const matchResult = !filterResult
      || (filterResult === 'ok' ? isAuditResultOk(e.result) : !isAuditResultOk(e.result));
    return matchSearch && matchResult;
  }));

  const queryErrorMessage = $derived.by(() => {
    const err = $query.error as Error | null;
    if (!err) return '';
    return err.message.includes('403') || err.message.toLowerCase().includes('forbidden')
      ? 'Your role does not have access to the audit log (admin only).'
      : err.message;
  });
</script>

<div class="space-y-4">
  <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Audit Log</h1>

  <div class="flex items-center gap-3">
    <div class="relative flex-1 max-w-xs">
      <Search class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
      <input
        type="text"
        bind:value={search}
        placeholder="Search..."
        class="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />
    </div>
    <select
      bind:value={filterResult}
      class="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none"
    >
      <option value="">All Results</option>
      <option value="ok">Success</option>
      <option value="fail">Failure</option>
    </select>
  </div>

  {#if $query.error}
    <div class="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-xl text-sm text-amber-800 dark:text-amber-300">
      {queryErrorMessage}
    </div>
  {:else}
  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400 sticky top-0">
          <tr>
            <th class="px-4 py-3 text-left font-medium">Time</th>
            <th class="px-4 py-3 text-left font-medium">Actor</th>
            <th class="px-4 py-3 text-left font-medium">Action</th>
            <th class="px-4 py-3 text-left font-medium">Target</th>
            <th class="px-4 py-3 text-left font-medium">Result</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <!-- Audit entries have no id field; ts alone can collide (two actions
               in the same second), so key by ts + position. -->
          {#each filtered as entry, i (`${entry.ts}-${i}`)}
            <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
              <td class="px-4 py-2.5 text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
                {new Date(entry.ts).toLocaleString()}
              </td>
              <td class="px-4 py-2.5 text-gray-700 dark:text-gray-300 text-xs">{entry.actor}</td>
              <td class="px-4 py-2.5 text-gray-700 dark:text-gray-300 font-mono text-xs">{entry.action}</td>
              <td class="px-4 py-2.5 text-gray-600 dark:text-gray-400 text-xs">{entry.target}</td>
              <td class="px-4 py-2.5">
                <StatusBadge
                  status={entry.result}
                  variant={isAuditResultOk(entry.result) ? 'success' : 'error'}
                />
              </td>
            </tr>
          {/each}
          {#if filtered.length === 0}
            <tr>
              <td colspan="5" class="px-4 py-8 text-center text-gray-400">No log entries</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
  </div>
  {/if}
</div>
