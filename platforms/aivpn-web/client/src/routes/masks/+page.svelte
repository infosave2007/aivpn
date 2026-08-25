<script lang="ts">
  import { createQuery, createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { masks as masksApi } from '$lib/api';
  import { RefreshCw, Shield, Upload, Trash2 } from 'lucide-svelte';

  const qc = useQueryClient();
  const query = createQuery({ queryKey: ['masks'], queryFn: () => masksApi.list() });

  let fileInput: HTMLInputElement;
  let uploading = $state(false);
  let uploadError = $state('');

  const deleteMut = createMutation({
    mutationFn: (name: string) => masksApi.delete(name),
    onSuccess: () => { uploadError = ''; qc.invalidateQueries({ queryKey: ['masks'] }); },
    // masksApi.delete now throws on non-2xx (e.g. 403 for viewer role, 502
    // daemon-down) — surface it instead of silently keeping the row.
    onError: (e: Error) => { uploadError = e.message; },
  });

  async function handleUpload(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    let name = file.name.replace(/\.json$/i, '').replace(/[^a-zA-Z0-9_-]/g, '_');
    if (!name) { uploadError = 'Invalid filename'; return; }

    uploading = true;
    uploadError = '';
    try {
      const content = await file.text();
      await masksApi.upload(name, content);
      qc.invalidateQueries({ queryKey: ['masks'] });
    } catch (err) {
      uploadError = err instanceof Error ? err.message : 'Upload failed';
    } finally {
      uploading = false;
      input.value = '';
    }
  }

  async function handleDelete(id: string) {
    if (confirm(`Delete mask "${id}"?`)) {
      $deleteMut.mutate(id);
    }
  }

  function humanSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  }
</script>

<div class="space-y-4">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Traffic Masks</h1>
    <div class="flex items-center gap-2">
      <button
        onclick={() => qc.invalidateQueries({ queryKey: ['masks'] })}
        class="flex items-center gap-2 px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
      >
        <RefreshCw size={16} />
        Refresh
      </button>
      <button
        onclick={() => fileInput.click()}
        disabled={uploading}
        class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
      >
        <Upload size={16} />
        {uploading ? 'Uploading...' : 'Upload Mask'}
      </button>
      <input
        bind:this={fileInput}
        type="file"
        accept=".json,application/json"
        onchange={handleUpload}
        class="hidden"
      />
    </div>
  </div>

  {#if uploadError}
    <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">
      {uploadError}
    </div>
  {/if}

  {#if $query.isLoading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
    </div>
  {:else if $query.data}
    <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
          <tr>
            <th class="px-4 py-3 text-left font-medium">ID</th>
            <th class="px-4 py-3 text-left font-medium">File</th>
            <th class="px-4 py-3 text-left font-medium">Size</th>
            <th class="px-4 py-3 text-left font-medium">Modified</th>
            <th class="px-4 py-3 text-right font-medium">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          {#each $query.data as mask (mask.id)}
            <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
              <td class="px-4 py-3 font-mono text-xs text-gray-600 dark:text-gray-400">
                <div class="flex items-center gap-2">
                  <Shield size={14} class="text-indigo-500 shrink-0" />
                  {mask.id}
                  {#if mask.generated}
                    <span
                      class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300"
                      title="Auto-generated from a recording">(auto)</span
                    >
                  {/if}
                </div>
              </td>
              <td class="px-4 py-3 text-gray-600 dark:text-gray-400 font-mono text-xs">{mask.file}</td>
              <td class="px-4 py-3 text-gray-600 dark:text-gray-400">{humanSize(mask.size_bytes)}</td>
              <td class="px-4 py-3 text-gray-600 dark:text-gray-400">
                {mask.modified ? new Date(mask.modified).toLocaleString() : '—'}
              </td>
              <td class="px-4 py-3 text-right">
                <button
                  onclick={() => handleDelete(mask.id)}
                  disabled={$deleteMut.isPending}
                  class="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded disabled:opacity-40"
                  title="Delete mask"
                >
                  <Trash2 size={15} />
                </button>
              </td>
            </tr>
          {/each}
          {#if $query.data.length === 0}
            <tr>
              <td colspan="5" class="px-4 py-8 text-center text-gray-400">No masks found. Upload a mask JSON file to get started.</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</div>
