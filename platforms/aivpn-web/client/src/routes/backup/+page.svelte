<script lang="ts">
  import { apiFetch } from '$lib/api';
  import { Upload, Download } from 'lucide-svelte';

  let importFile = $state<File | null>(null);
  let importing = $state(false);
  let importResult = $state('');
  let importError = $state(false);
  let exporting = $state(false);
  let dragOver = $state(false);
  let exportingBootstrap = $state(false);
  let bootstrapError = $state('');

  async function handleExport() {
    exporting = true;
    try {
      const res = await apiFetch('/api/v1/backup/export');
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aivpn-backup-${new Date().toISOString().slice(0, 10)}.bin`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Export failed');
    } finally {
      exporting = false;
    }
  }

  /**
   * GET /api/v1/bootstrap/export (admin-only, gated in proxy.ts) — the same
   * signed previous/current/next-epoch bootstrap descriptor JSON array an
   * already-connected client receives, and what
   * `--export-bootstrap-descriptor` prints on the CLI. Download-only, no
   * mutation — plain direct apiFetch like handleExport above.
   */
  async function handleExportBootstrap() {
    exportingBootstrap = true;
    bootstrapError = '';
    try {
      const res = await apiFetch('/api/v1/bootstrap/export');
      if (!res.ok) throw new Error(await res.text() || 'Export failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aivpn-bootstrap-descriptor-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      bootstrapError = e instanceof Error ? e.message : 'Export failed';
    } finally {
      exportingBootstrap = false;
    }
  }

  async function handleImport() {
    if (!importFile) return;
    importing = true;
    importResult = '';
    try {
      // apiFetch skips the default JSON Content-Type for File/Blob bodies,
      // so the backup binary is sent with the browser-derived type instead
      // of a mislabeled application/json.
      const res = await apiFetch('/api/v1/backup/import', {
        method: 'POST',
        body: importFile,
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || 'Import failed');
      }
      importResult = 'Backup imported successfully';
      importError = false;
      importFile = null;
    } catch (e: unknown) {
      importResult = e instanceof Error ? e.message : 'Import failed';
      importError = true;
    } finally {
      importing = false;
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragOver = false;
    const file = e.dataTransfer?.files[0];
    if (file) importFile = file;
  }
</script>

<div class="max-w-lg space-y-6">
  <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Backup</h1>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-3">
    <h2 class="text-base font-semibold text-gray-900 dark:text-white">Export</h2>
    <p class="text-sm text-gray-500 dark:text-gray-400">Download a full backup of all client configurations and keys.</p>
    <button
      onclick={handleExport}
      disabled={exporting}
      class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
    >
      <Download size={16} />
      {exporting ? 'Exporting...' : 'Export Backup'}
    </button>
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-3">
    <h2 class="text-base font-semibold text-gray-900 dark:text-white">Bootstrap Descriptor</h2>
    <p class="text-sm text-gray-500 dark:text-gray-400">Download the signed previous/current/next-epoch bootstrap descriptor to publish manually (same data an already-connected client receives, and what <code class="font-mono text-xs">--export-bootstrap-descriptor</code> prints on the CLI).</p>
    {#if bootstrapError}
      <div class="p-3 rounded-lg text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800">
        {bootstrapError}
      </div>
    {/if}
    <button
      onclick={handleExportBootstrap}
      disabled={exportingBootstrap}
      class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
    >
      <Download size={16} />
      {exportingBootstrap ? 'Exporting...' : 'Export Bootstrap Descriptor'}
    </button>
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 space-y-4">
    <h2 class="text-base font-semibold text-gray-900 dark:text-white">Import</h2>

    {#if importResult}
      <div class="p-3 rounded-lg text-sm {importError ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border border-red-200' : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200'}">
        {importResult}
      </div>
    {/if}

    <div
      role="region"
      aria-label="Drop zone"
      class="border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer
        {dragOver ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600 hover:border-gray-400'}"
      ondragover={(e) => { e.preventDefault(); dragOver = true; }}
      ondragleave={() => { dragOver = false; }}
      ondrop={onDrop}
    >
      <Upload class="mx-auto mb-3 text-gray-400" size={32} />
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">Drag and drop a backup file, or</p>
      <label class="cursor-pointer">
        <span class="text-indigo-600 dark:text-indigo-400 text-sm font-medium hover:underline">Browse file</span>
        <input
          type="file"
          class="hidden"
          onchange={(e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) importFile = f; }}
        />
      </label>
      {#if importFile}
        <p class="mt-2 text-xs text-gray-500">{importFile.name}</p>
      {/if}
    </div>

    <button
      onclick={handleImport}
      disabled={!importFile || importing}
      class="w-full py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
    >
      {importing ? 'Importing...' : 'Import Backup'}
    </button>
  </div>
</div>
