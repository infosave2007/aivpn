<script lang="ts">
  import { X, Copy, Check } from 'lucide-svelte';

  let { open, connectionKey, onClose }: {
    open: boolean;
    connectionKey: string;
    onClose: () => void;
  } = $props();

  let copied = $state(false);

  async function copyKey() {
    await navigator.clipboard.writeText(connectionKey);
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
  }
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <button aria-label="Close dialog" class="absolute inset-0 bg-black/60" onclick={onClose}></button>
    <div class="relative bg-white dark:bg-gray-800 rounded-xl p-6 shadow-2xl max-w-lg w-full mx-4">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Connection Key</h2>
        <button onclick={onClose} class="text-gray-400 hover:text-gray-600">
          <X size={20} />
        </button>
      </div>
      <div class="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 mb-4">
        <p class="text-xs font-mono text-gray-700 dark:text-gray-300 break-all">{connectionKey}</p>
      </div>
      <button
        onclick={copyKey}
        class="flex items-center gap-2 w-full justify-center px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium transition-colors"
      >
        {#if copied}
          <Check size={16} />
          Copied!
        {:else}
          <Copy size={16} />
          Copy to clipboard
        {/if}
      </button>
    </div>
  </div>
{/if}
