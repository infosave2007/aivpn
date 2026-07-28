<script lang="ts">
  import QRCode from 'qrcode';
  import { X } from 'lucide-svelte';

  let { open, data, title, onClose }: {
    open: boolean;
    data: string;
    title: string;
    onClose: () => void;
  } = $props();

  let qrDataUrl = $state('');
  let error = $state('');

  // Re-render from scratch whenever the payload changes or the modal closes.
  // Keeping the previous data URL around painted client A's code while B was
  // still encoding (a phone could enroll against the wrong key — and this
  // modal also shows the TOTP otpauth_url, a different secret class than the
  // caption claims), and a single failure left `error` set forever, poisoning
  // every later open until a page reload. The stale-response guard drops a
  // slow encode whose payload has since been replaced.
  $effect(() => {
    qrDataUrl = '';
    error = '';
    if (!open || !data) return;
    let current = true;
    QRCode.toDataURL(data, { width: 256, margin: 2 })
      .then((url) => { if (current) qrDataUrl = url; })
      .catch((e: Error) => { if (current) error = e.message; });
    return () => { current = false; };
  });
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <button class="absolute inset-0 bg-black/60" onclick={onClose}></button>
    <div class="relative bg-white dark:bg-gray-800 rounded-xl p-6 shadow-2xl max-w-sm w-full mx-4">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
        <button onclick={onClose} class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
          <X size={20} />
        </button>
      </div>
      {#if error}
        <p class="text-red-500 text-sm">{error}</p>
      {:else if qrDataUrl}
        <div class="flex justify-center p-4 bg-white rounded-lg">
          <img src={qrDataUrl} alt="QR Code" class="w-64 h-64" />
        </div>
      {:else}
        <div class="flex justify-center py-8">
          <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
      {/if}
    </div>
  </div>
{/if}
