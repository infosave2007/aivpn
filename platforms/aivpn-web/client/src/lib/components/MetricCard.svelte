<script lang="ts">
  // `icon` accepts both Svelte 5 `Component` functions and lucide-svelte's
  // (currently still Svelte 3/4-style `SvelteComponentTyped` class) icon
  // exports — the two are not structurally assignable to each other under
  // the installed lucide-svelte@0.513/svelte@5.33 version pair, so this is
  // typed loosely on purpose rather than picking one shape and breaking the
  // other caller.
  let { title, value, subtitle, icon: Icon }: {
    title: string;
    value: string | number;
    subtitle?: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    icon?: any;
  } = $props();
</script>

<div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700 shadow-sm">
  <div class="flex items-start justify-between">
    <div>
      <p class="text-sm text-gray-500 dark:text-gray-400">{title}</p>
      <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">{value}</p>
      {#if subtitle}
        <p class="text-xs text-gray-400 mt-1">{subtitle}</p>
      {/if}
    </div>
    {#if Icon}
      <div class="p-2 bg-indigo-50 dark:bg-indigo-900/30 rounded-lg">
        <Icon size={20} class="text-indigo-600 dark:text-indigo-400" />
      </div>
    {/if}
  </div>
</div>
