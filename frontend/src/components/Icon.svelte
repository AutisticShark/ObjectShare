<script lang="ts">
  let { name, size = 20 }: { name: string; size?: number } = $props();
  const paths: Record<string, string> = {
    upload: 'M12 16V4m-4 4 4-4 4 4M4 16v4h16v-4',
    files: 'M4 4h6l2 3h8v13H4V4Z',
    billing: 'M3 6h18v13H3V6Zm0 4h18M7 15h3',
    account: 'M8 7a4 4 0 1 0 8 0 4 4 0 0 0-8 0ZM5 21v-2a7 7 0 0 1 14 0v2',
    admin: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Zm-4 9 3 3 5-6',
    arrow: 'M5 12h14m-5-5 5 5-5 5',
    file: 'M14 3H5v18h14V8l-5-5Zm0 0v5h5',
    sun: 'M8 12a4 4 0 1 0 8 0 4 4 0 0 0-8 0ZM12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1',
    moon: 'M20 14a8 8 0 0 1-10-10 9 9 0 1 0 10 10Z',
    logout: 'M9 4H4v16h5m5-12 4 4-4 4m-6-4h14',
    lock: 'M6 11h12v10H6V11Zm3 0V7a3 3 0 0 1 6 0v4',
    close: 'm6 6 12 12M6 18 18 6',
    check: 'm5 12 4 4L19 6',
    search: 'M3 10a7 7 0 1 0 14 0 7 7 0 0 0-14 0Zm12 5 6 6',
    plus: 'M12 5v14M5 12h14',
    menu: 'M4 6h16M4 12h16M4 18h16',
    heart: 'M20 5a5 5 0 0 0-8 1 5 5 0 0 0-8 6l8 8 8-8a5 5 0 0 0 0-7Z',
  };
</script>
<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[name] || paths.file}></path></svg>
