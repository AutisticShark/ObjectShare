export function date(value: string | null | undefined, time = false): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat('en', {
    year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC',
    ...(time ? { hour: '2-digit', minute: '2-digit' } : {}),
  }).format(parsed) + (time ? ' UTC' : '');
}

export function amount(minor: number, currency: string): string {
  return new Intl.NumberFormat('en', { style: 'currency', currency }).format(minor / 100);
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let index = -1;
  do { value /= 1024; index++; } while (value >= 1024 && index < units.length - 1);
  return `${new Intl.NumberFormat('en', { maximumFractionDigits: 1 }).format(value)} ${units[index]}`;
}
