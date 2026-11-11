/**
 * Public IP reputation lists, matched locally (no visitor IP leaves the
 * server). Sources:
 * - X4BNet lists_vpn: known VPN netblocks and VPN/datacenter ASNs (MIT).
 *   On the October 2026 study data the datacenter list matched 8/8 labelled
 *   VPN scans and 0/64 no-VPN scans; the VPN-only list matched 3/8.
 * - Apple iCloud Private Relay egress ranges (official CSV).
 * - Tor Project bulk exit list.
 */

export type ListName = "vpn" | "datacenter" | "private-relay" | "tor";

/** Each list may combine several files (X4BNet publishes IPv4 and IPv6 separately). */
export const LIST_SOURCES: Record<ListName, string[]> = {
  vpn: [
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt",
  ],
  datacenter: [
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt",
  ],
  "private-relay": ["https://mask-api.icloud.com/egress-ip-ranges.csv"],
  tor: ["https://check.torproject.org/torbulkexitlist"],
};

/** Sorted, merged [start, end] ranges per address family, for binary search. */
export interface RangeSet {
  v4: Array<[number, number]>;
  v6: Array<[bigint, bigint]>;
  entries: number;
}

export function parseIpv4(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

export function parseIpv6(ip: string): bigint | null {
  let address = ip.trim().toLowerCase();
  if (!address.includes(":")) return null;
  const zone = address.indexOf("%");
  if (zone >= 0) address = address.slice(0, zone);
  // IPv4-mapped tail, e.g. ::ffff:1.2.3.4
  const lastColon = address.lastIndexOf(":");
  const tail = address.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIpv4(tail);
    if (v4 === null) return null;
    address = `${address.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  let value = BigInt(0);
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << BigInt(16)) + BigInt(parseInt(group, 16));
  }
  return value;
}

/** Parses one CIDR or bare address; returns null for anything else. */
function parseCidr(text: string): { family: 4; start: number; end: number } | { family: 6; start: bigint; end: bigint } | null {
  const [address, bitsText] = text.trim().split("/");
  const v4 = parseIpv4(address);
  if (v4 !== null) {
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const size = 2 ** (32 - bits);
    const start = Math.floor(v4 / size) * size;
    return { family: 4, start, end: start + size - 1 };
  }
  const v6 = parseIpv6(address);
  if (v6 !== null) {
    const bits = bitsText === undefined ? 128 : Number(bitsText);
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
    const hostBits = BigInt(128 - bits);
    const start = (v6 >> hostBits) << hostBits;
    return { family: 6, start, end: start + (BigInt(1) << hostBits) - BigInt(1) };
  }
  return null;
}

function merge<T extends number | bigint>(ranges: Array<[T, T]>): Array<[T, T]> {
  ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const merged: Array<[T, T]> = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1]) {
      if (range[1] > last[1]) last[1] = range[1];
    } else merged.push([range[0], range[1]]);
  }
  return merged;
}

/** Accepts plain CIDR lists and CSVs whose first column is a CIDR (Apple). */
export function buildRangeSet(text: string): RangeSet {
  const v4: Array<[number, number]> = [];
  const v6: Array<[bigint, bigint]> = [];
  for (const line of text.split(/\r?\n/)) {
    const first = line.split(",")[0].trim();
    if (!first || first.startsWith("#")) continue;
    const parsed = parseCidr(first);
    if (!parsed) continue;
    if (parsed.family === 4) v4.push([parsed.start, parsed.end]);
    else v6.push([parsed.start, parsed.end]);
  }
  return { v4: merge(v4), v6: merge(v6), entries: v4.length + v6.length };
}

function search<T extends number | bigint>(ranges: Array<[T, T]>, value: T): boolean {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (ranges[middle][0] > value) high = middle - 1;
    else if (ranges[middle][1] < value) low = middle + 1;
    else return true;
  }
  return false;
}

export function inRangeSet(set: RangeSet, ip: string): boolean {
  const v4 = parseIpv4(ip);
  if (v4 !== null) return search(set.v4, v4);
  const v6 = parseIpv6(ip);
  if (v6 === null) return false;
  // IPv4-mapped IPv6 addresses are checked against the IPv4 ranges.
  if (v6 >> BigInt(32) === BigInt(0xffff)) return search(set.v4, Number(v6 & BigInt(0xffffffff)));
  return search(set.v6, v6);
}

export interface ReputationResult {
  vpn: boolean;
  datacenter: boolean;
  privateRelay: boolean;
  tor: boolean;
  /** Lists that were available for this lookup. */
  checked: ListName[];
  loadedAt: string | null;
}

type ListGlobal = typeof globalThis & {
  __ipLists?: { sets: Partial<Record<ListName, RangeSet>>; loadedAt: number; loading?: Promise<void> };
};

const LIST_TTL_MS = 24 * 60 * 60_000;

/**
 * Loads (and daily refreshes) the lists in memory. Each list is fetched
 * independently, so one unavailable source never blocks the others; a
 * failed refresh keeps the last good copy.
 */
export async function loadIpLists(fetcher: typeof fetch = fetch, names: ListName[] = ["vpn", "datacenter", "private-relay", "tor"]): Promise<Partial<Record<ListName, RangeSet>>> {
  const shared = globalThis as ListGlobal;
  const current = shared.__ipLists;
  if (current && Date.now() - current.loadedAt < LIST_TTL_MS && names.every((name) => current.sets[name])) return current.sets;
  if (current?.loading) {
    await current.loading;
    return shared.__ipLists!.sets;
  }
  const sets: Partial<Record<ListName, RangeSet>> = { ...(current?.sets || {}) };
  const loading = Promise.all(names.map(async (name) => {
    try {
      // A file that fails to load is skipped, so a missing IPv6 file never drops the IPv4 one.
      const texts = await Promise.all(LIST_SOURCES[name].map(async (source) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15_000);
        try {
          const response = await fetcher(source, { signal: controller.signal, cache: "no-store" });
          return response.ok ? await response.text() : "";
        } catch {
          return "";
        } finally {
          clearTimeout(timer);
        }
      }));
      const parsed = buildRangeSet(texts.join("\n"));
      if (parsed.entries > 0) sets[name] = parsed;
    } catch {
      // keep the previous copy of this list, if any
    }
  })).then(() => undefined);
  shared.__ipLists = { sets, loadedAt: current?.loadedAt || 0, loading };
  await loading;
  shared.__ipLists = { sets, loadedAt: Date.now() };
  return sets;
}

export function checkReputation(sets: Partial<Record<ListName, RangeSet>>, ip: string, loadedAt: string | null = null): ReputationResult {
  const has = (name: ListName) => Boolean(sets[name] && inRangeSet(sets[name]!, ip));
  return {
    vpn: has("vpn"),
    datacenter: has("datacenter"),
    privateRelay: has("private-relay"),
    tor: has("tor"),
    checked: (Object.keys(sets) as ListName[]).filter((name) => sets[name]),
    loadedAt,
  };
}
