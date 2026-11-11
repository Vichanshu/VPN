import "server-only";

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { isIP, setDefaultAutoSelectFamilyAttemptTimeout } from "node:net";
import { checkReputation, loadIpLists } from "./ip-lists";
import { lookupIpinfo } from "./ipinfo";
import { canonicalClientAddress, isPublicIp, utcOffsetForTimeZone } from "./server-network";
import type { ServerNetworkData } from "./network";
import { evaluateGeolocation, readMeasurement, selectProbes, startPingMeasurement, type AtlasSample } from "./ripe-atlas";
import type { AtlasState, IpIntel, IpinfoState } from "./ip-intel";

// Node gives each address 250 ms before trying the next one. Distant APIs (RIPE Atlas
// from Asia) need longer, and IPv6 may be unreachable on the host network.
setDefaultAutoSelectFamilyAttemptTimeout(3_000);

/**
 * Orchestrates the IP intelligence layers with a small on-disk cache.
 *
 *  1. cache      .research-data/ip-intel.json, IPinfo answers kept 7 days
 *  2. lists      X4BNet / Tor / Apple Private Relay, matched locally
 *  3. IPinfo     claimed geolocation, ASN, privacy flags when the plan has them
 *  4. RIPE Atlas active geolocation check, started on request and polled
 *
 * Atlas measurements cost credits, so they are never started implicitly for
 * clean-looking addresses and are capped per day (ATLAS_DAILY_LIMIT).
 */

const IPINFO_TTL_MS = 7 * 24 * 60 * 60_000;
const ATLAS_TTL_MS = 24 * 60 * 60_000;
const FAILED_RETRY_MS = 10 * 60_000;
const ATLAS_MAX_WAIT_MS = 90_000;
const MAX_ENTRIES = 2_000;

interface CacheEntry {
  ip: string;
  ipinfo: IpinfoState;
  ipinfoAt: number;
  atlas: AtlasState;
  atlasAt: number;
}

interface CacheFile {
  entries: Record<string, CacheEntry>;
  atlasStarts: Record<string, number>;
}

function cachePath(): string {
  return process.env.IP_INTEL_FILE_STORE || path.join(process.cwd(), ".research-data", "ip-intel.json");
}

let writeQueue: Promise<void> = Promise.resolve();

async function readCache(): Promise<CacheFile> {
  try {
    const parsed = JSON.parse(await readFile(/*turbopackIgnore: true*/ cachePath(), "utf8")) as Partial<CacheFile>;
    return { entries: parsed.entries || {}, atlasStarts: parsed.atlasStarts || {} };
  } catch {
    return { entries: {}, atlasStarts: {} };
  }
}

/** Serialised read-modify-write so concurrent requests never clobber each other. */
function mutateCache(change: (cache: CacheFile) => void): Promise<void> {
  writeQueue = writeQueue.then(async () => {
    const cache = await readCache();
    change(cache);
    const keys = Object.keys(cache.entries);
    if (keys.length > MAX_ENTRIES) {
      keys.sort((a, b) => cache.entries[a].ipinfoAt - cache.entries[b].ipinfoAt).slice(0, keys.length - MAX_ENTRIES).forEach((key) => delete cache.entries[key]);
    }
    const file = cachePath();
    await mkdir(path.dirname(file), { recursive: true });
    const temporary = `${file}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(cache), "utf8");
    await rename(temporary, file);
  }).catch(() => undefined);
  return writeQueue;
}

export function normalizeIp(value: string | null | undefined): string | null {
  const ip = (value || "").trim().replace(/^\[|\]$/g, "");
  return isIP(ip) ? ip.toLowerCase() : null;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function dailyLimit(): number {
  const configured = Number(process.env.ATLAS_DAILY_LIMIT);
  return Number.isFinite(configured) && configured >= 0 ? configured : 20;
}

export function integrationStatus() {
  return { ipinfo: Boolean(process.env.IPINFO_TOKEN), atlas: Boolean(process.env.RIPE_ATLAS_KEY), atlasDailyLimit: dailyLimit() };
}

/**
 * Lists + IPinfo (cached) + whatever Atlas state is already known. Cheap
 * enough to run on every scan.
 */
export async function lookupIpIntel(ipInput: string): Promise<IpIntel | null> {
  const ip = normalizeIp(ipInput);
  if (!ip) return null;
  const isPublic = isPublicIp(ip);
  const now = Date.now();
  const cache = await readCache();
  let entry = cache.entries[ip];
  let fromCache = true;

  const lists = !isPublic || process.env.PUBLIC_IP_LISTS === "false" ? null : checkReputation(await loadIpLists(), ip, new Date().toISOString());

  if (isPublic && (!entry || now - entry.ipinfoAt > IPINFO_TTL_MS || (entry.ipinfo.status === "unavailable" && now - entry.ipinfoAt > 10 * 60_000))) {
    fromCache = false;
    const outcome = await lookupIpinfo(ip);
    const ipinfo: IpinfoState = outcome.ok ? { status: "ok", result: outcome.result } : { status: "unavailable", message: outcome.message };
    entry = { ip, ipinfo, ipinfoAt: now, atlas: entry?.atlas || { status: "not-run", message: "Not started." }, atlasAt: entry?.atlasAt || 0 };
    await mutateCache((file) => {
      const current = file.entries[ip];
      file.entries[ip] = { ...entry!, atlas: current?.atlas || entry!.atlas, atlasAt: current?.atlasAt || entry!.atlasAt };
    });
  }

  const expired = entry && ((entry.atlas.status === "done" && now - entry.atlasAt > ATLAS_TTL_MS) || (entry.atlas.status === "failed" && now - entry.atlasAt > FAILED_RETRY_MS));
  const atlas: AtlasState = expired ? { status: "not-run", message: "Earlier result expired." } : entry?.atlas || { status: "not-run", message: "Not started." };

  return {
    ip,
    checkedAt: new Date().toISOString(),
    fromCache,
    isPublic,
    lists,
    ipinfo: entry?.ipinfo || { status: "unavailable", message: isPublic ? "No lookup." : "Not a public address." },
    atlas,
  };
}

export type StartAtlasResult = { started: true } | { started: false; reason: string };

/** Starts a RIPE Atlas check for the address, unless one is running or the daily cap is reached. */
export async function startAtlasCheck(ipInput: string, force = false): Promise<StartAtlasResult> {
  const ip = normalizeIp(ipInput);
  if (!ip || !isPublicIp(ip)) return { started: false, reason: "Not a public IP address." };
  const intel = await lookupIpIntel(ip);
  if (!intel) return { started: false, reason: "Invalid IP address." };
  if (intel.ipinfo.status !== "ok") return { started: false, reason: "Atlas needs IPinfo's claimed location first, and IPinfo is unavailable." };
  const info = intel.ipinfo.result;
  if (info.latitude === null || info.longitude === null) return { started: false, reason: "IPinfo gave no coordinates for this address." };
  if (info.anycast) return { started: false, reason: "Anycast address: it answers from many places, so a single location cannot be checked." };
  if (!process.env.RIPE_ATLAS_KEY) return { started: false, reason: "RIPE_ATLAS_KEY is not configured." };
  if (intel.atlas.status === "running") return { started: false, reason: "A measurement is already running." };
  if (intel.atlas.status === "done" && !force) return { started: false, reason: "A recent result already exists." };

  const cache = await readCache();
  if ((cache.atlasStarts[today()] || 0) >= dailyLimit()) return { started: false, reason: `Daily RIPE Atlas limit (${dailyLimit()}) reached.` };

  const probes = await selectProbes({ latitude: info.latitude, longitude: info.longitude, country: info.country }, ip.includes(":") ? 6 : 4);
  const started = await startPingMeasurement(ip, probes);
  if (!started.ok) {
    await setAtlas(ip, { status: "failed", message: started.message });
    return { started: false, reason: started.message };
  }
  const sampled: AtlasSample[] = started.probes.map((probe) => ({ ...probe, minRttMs: null }));
  await mutateCache((file) => {
    file.atlasStarts[today()] = (file.atlasStarts[today()] || 0) + 1;
    for (const day of Object.keys(file.atlasStarts)) if (day !== today()) delete file.atlasStarts[day];
  });
  await setAtlas(ip, { status: "running", measurementId: started.measurementId, startedAt: new Date().toISOString(), probes: sampled, message: `Measurement ${started.measurementId} started from ${sampled.length} probes.` });
  return { started: true };
}

async function setAtlas(ip: string, atlas: AtlasState): Promise<void> {
  await mutateCache((file) => {
    const current = file.entries[ip];
    if (current) file.entries[ip] = { ...current, atlas, atlasAt: Date.now() };
  });
}

/** Reads the running measurement; when enough probes answered (or time is up) it computes the verdict. */
export async function pollAtlasCheck(ipInput: string): Promise<IpIntel | null> {
  const intel = await lookupIpIntel(ipInput);
  if (!intel || intel.atlas.status !== "running" || intel.ipinfo.status !== "ok") return intel;
  const running = intel.atlas;
  const info = intel.ipinfo.result;
  const progress = await readMeasurement(running.measurementId, running.probes);
  if (!progress || info.latitude === null || info.longitude === null) return intel;
  const answered = progress.samples.filter((sample) => sample.minRttMs !== null).length;
  const expired = Date.now() - Date.parse(running.startedAt) > ATLAS_MAX_WAIT_MS;
  const enough = answered >= Math.ceil(progress.samples.length * 0.8);
  if (progress.finished || expired || enough) {
    const geo = evaluateGeolocation({ latitude: info.latitude, longitude: info.longitude }, progress.samples);
    const atlas: AtlasState = { status: "done", measurementId: running.measurementId, finishedAt: new Date().toISOString(), samples: progress.samples, geo };
    await setAtlas(intel.ip, atlas);
    return { ...intel, atlas };
  }
  const atlas: AtlasState = { ...running, probes: progress.samples, message: `${answered} of ${progress.samples.length} probes have answered (${progress.status}).` };
  return { ...intel, atlas };
}

/* Request helpers ---------------------------------------------------- */

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 20;
const hits = new Map<string, number[]>();

/** Small per-client limiter: every lookup can spend IPinfo quota. */
export function rateLimited(request: Request): boolean {
  const client = canonicalClientAddress(request.headers).ip || request.headers.get("x-forwarded-for") || "local";
  const now = Date.now();
  const recent = (hits.get(client) || []).filter((time) => now - time < WINDOW_MS);
  recent.push(now);
  hits.set(client, recent);
  if (hits.size > 5_000) hits.clear();
  return recent.length > MAX_PER_WINDOW;
}

/**
 * "me" means the caller's address. Behind a trusted ingress that is the
 * canonical client IP; on a local dev machine the server shares the caller's
 * public address, so IPinfo's own "who am I" answer is used.
 */
export async function resolveMyIp(request: Request): Promise<string | null> {
  const canonical = canonicalClientAddress(request.headers);
  if (canonical.isPublicIp) return canonical.ip;
  if (process.env.NODE_ENV === "production" || !process.env.IPINFO_TOKEN) return null;
  // Networks that are switching (a VPN turning on, Wi-Fi roaming) drop the first
  // connection, so retry once before giving up.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await fetch("https://ipinfo.io/json", { headers: { authorization: `Bearer ${process.env.IPINFO_TOKEN}` }, cache: "no-store", signal: AbortSignal.timeout(10_000) });
      if (response.ok) {
        const ip = normalizeIp(((await response.json()) as { ip?: string }).ip);
        if (ip) return ip;
      }
      if (response.status === 401 || response.status === 403 || response.status === 429) return null;
    } catch {
      // try again
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return null;
}


/**
 * Local development only. Without a trusted ingress the server cannot read the
 * visitor's address, so every scan would lack an IP, location and list check.
 * A dev server shares the visitor's public address, so IPinfo's "who am I"
 * answer stands in for it, unless the browser reported its own address. The notice says so, and `trusted` stays false.
 */
export async function withDevNetworkFallback(request: Request, network: ServerNetworkData, browserReportedIp?: string): Promise<ServerNetworkData> {
  if (process.env.NODE_ENV === "production" || network.isPublicIp) return network;
  // The browser's own address is right even when a VPN covers only the browser;
  // the dev server's connection may bypass it.
  const reported = normalizeIp(browserReportedIp);
  const ip = reported && isPublicIp(reported) ? reported : await resolveMyIp(request);
  if (!ip) return network;
  const intel = await lookupIpIntel(ip);
  if (!intel || intel.ipinfo.status !== "ok") return network;
  const info = intel.ipinfo.result;
  const lists = intel.lists;
  return {
    ...network,
    ip,
    ipFamily: ip.includes(":") ? "ipv6" : "ipv4",
    isPublicIp: true,
    source: "local-dev-ipinfo",
    trusted: false,
    trustNotice: "Local development: the address was resolved through IPinfo, not read from a trusted ingress. Set TRUSTED_PROXY_PROVIDER on a deployment.",
    geoIp: {
      ip,
      city: info.city || "Unknown",
      country: info.country || "Unknown",
      countryCode: info.country || "Unknown",
      latitude: info.latitude,
      longitude: info.longitude,
      timezone: info.timezone || "Unknown",
      utcOffsetMinutes: info.timezone ? utcOffsetForTimeZone(info.timezone) : null,
      org: info.asnName || info.org || "Unknown",
      asn: info.asn || "Unknown",
      network: "",
      accuracyRadiusKm: null,
      countryConfidence: null,
      cityConfidence: null,
      databaseDate: "",
      source: "ipinfo",
      region: info.region || undefined,
    },
    anonymizer: lists
      ? { ...network.anonymizer, isTorExitNode: lists.tor, isPrivateRelay: lists.privateRelay, source: "public-lists", lists: { vpn: lists.vpn, datacenter: lists.datacenter, privateRelay: lists.privateRelay, tor: lists.tor, checked: lists.checked } }
      : network.anonymizer,
  };
}
