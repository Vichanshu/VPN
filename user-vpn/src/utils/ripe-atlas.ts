import { haversineKm } from "./vpn-detection.ts";

/**
 * RIPE Atlas active geolocation check.
 *
 * An IP address cannot be nearer to a probe than light allows. Pinging the
 * target from probes around the world gives each probe a hard upper bound on
 * the target's distance (constraint-based geolocation, Gueye et al. 2006):
 *   distance <= minRTT x 100 km/ms  (light in fibre, round trip)
 * If the location an IP claims lies outside any probe's circle, the address is
 * not where geolocation says, which is how VPN "virtual locations" give
 * themselves away (Weinberg et al., IMC 2018).
 *
 * The API key comes from RIPE_ATLAS_KEY on the server only.
 */

const API = "https://atlas.ripe.net/api/v2";
const TIMEOUT_MS = 12_000;
/** Maximum distance per millisecond of measured round trip (200 km/ms one way). */
export const KM_PER_RTT_MS = 100;
/** Probe coordinates are fuzzed and last-mile delay is not zero; allow for both. */
const SLACK_KM = 60;
/** Countries spread over the continents, one far probe each. */
const FAR_COUNTRIES = ["US", "BR", "GB", "ZA", "IN", "SG", "JP", "AU"];
const NEAR_PROBES = 4;
const NEAR_RADIUS_KM = 150;
export const MAX_PROBES_PER_CHECK = 12;
const PING_PACKETS = 2;

export interface AtlasProbe {
  id: number;
  latitude: number;
  longitude: number;
  country: string;
  role: "near" | "far";
}

export interface AtlasSample extends AtlasProbe {
  /** Best round trip in ms, or null when the probe got no reply. */
  minRttMs: number | null;
}

export type GeoVerdict = "consistent" | "inconsistent" | "inconclusive";

export interface GeoViolation {
  probeId: number;
  country: string;
  rttMs: number;
  maxKm: number;
  distanceKm: number;
}

export interface GeoCheck {
  verdict: GeoVerdict;
  reason: string;
  usableProbes: number;
  /** Smallest distance bound any probe gives for the target, in km. */
  tightestBoundKm: number | null;
  tightestProbe: { id: number; country: string; rttMs: number } | null;
  violations: GeoViolation[];
}

/** Pure geometry: does the claimed point fit every probe's distance bound? */
export function evaluateGeolocation(claimed: { latitude: number; longitude: number }, samples: AtlasSample[]): GeoCheck {
  const usable = samples.filter((sample): sample is AtlasSample & { minRttMs: number } => sample.minRttMs !== null && sample.minRttMs >= 0);
  const violations: GeoViolation[] = [];
  let tightest: (typeof usable)[number] | null = null;
  for (const sample of usable) {
    const maxKm = sample.minRttMs * KM_PER_RTT_MS;
    const distanceKm = haversineKm(claimed.latitude, claimed.longitude, sample.latitude, sample.longitude);
    if (distanceKm > maxKm + SLACK_KM) violations.push({ probeId: sample.id, country: sample.country, rttMs: sample.minRttMs, maxKm: Math.round(maxKm), distanceKm: Math.round(distanceKm) });
    if (!tightest || sample.minRttMs < tightest.minRttMs) tightest = sample;
  }
  const tightestBoundKm = tightest ? Math.round(tightest.minRttMs * KM_PER_RTT_MS) : null;
  const tightestProbe = tightest ? { id: tightest.id, country: tightest.country, rttMs: tightest.minRttMs } : null;
  violations.sort((a, b) => (b.distanceKm - b.maxKm) - (a.distanceKm - a.maxKm));
  if (usable.length < 3) return { verdict: "inconclusive", reason: `Only ${usable.length} probe${usable.length === 1 ? "" : "s"} answered; at least 3 are needed.`, usableProbes: usable.length, tightestBoundKm, tightestProbe, violations };
  if (violations.length) {
    const worst = violations[0];
    return { verdict: "inconsistent", reason: `A probe in ${worst.country} measured ${worst.rttMs} ms, so the target is within ${worst.maxKm} km of it, but the claimed location is ${worst.distanceKm} km away. The address cannot be where it claims to be.`, usableProbes: usable.length, tightestBoundKm, tightestProbe, violations };
  }
  if (tightestBoundKm !== null && tightestBoundKm <= 1_500) return { verdict: "consistent", reason: `No probe contradicts the claimed location, and the closest probe (${tightestProbe!.country}, ${tightestProbe!.rttMs} ms) places the target within ${tightestBoundKm} km of itself.`, usableProbes: usable.length, tightestBoundKm, tightestProbe, violations };
  return { verdict: "inconclusive", reason: "No probe contradicts the claimed location, but none was close enough to confirm it.", usableProbes: usable.length, tightestBoundKm, tightestProbe, violations };
}

/* ----------------------------------------------------------------------- */
/* API calls                                                                */
/* ----------------------------------------------------------------------- */

async function request(fetcher: typeof fetch, url: string, init: RequestInit = {}, key?: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetcher(url, {
      ...init,
      signal: controller.signal,
      cache: "no-store",
      headers: { accept: "application/json", ...(init.body ? { "content-type": "application/json" } : {}), ...(key ? { authorization: `Key ${key}` } : {}) },
    });
  } finally {
    clearTimeout(timer);
  }
}

function toProbe(raw: unknown, role: AtlasProbe["role"]): AtlasProbe | null {
  const item = raw as { id?: number; country_code?: string; geometry?: { coordinates?: number[] } };
  const coordinates = item?.geometry?.coordinates;
  if (typeof item?.id !== "number" || !coordinates || coordinates.length < 2) return null;
  return { id: item.id, longitude: coordinates[0], latitude: coordinates[1], country: item.country_code || "??", role };
}

async function probeQuery(fetcher: typeof fetch, params: Record<string, string>, family: 4 | 6, role: AtlasProbe["role"]): Promise<AtlasProbe[]> {
  const query = new URLSearchParams({ status: "1", is_public: "true", tags: family === 6 ? "system-ipv6-works" : "system-ipv4-works", fields: "id,geometry,country_code", ...params });
  try {
    const response = await request(fetcher, `${API}/probes/?${query}`);
    if (!response.ok) return [];
    const body = (await response.json()) as { results?: unknown[] };
    return (body.results || []).map((item) => toProbe(item, role)).filter((probe): probe is AtlasProbe => probe !== null);
  } catch {
    return [];
  }
}

/** Probes near the claimed location plus one far probe on each continent. */
export async function selectProbes(claimed: { latitude: number; longitude: number; country?: string | null }, family: 4 | 6 = 4, fetcher: typeof fetch = fetch): Promise<AtlasProbe[]> {
  const [near, ...far] = await Promise.all([
    probeQuery(fetcher, { radius: `${claimed.latitude},${claimed.longitude}:${NEAR_RADIUS_KM}`, page_size: String(NEAR_PROBES) }, family, "near"),
    ...FAR_COUNTRIES.filter((country) => country !== claimed.country).map((country) => probeQuery(fetcher, { country_code: country, page_size: "1" }, family, "far")),
  ]);
  const unique = new Map<number, AtlasProbe>();
  for (const probe of [...near, ...far.flat()]) if (!unique.has(probe.id)) unique.set(probe.id, probe);
  return Array.from(unique.values()).slice(0, MAX_PROBES_PER_CHECK);
}

export type StartOutcome =
  | { ok: true; measurementId: number; probes: AtlasProbe[] }
  | { ok: false; reason: "no-key" | "no-probes" | "rejected" | "failed"; message: string };

/** Starts a one-off ping measurement to the target from the chosen probes. */
export async function startPingMeasurement(target: string, probes: AtlasProbe[], fetcher: typeof fetch = fetch, key = process.env.RIPE_ATLAS_KEY): Promise<StartOutcome> {
  if (!key) return { ok: false, reason: "no-key", message: "RIPE_ATLAS_KEY is not configured." };
  if (!probes.length) return { ok: false, reason: "no-probes", message: "No RIPE Atlas probes could be selected." };
  // Private measurements cost twice the credits. Public ones list the target IP on atlas.ripe.net.
  const publicMeasurements = process.env.RIPE_ATLAS_PUBLIC_MEASUREMENTS === "true";
  const body = {
    definitions: [{ type: "ping", af: target.includes(":") ? 6 : 4, target, description: "VPN lab geolocation check", packets: PING_PACKETS, size: 48, is_oneoff: true, is_public: publicMeasurements }],
    probes: [{ requested: probes.length, type: "probes", value: probes.map((probe) => probe.id).join(",") }],
    is_oneoff: true,
  };
  try {
    const response = await request(fetcher, `${API}/measurements/`, { method: "POST", body: JSON.stringify(body) }, key);
    const payload = (await response.json().catch(() => null)) as { measurements?: number[]; error?: { detail?: string; errors?: Array<{ detail?: string }> } } | null;
    if (!response.ok || !payload?.measurements?.length) {
      const detail = payload?.error?.errors?.[0]?.detail || payload?.error?.detail || `HTTP ${response.status}`;
      return { ok: false, reason: response.status === 401 || response.status === 403 ? "rejected" : "failed", message: `RIPE Atlas refused the measurement: ${detail}` };
    }
    return { ok: true, measurementId: payload.measurements[0], probes };
  } catch {
    return { ok: false, reason: "failed", message: "RIPE Atlas could not be reached." };
  }
}

export interface MeasurementProgress {
  status: string;
  finished: boolean;
  samples: AtlasSample[];
}

/** Reads the results so far. Probes that have not replied yet show minRttMs null. */
export async function readMeasurement(measurementId: number, probes: AtlasProbe[], fetcher: typeof fetch = fetch, key = process.env.RIPE_ATLAS_KEY): Promise<MeasurementProgress | null> {
  try {
    const [meta, results] = await Promise.all([
      request(fetcher, `${API}/measurements/${measurementId}/`, {}, key),
      request(fetcher, `${API}/measurements/${measurementId}/results/`, {}, key),
    ]);
    if (!meta.ok || !results.ok) return null;
    const status = ((await meta.json()) as { status?: { name?: string } }).status?.name || "Unknown";
    const rows = (await results.json()) as Array<{ prb_id?: number; min?: number; rcvd?: number }>;
    const byProbe = new Map<number, number | null>();
    for (const row of rows) {
      if (typeof row.prb_id !== "number") continue;
      byProbe.set(row.prb_id, typeof row.min === "number" && row.min >= 0 && (row.rcvd ?? 1) > 0 ? row.min : null);
    }
    return {
      status,
      finished: ["Stopped", "Failed", "No suitable probes", "Archived"].includes(status),
      samples: probes.map((probe) => ({ ...probe, minRttMs: byProbe.get(probe.id) ?? null })),
    };
  } catch {
    return null;
  }
}
