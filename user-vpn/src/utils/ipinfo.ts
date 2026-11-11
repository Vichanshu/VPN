/**
 * IPinfo client: claimed geolocation, ASN/organisation, and (on plans that
 * include it) the privacy flags vpn / proxy / tor / relay / hosting.
 *
 * The token is read from IPINFO_TOKEN on the server only and is never part of
 * a response body or an error message.
 */

export interface IpinfoPrivacy {
  vpn: boolean;
  proxy: boolean;
  tor: boolean;
  relay: boolean;
  hosting: boolean;
  service: string;
}

export interface IpinfoResult {
  ip: string;
  city: string | null;
  region: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  /** Raw "AS15169 Google LLC" string. */
  org: string | null;
  asn: string | null;
  asnName: string | null;
  /** hosting | isp | business | education when the plan returns ASN type. */
  asnType: string | null;
  /** null when the plan does not include privacy detection. */
  privacy: IpinfoPrivacy | null;
  privacyAvailable: boolean;
  bogon: boolean;
  /** Anycast addresses answer from many places, so a single location is meaningless. */
  anycast: boolean;
}

export type IpinfoOutcome =
  | { ok: true; result: IpinfoResult }
  | { ok: false; reason: "no-token" | "rate-limited" | "unauthorized" | "failed"; message: string };

const BASE = "https://ipinfo.io";
const TIMEOUT_MS = 8_000;
/** Tokens whose plan lacks the privacy module (never stores the token outside memory). */
const privacyDenied = new Set<string>();

async function getJson(fetcher: typeof fetch, url: string, token: string): Promise<{ status: number; body: Record<string, unknown> | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    // The token travels in the Authorization header, not the URL, so it never lands in logs.
    const response = await fetcher(url, { signal: controller.signal, cache: "no-store", headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
    const body = response.ok ? ((await response.json()) as Record<string, unknown>) : null;
    return { status: response.status, body };
  } finally {
    clearTimeout(timer);
  }
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function parsePrivacy(value: unknown): IpinfoPrivacy | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (!["vpn", "proxy", "tor", "relay", "hosting"].some((key) => key in raw)) return null;
  return {
    vpn: raw.vpn === true,
    proxy: raw.proxy === true,
    tor: raw.tor === true,
    relay: raw.relay === true,
    hosting: raw.hosting === true,
    service: text(raw.service) || "",
  };
}

/** Parses the /json (and optional /privacy) payloads into one result. Exported for tests. */
export function parseIpinfo(ip: string, base: Record<string, unknown>, privacyBody: Record<string, unknown> | null): IpinfoResult {
  const [latText, lonText] = (text(base.loc) || "").split(",");
  const latitude = latText !== undefined && Number.isFinite(Number(latText)) && latText !== "" ? Number(latText) : null;
  const longitude = lonText !== undefined && Number.isFinite(Number(lonText)) && lonText !== "" ? Number(lonText) : null;
  const org = text(base.org);
  const orgMatch = org?.match(/^(AS\d+)\s+(.*)$/);
  const asnObject = base.asn && typeof base.asn === "object" ? (base.asn as Record<string, unknown>) : null;
  const privacy = parsePrivacy(base.privacy) || parsePrivacy(privacyBody);
  return {
    ip,
    city: text(base.city),
    region: text(base.region),
    country: text(base.country),
    latitude,
    longitude,
    timezone: text(base.timezone),
    org,
    asn: text(asnObject?.asn) || orgMatch?.[1] || null,
    asnName: text(asnObject?.name) || orgMatch?.[2] || null,
    asnType: text(asnObject?.type),
    privacy,
    privacyAvailable: privacy !== null,
    bogon: base.bogon === true,
    anycast: base.anycast === true,
  };
}

export async function lookupIpinfo(ip: string, fetcher: typeof fetch = fetch, token = process.env.IPINFO_TOKEN): Promise<IpinfoOutcome> {
  if (!token) return { ok: false, reason: "no-token", message: "IPINFO_TOKEN is not configured." };
  const target = encodeURIComponent(ip);
  try {
    const base = await getJson(fetcher, `${BASE}/${target}/json`, token);
    if (base.status === 401 || base.status === 403) return { ok: false, reason: "unauthorized", message: "IPinfo rejected the token." };
    if (base.status === 429) return { ok: false, reason: "rate-limited", message: "IPinfo rate limit or quota reached." };
    if (!base.body) return { ok: false, reason: "failed", message: `IPinfo returned HTTP ${base.status}.` };
    let privacyBody: Record<string, unknown> | null = null;
    if (!parsePrivacy(base.body.privacy) && !base.body.bogon && !privacyDenied.has(token)) {
      // Free plans answer 403 here; remember that so later lookups skip the wasted call.
      try {
        const privacy = await getJson(fetcher, `${BASE}/${target}/privacy`, token);
        if (privacy.status === 403) privacyDenied.add(token);
        privacyBody = privacy.body;
      } catch { privacyBody = null; }
    }
    return { ok: true, result: parseIpinfo(ip, base.body, privacyBody) };
  } catch {
    return { ok: false, reason: "failed", message: "IPinfo could not be reached." };
  }
}
