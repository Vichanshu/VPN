import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { checkReputation, loadIpLists } from "./ip-lists";
import type {
  AnonymizerData,
  GeoIpData,
  IpFamily,
  NetworkPathProbe,
  PathProbeKind,
  ProbeConfiguration,
  ServerNetworkData,
} from "./network";

type NetworkGlobal = typeof globalThis & {
  __torExitCache?: { expiresAt: number; addresses: Set<string> };
};

interface MaxMindInsightsResponse {
  city?: { names?: { en?: string }; confidence?: number };
  country?: { names?: { en?: string }; iso_code?: string; confidence?: number };
  location?: { latitude?: number; longitude?: number; time_zone?: string; accuracy_radius?: number };
  traits?: {
    organization?: string; isp?: string; autonomous_system_number?: number; network?: string;
    is_anonymous_vpn?: boolean; is_hosting_provider?: boolean; is_public_proxy?: boolean;
    is_residential_proxy?: boolean; is_tor_exit_node?: boolean; anonymizer_provider_name?: string;
    anonymizer_confidence?: number; network_last_seen?: string;
  };
}

const HOSTING_TERMS = [
  "amazon", "aws", "azure", "cloud", "digitalocean", "google cloud", "hetzner",
  "hosting", "linode", "m247", "oracle", "ovh", "server", "vultr", "leaseweb",
  "choopa", "quadranet", "hostinger", "datacamp", "mullvad", "nordvpn",
  "expressvpn", "surfshark",
];

export async function observeServerNetwork(request: Request, includeConfiguration = false): Promise<ServerNetworkData> {
  const canonical = canonicalClientAddress(request.headers);
  const enriched = canonical.isPublicIp ? await enrichIp(canonical.ip, request.headers) : unavailableEnrichment();
  const vercelPath = vercelRegions(request.headers);
  const configuredJa4Header = process.env.JA4_HEADER_NAME?.toLowerCase();
  const configuredProtocolHeader = process.env.HTTP_PROTOCOL_HEADER_NAME?.toLowerCase();

  const result: ServerNetworkData = {
    ...canonical,
    receivedAt: new Date().toISOString(),
    headers: selectedHeaders(request.headers),
    geoIp: enriched.geoIp,
    anonymizer: enriched.anonymizer,
    ja4: configuredJa4Header ? request.headers.get(configuredJa4Header) || "unavailable" : "unavailable",
    httpProtocol: configuredProtocolHeader ? request.headers.get(configuredProtocolHeader) || "unknown" : "unknown",
    tcpRttMs: trustedTcpRtt(request.headers),
    ...(vercelPath ? { edgeRegions: vercelPath.edgeRegions, functionRegion: vercelPath.functionRegion } : {}),
    proxyHeaders: proxyHeaders(request.headers),
    ...(includeConfiguration ? { probeConfiguration: probeConfiguration() } : {}),
  };
  if (includeConfiguration) result.scanChallenge = createScanChallenge(result, request.headers);
  return result;
}

export function verifyScanChallenge(token: string, network: ServerNetworkData, headers: Headers): boolean {
  const secret = process.env.SCAN_SIGNING_SECRET;
  if (!secret) return true;
  if (!token.includes(".")) return false;
  const [encoded, supplied] = token.split(".", 2);
  const expected = createHmac("sha256", secret).update(encoded).digest("base64url");
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(expected);
  if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) return false;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as { ip: string; ua: string; expiresAt: number };
    const ua = createHmac("sha256", secret).update(headers.get("user-agent") || "Unknown").digest("base64url");
    return payload.ip === network.ip && payload.ua === ua && payload.expiresAt >= Date.now();
  } catch {
    return false;
  }
}

export function canonicalClientAddress(headers: Headers): Pick<ServerNetworkData, "ip" | "ipFamily" | "isPublicIp" | "source" | "trusted" | "trustNotice"> {
  const provider = configuredIngressProvider();
  let source = "unavailable";
  let raw = "";

  if (provider === "cloudflare") {
    source = "cf-connecting-ip";
    raw = headers.get(source) || "";
  } else if (provider === "vercel") {
    source = "x-vercel-forwarded-for";
    raw = headers.get(source) || "";
  } else if (provider === "generic") {
    source = (process.env.TRUSTED_CLIENT_IP_HEADER || "").toLowerCase();
    raw = source ? headers.get(source) || "" : "";
  }

  const ip = normalizeIp(raw.split(",")[0] || "");
  const family = ipFamily(ip);
  const trusted = provider !== "none" && family !== "unknown";
  return {
    ip: trusted ? ip : "Unknown",
    ipFamily: trusted ? family : "unknown",
    isPublicIp: trusted && isPublicIp(ip),
    source: trusted ? source : "not-configured",
    trusted,
    trustNotice: trusted
      ? `Client IP accepted only from the configured ${provider} ingress header.`
      : "Set TRUSTED_PROXY_PROVIDER and its canonical client-IP header before treating network evidence as authoritative.",
  };
}

export function createProbeResponse(kind: PathProbeKind, network: ServerNetworkData): NetworkPathProbe {
  const payload = {
    kind,
    ip: network.ip,
    ipFamily: network.ipFamily,
    observedAt: network.receivedAt,
  };
  return {
    ...payload,
    status: network.isPublicIp ? "observed" : "unavailable",
    token: signProbePayload(payload),
    trusted: network.isPublicIp && Boolean(process.env.PROBE_SIGNING_SECRET),
  };
}

export async function verifyAndEnrichProbe(probe: NetworkPathProbe): Promise<NetworkPathProbe> {
  const verified = verifyProbeToken(probe.token, probe.kind);
  if (!verified) return { ...probe, trusted: false };
  const network = await networkForVerifiedProbe(verified.ip, verified.observedAt);
  return {
    kind: verified.kind,
    status: network.isPublicIp ? "observed" : "unavailable",
    ip: verified.ip,
    ipFamily: verified.ipFamily,
    observedAt: verified.observedAt,
    token: probe.token,
    trusted: network.isPublicIp,
    network,
  };
}

export function probeConfiguration(): ProbeConfiguration {
  const ipv4Url = process.env.IPV4_PROBE_URL || "";
  const ipv6Url = process.env.IPV6_PROBE_URL || "";
  const configuredStun = process.env.STUN_URL || "";
  const publicFallback = process.env.ALLOW_PUBLIC_STUN === "true" ? "stun:stun.l.google.com:19302" : "";
  return {
    ipv4Url,
    ipv6Url,
    stunUrl: configuredStun || publicFallback,
    configured: Boolean(ipv4Url || ipv6Url || configuredStun || publicFallback),
  };
}

/**
 * TCP RTT measured by the trusted ingress, e.g. nginx
 * `proxy_set_header X-TCP-RTT $tcpinfo_rtt;` (microseconds). Browsers cannot
 * spoof it because only the configured ingress sets the header.
 */
function trustedTcpRtt(headers: Headers): number | null {
  const name = process.env.TCP_RTT_HEADER_NAME?.toLowerCase();
  if (!name) return null;
  const raw = Number(headers.get(name));
  if (!Number.isFinite(raw) || raw <= 0) return null;
  const milliseconds = (process.env.TCP_RTT_HEADER_UNIT || "us").toLowerCase() === "ms" ? raw : raw / 1_000;
  return Number(milliseconds.toFixed(2));
}

function configuredIngressProvider(): "cloudflare" | "vercel" | "generic" | "none" {
  const configured = process.env.TRUSTED_PROXY_PROVIDER?.toLowerCase();
  if (configured === "cloudflare" || configured === "vercel" || configured === "generic") return configured;
  if (process.env.VERCEL === "1") return "vercel";
  return "none";
}

function createScanChallenge(network: ServerNetworkData, headers: Headers): string {
  const secret = process.env.SCAN_SIGNING_SECRET;
  if (!secret) return "";
  const payload = {
    ip: network.ip,
    ua: createHmac("sha256", secret).update(headers.get("user-agent") || "Unknown").digest("base64url"),
    expiresAt: Date.now() + 5 * 60_000,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${createHmac("sha256", secret).update(encoded).digest("base64url")}`;
}

function selectedHeaders(headers: Headers): Record<string, string> {
  return Object.fromEntries([
    "user-agent", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
  ].map((name) => [name, headers.get(name) || "Unknown"]));
}

function normalizeIp(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("[") && trimmed.includes("]")) return trimmed.slice(1, trimmed.indexOf("]"));
  return trimmed.replace(/^::ffff:/, "");
}

function ipFamily(ip: string): IpFamily {
  const version = isIP(ip);
  return version === 4 ? "ipv4" : version === 6 ? "ipv6" : "unknown";
}

export function isPublicIp(ip: string): boolean {
  const family = ipFamily(ip);
  if (family === "ipv4") {
    const octets = ip.split(".").map(Number);
    return !(
      octets[0] === 0 || octets[0] === 10 || octets[0] === 127 ||
      (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) || octets[0] >= 224
    );
  }
  if (family === "ipv6") {
    const lower = ip.toLowerCase();
    return !(lower === "::" || lower === "::1" || lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb") || lower.startsWith("fc") || lower.startsWith("fd"));
  }
  return false;
}

/**
 * Location: Vercel's edge geolocation headers when present (free, no
 * external call), otherwise MaxMind or ipapi. Reputation: public VPN,
 * datacenter, Private Relay and Tor lists matched locally, plus MaxMind's
 * anonymizer flags when configured.
 */
async function enrichIp(ip: string, headers?: Headers): Promise<{ geoIp: GeoIpData | null; anonymizer: AnonymizerData }> {
  const provider = process.env.IP_ENRICHMENT_PROVIDER || (process.env.MAXMIND_ACCOUNT_ID ? "maxmind" : "vercel");
  try {
    const vercelGeo = headers ? geoFromVercelHeaders(ip, headers) : null;
    const result = provider === "maxmind" ? await enrichWithMaxMind(ip)
      : provider === "ipapi" ? await enrichWithIpApi(ip)
        : { geoIp: vercelGeo, anonymizer: emptyAnonymizer() };
    if (!result.geoIp && vercelGeo) result.geoIp = vercelGeo;
    await applyPublicLists(ip, result.anonymizer);
    const tor = result.anonymizer.isTorExitNode || await isTorExit(ip);
    if (tor) {
      result.anonymizer.isTorExitNode = true;
      if (result.anonymizer.source === "unavailable") result.anonymizer.source = "tor-project";
    }
    return result;
  } catch {
    return unavailableEnrichment();
  }
}

async function applyPublicLists(ip: string, anonymizer: AnonymizerData): Promise<void> {
  if (process.env.PUBLIC_IP_LISTS === "false") return;
  const sets = await loadIpLists();
  const lists = checkReputation(sets, ip);
  if (!lists.checked.length) return;
  anonymizer.lists = { vpn: lists.vpn, datacenter: lists.datacenter, privateRelay: lists.privateRelay, tor: lists.tor, checked: lists.checked };
  // MaxMind's own flags take precedence; lists fill in what is unknown.
  if (lists.vpn) anonymizer.isAnonymousVpn = true;
  else anonymizer.isAnonymousVpn ??= false;
  if (lists.datacenter) anonymizer.isHostingProvider = true;
  else anonymizer.isHostingProvider ??= false;
  if (lists.tor) anonymizer.isTorExitNode = true;
  anonymizer.isPrivateRelay = lists.privateRelay;
  if (anonymizer.source === "unavailable") anonymizer.source = "public-lists";
}

/** Vercel adds IP geolocation headers to every deployed request. */
function geoFromVercelHeaders(ip: string, headers: Headers): GeoIpData | null {
  const country = headers.get("x-vercel-ip-country");
  if (!country) return null;
  const decode = (value: string | null) => {
    if (!value) return "Unknown";
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  };
  const timezone = headers.get("x-vercel-ip-timezone") || "Unknown";
  return {
    ip,
    city: decode(headers.get("x-vercel-ip-city")),
    country,
    countryCode: country,
    region: headers.get("x-vercel-ip-country-region") || undefined,
    continent: headers.get("x-vercel-ip-continent") || undefined,
    latitude: headerNumber(headers.get("x-vercel-ip-latitude")),
    longitude: headerNumber(headers.get("x-vercel-ip-longitude")),
    timezone,
    utcOffsetMinutes: timezone !== "Unknown" ? utcOffsetForTimeZone(timezone) : null,
    org: "Unknown",
    asn: "Unknown",
    network: "Unknown",
    accuracyRadiusKm: null,
    countryConfidence: null,
    cityConfidence: null,
    databaseDate: "vercel-edge",
    source: "vercel-edge",
  };
}

function headerNumber(value: string | null): number | null {
  return value === null || value.trim() === "" ? null : finiteNumber(value);
}

/** Current UTC offset of an IANA zone, in minutes. */
export function utcOffsetForTimeZone(timeZone: string, at = new Date()): number | null {
  try {
    const name = new Intl.DateTimeFormat("en-US", { timeZone, timeZoneName: "shortOffset" }).formatToParts(at).find((part) => part.type === "timeZoneName")?.value || "";
    const match = name.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
    if (name === "GMT") return 0;
    if (!match) return null;
    const minutes = Number(match[2]) * 60 + Number(match[3] || 0);
    return match[1] === "-" ? -minutes : minutes;
  } catch {
    return null;
  }
}

/** "bom1::iad1::abc-123" → edge regions ["bom1"], function region "iad1". */
function vercelRegions(headers: Headers): { edgeRegions: string[]; functionRegion: string } | null {
  const id = headers.get("x-vercel-id");
  if (!id) return null;
  const parts = id.split("::").filter(Boolean);
  if (parts.length < 2) return null;
  parts.pop();
  const functionRegion = parts.pop() || "";
  return { edgeRegions: parts.filter((part) => /^[a-z]{3}\d$/.test(part)), functionRegion };
}

/** Headers that ordinary clients never send but forwarding proxies often add. */
function proxyHeaders(headers: Headers): Record<string, string> {
  const names = ["via", "forwarded", "x-proxy-id", "proxy-connection", "x-bluecoat-via", "client-ip", "x-client-ip", "x-originating-ip", "x-forwarded-server"];
  return Object.fromEntries(names.map((name) => [name, headers.get(name)]).filter(([, value]) => value)) as Record<string, string>;
}

async function enrichWithMaxMind(ip: string): Promise<{ geoIp: GeoIpData | null; anonymizer: AnonymizerData }> {
  const account = process.env.MAXMIND_ACCOUNT_ID;
  const license = process.env.MAXMIND_LICENSE_KEY;
  if (!account || !license) return unavailableEnrichment();
  const authorization = Buffer.from(`${account}:${license}`).toString("base64");
  const response = await fetch(`https://geoip.maxmind.com/geoip/v2.1/insights/${encodeURIComponent(ip)}`, {
    cache: "no-store",
    headers: { authorization: `Basic ${authorization}` },
  });
  if (!response.ok) return unavailableEnrichment();
  const data = await response.json() as MaxMindInsightsResponse;
  const traits = data.traits || {};
  const location = data.location || {};
  const geoIp: GeoIpData = {
    ip,
    city: data.city?.names?.en || "Unknown",
    country: data.country?.names?.en || "Unknown",
    countryCode: data.country?.iso_code || "Unknown",
    latitude: finiteNumber(location.latitude),
    longitude: finiteNumber(location.longitude),
    timezone: location.time_zone || "Unknown",
    utcOffsetMinutes: null,
    org: traits.organization || traits.isp || "Unknown",
    asn: traits.autonomous_system_number ? `AS${traits.autonomous_system_number}` : "Unknown",
    network: traits.network || "Unknown",
    accuracyRadiusKm: finiteNumber(location.accuracy_radius),
    countryConfidence: finiteNumber(data.country?.confidence),
    cityConfidence: finiteNumber(data.city?.confidence),
    databaseDate: new Date().toISOString().slice(0, 10),
  };
  return {
    geoIp,
    anonymizer: {
      isAnonymousVpn: nullableBoolean(traits.is_anonymous_vpn),
      isHostingProvider: nullableBoolean(traits.is_hosting_provider),
      isPublicProxy: nullableBoolean(traits.is_public_proxy),
      isResidentialProxy: nullableBoolean(traits.is_residential_proxy),
      isTorExitNode: nullableBoolean(traits.is_tor_exit_node),
      providerName: traits.anonymizer_provider_name || "Unknown",
      confidence: finiteNumber(traits.anonymizer_confidence),
      networkLastSeen: traits.network_last_seen || "Unknown",
      source: "maxmind",
    },
  };
}

async function enrichWithIpApi(ip: string): Promise<{ geoIp: GeoIpData | null; anonymizer: AnonymizerData }> {
  const response = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { cache: "no-store" });
  if (!response.ok) return unavailableEnrichment();
  const data = await response.json() as Record<string, unknown>;
  const org = String(data.org || "Unknown");
  const asn = String(data.asn || "Unknown");
  const heuristicHosting = HOSTING_TERMS.some((term) => `${org} ${asn}`.toLowerCase().includes(term));
  return {
    geoIp: {
      ip,
      city: String(data.city || "Unknown"),
      country: String(data.country_name || "Unknown"),
      countryCode: String(data.country_code || "Unknown"),
      latitude: finiteNumber(data.latitude),
      longitude: finiteNumber(data.longitude),
      timezone: String(data.timezone || "Unknown"),
      utcOffsetMinutes: parseUtcOffset(data.utc_offset),
      org,
      asn,
      network: String(data.network || "Unknown"),
      accuracyRadiusKm: null,
      countryConfidence: null,
      cityConfidence: null,
      databaseDate: new Date().toISOString().slice(0, 10),
    },
    anonymizer: {
      ...emptyAnonymizer(),
      isHostingProvider: heuristicHosting,
      source: heuristicHosting ? "heuristic" : "unavailable",
    },
  };
}

async function isTorExit(ip: string): Promise<boolean> {
  if (process.env.TOR_EXIT_LOOKUP === "false") return false;
  const shared = globalThis as NetworkGlobal;
  const now = Date.now();
  if (!shared.__torExitCache || shared.__torExitCache.expiresAt < now) {
    try {
      const response = await fetch("https://check.torproject.org/torbulkexitlist", { cache: "no-store" });
      if (!response.ok) return false;
      const text = await response.text();
      shared.__torExitCache = {
        expiresAt: now + 15 * 60_000,
        addresses: new Set(text.split(/\s+/).filter((value) => isIP(value) > 0)),
      };
    } catch {
      return false;
    }
  }
  return shared.__torExitCache.addresses.has(ip);
}

function signProbePayload(payload: { kind: PathProbeKind; ip: string; ipFamily: IpFamily; observedAt: string }): string {
  const secret = process.env.PROBE_SIGNING_SECRET;
  if (!secret) return "";
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyProbeToken(token: string, expectedKind: PathProbeKind): { kind: PathProbeKind; ip: string; ipFamily: IpFamily; observedAt: string } | null {
  const secret = process.env.PROBE_SIGNING_SECRET;
  if (!secret || !token.includes(".")) return null;
  const [encoded, supplied] = token.split(".", 2);
  const expected = createHmac("sha256", secret).update(encoded).digest("base64url");
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(expected);
  if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (payload.kind !== expectedKind || ipFamily(payload.ip) !== payload.ipFamily || !isPublicIp(payload.ip)) return null;
    const age = Math.abs(Date.now() - Date.parse(payload.observedAt));
    if (!Number.isFinite(age) || age > 5 * 60_000) return null;
    return payload;
  } catch {
    return null;
  }
}

async function networkForVerifiedProbe(ip: string, observedAt: string): Promise<ServerNetworkData> {
  const enriched = await enrichIp(ip);
  return {
    ip,
    ipFamily: ipFamily(ip),
    isPublicIp: isPublicIp(ip),
    source: "signed-path-probe",
    trusted: true,
    trustNotice: "Address verified by an HMAC-signed first-party path endpoint.",
    receivedAt: observedAt,
    headers: {},
    geoIp: enriched.geoIp,
    anonymizer: enriched.anonymizer,
    ja4: "unavailable",
    httpProtocol: "unknown",
  };
}

function unavailableEnrichment(): { geoIp: null; anonymizer: AnonymizerData } {
  return { geoIp: null, anonymizer: emptyAnonymizer() };
}

function emptyAnonymizer(): AnonymizerData {
  return {
    isAnonymousVpn: null,
    isHostingProvider: null,
    isPublicProxy: null,
    isResidentialProxy: null,
    isTorExitNode: null,
    providerName: "Unknown",
    confidence: null,
    networkLastSeen: "Unknown",
    source: "unavailable",
  };
}

function finiteNumber(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? number : null;
}

function nullableBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function parseUtcOffset(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const match = value.match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!match) return null;
  const minutes = Number(match[2]) * 60 + Number(match[3]);
  return match[1] === "+" ? minutes : -minutes;
}
