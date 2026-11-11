import type { ResearchObservation } from "./fingerprint";
import { ipIntelEvidence, type IpIntel } from "./ip-intel.ts";
import type { EvidenceGroup, RiskAssessment, RiskEvidence } from "./risk";

/**
 * Device-anchored VPN detection.
 *
 * A VPN changes the network a device appears from, not the device. Once the
 * linkage model knows which earlier scans belong to the same physical device,
 * the device's own history becomes the baseline: its usual networks, its
 * usual latency, its usual location. Population-wide, a VPN exit is a network
 * that many unrelated devices pass through but none of them lives on.
 *
 * Evidence sources and parameters (see VPN_DETECTION_RESEARCH.md):
 * - IP reputation: X4BNet VPN and datacenter lists, Tor exit list, Apple
 *   Private Relay ranges, MaxMind anonymizer flags when configured.
 * - Location consistency: IP timezone vs browser timezone; device home
 *   country (FP-Inconsistent-style consistency checks).
 * - Latency geometry: light in fibre ≈ 200 km/ms, so RTT ≥ distance/100 km
 *   (Octant; CBG, Gueye et al.). Latency the claimed IP location cannot
 *   explain indicates a relay (Weinberg et al., IMC 2018; SNITCH).
 * - Path: WebRTC public address vs HTTP address (VPNalyzer-style leaks),
 *   forwarding headers, application vs TCP RTT gap > 50 ms (CalcuLatency,
 *   USENIX Security 2024).
 * - Device history: leaving the device's usual networks, latency jumps over
 *   its own baseline, exits shared by unrelated devices.
 *
 * Likelihood ratios are research priors; the per-signal table on the Saved
 * data page shows how each one behaves on labelled scans.
 */

export const VPN_MODEL_VERSION = "vpn-device-anchored-1.0";

export interface ReputationLookup {
  vpn: boolean;
  datacenter: boolean;
  privateRelay: boolean;
  tor: boolean;
  checked: string[];
}

export interface VpnContext {
  current: ResearchObservation;
  /** Earlier scans the linkage model attributes to the same physical device. */
  deviceHistory: ResearchObservation[];
  /** Recent scans from everyone, each with its inferred device id. */
  population: Array<{ observation: ResearchObservation; deviceId: string }>;
  currentDeviceId?: string;
  /** IPinfo and RIPE Atlas findings for the scan's address, when available. */
  ipIntel?: Pick<IpIntel, "ipinfo" | "atlas"> | null;
  /** Reputation of any address (used for history and population scans). */
  reputationOf?: (ip: string) => ReputationLookup | null;
  priorProbability?: number;
}

const GROUP_CAPS: Record<EvidenceGroup, { positive: number; negative: number }> = {
  network: { positive: 5.5, negative: -1.2 },
  location: { positive: 3, negative: -1 },
  path: { positive: 4, negative: -1.2 },
  history: { positive: 3, negative: -1.5 },
  integrity: { positive: 0.8, negative: 0 },
};

/* ----------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ----------------------------------------------------------------------- */

/** Great-circle distance in km. */
export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const radians = (degrees: number) => (degrees * Math.PI) / 180;
  const deltaLat = radians(lat2 - lat1);
  const deltaLon = radians(lon2 - lon1);
  const a = Math.sin(deltaLat / 2) ** 2 + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  return 6_371 * 2 * Math.asin(Math.sqrt(a));
}

/** Minimum physically possible round trip for a distance (light in fibre). */
export function minimumRttMs(distanceKm: number): number {
  return distanceKm / 100;
}

export function networkPrefix(ip: string | undefined): string | null {
  if (!ip || ip === "Unknown") return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").slice(0, 2).join(".") + ".0.0/16";
  if (ip.includes(":")) return ip.toLowerCase().split(":").slice(0, 2).join(":") + "::/32";
  return null;
}

export function exitPrefix(ip: string | undefined): string | null {
  if (!ip || ip === "Unknown") return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").slice(0, 3).join(".") + ".0/24";
  if (ip.includes(":")) return ip.toLowerCase().split(":").slice(0, 3).join(":") + "::/48";
  return null;
}

interface TimezoneAnchor { latitude: number; longitude: number; region: string }

const ZONE_ANCHORS: Record<string, [number, number, string]> = {
  "Asia/Calcutta": [22.5, 78.9, "India"], "Asia/Kolkata": [22.5, 78.9, "India"],
  "Asia/Karachi": [30, 69, "Pakistan"], "Asia/Dhaka": [23.8, 90.4, "Bangladesh"], "Asia/Colombo": [7.9, 80.7, "Sri Lanka"],
  "Asia/Dubai": [25.2, 55.3, "the Gulf"], "Asia/Riyadh": [24.7, 46.7, "Arabia"], "Asia/Tehran": [35.7, 51.4, "Iran"],
  "Asia/Singapore": [1.35, 103.8, "Singapore"], "Asia/Bangkok": [13.8, 100.5, "Southeast Asia"], "Asia/Jakarta": [-6.2, 106.8, "Indonesia"],
  "Asia/Manila": [14.6, 121, "the Philippines"], "Asia/Hong_Kong": [22.3, 114.2, "Hong Kong"], "Asia/Shanghai": [31.2, 121.5, "China"],
  "Asia/Tokyo": [35.7, 139.7, "Japan"], "Asia/Seoul": [37.6, 127, "Korea"], "Australia/Sydney": [-33.9, 151.2, "eastern Australia"],
  "Australia/Melbourne": [-37.8, 145, "eastern Australia"], "Australia/Perth": [-31.9, 115.9, "western Australia"],
  "Pacific/Auckland": [-36.9, 174.8, "New Zealand"], "Europe/London": [51.5, -0.1, "the UK"], "Europe/Dublin": [53.3, -6.3, "Ireland"],
  "Europe/Paris": [48.9, 2.4, "France"], "Europe/Berlin": [52.5, 13.4, "Germany"], "Europe/Madrid": [40.4, -3.7, "Spain"],
  "Europe/Rome": [41.9, 12.5, "Italy"], "Europe/Amsterdam": [52.4, 4.9, "the Netherlands"], "Europe/Moscow": [55.8, 37.6, "Russia"],
  "Europe/Istanbul": [41, 29, "Turkey"], "Africa/Johannesburg": [-26.2, 28, "South Africa"], "Africa/Cairo": [30, 31.2, "Egypt"],
  "Africa/Lagos": [6.5, 3.4, "Nigeria"], "Africa/Nairobi": [-1.3, 36.8, "Kenya"],
  "America/New_York": [40.7, -74, "the US east coast"], "America/Toronto": [43.7, -79.4, "eastern Canada"], "America/Chicago": [41.9, -87.6, "the US midwest"],
  "America/Denver": [39.7, -105, "the US mountain states"], "America/Los_Angeles": [34, -118.2, "the US west coast"],
  "America/Mexico_City": [19.4, -99.1, "Mexico"], "America/Sao_Paulo": [-23.5, -46.6, "Brazil"], "America/Argentina/Buenos_Aires": [-34.6, -58.4, "Argentina"],
  "America/Bogota": [4.7, -74.1, "Colombia"],
};

/** A rough location for the browser's timezone, for use when no IP location exists. */
export function timezoneAnchor(name: string): TimezoneAnchor | null {
  const known = ZONE_ANCHORS[name];
  if (known) return { latitude: known[0], longitude: known[1], region: known[2] };
  return null;
}

function ipOf(observation: ResearchObservation): string {
  return observation.serverNetwork?.ip || observation.effectivePublicIp;
}

function median(values: number[]): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function storedReputation(observation: ResearchObservation, lookup?: VpnContext["reputationOf"]): ReputationLookup | null {
  const stored = observation.serverNetwork?.anonymizer?.lists;
  if (stored) return stored;
  return lookup ? lookup(ipOf(observation)) : null;
}

/**
 * A scan counts towards a device's "home" baseline only if nothing marks it
 * as anonymized: not on a VPN/datacenter/Tor list and not previously judged
 * likely VPN. Otherwise a device that used a VPN before would learn its VPN
 * exit as "home".
 */
function isCleanScan(observation: ResearchObservation, lookup?: VpnContext["reputationOf"]): boolean {
  const reputation = storedReputation(observation, lookup);
  if (reputation && (reputation.vpn || reputation.datacenter || reputation.tor)) return false;
  const assessment = observation.riskAssessment;
  if (assessment?.modelVersion === VPN_MODEL_VERSION && assessment.probability >= 0.5) return false;
  return true;
}

function add(evidence: RiskEvidence[], id: string, group: EvidenceGroup, label: string, detail: string, logLikelihoodRatio: number, strength: RiskEvidence["strength"], source: string) {
  evidence.push({ id, group, label, detail, logLikelihoodRatio, strength, source });
}

/* ----------------------------------------------------------------------- */
/* Model                                                                    */
/* ----------------------------------------------------------------------- */

export function assessVpn(context: VpnContext): RiskAssessment {
  const { current } = context;
  const evidence: RiskEvidence[] = [];
  const server = current.serverNetwork;
  const fingerprint = current.fingerprint;
  const ip = ipOf(current);
  const geo = server?.geoIp || null;
  const anonymizer = server?.anonymizer;
  // Reputation only means something for a trusted public address.
  const lists = server?.isPublicIp ? storedReputation(current, context.reputationOf) : null;
  const details: NonNullable<RiskAssessment["details"]> = {};

  /* --- IP reputation ----------------------------------------------------- */
  if (lists?.tor || anonymizer?.isTorExitNode) add(evidence, "tor-exit", "network", "Tor exit node", "The address is on the Tor Project's exit list.", 5, "strong", "tor-project");
  if (lists?.vpn) add(evidence, "vpn-list", "network", "Known VPN network", "The address is inside a netblock attributed to a commercial VPN provider (X4BNet list).", 4, "strong", "x4bnet-vpn");
  else if (lists?.datacenter) add(evidence, "datacenter-list", "network", "Datacenter / hosting network", "The address belongs to a hosting or VPN provider's network, not a home or mobile ISP (X4BNet list). Cloud desktops and some corporate gateways also match.", 2.8, "strong", "x4bnet-datacenter");
  if (lists?.privateRelay) add(evidence, "private-relay", "network", "iCloud Private Relay", "The address is an Apple iCloud Private Relay egress. This is a privacy relay built into Safari, not a VPN chosen to hide location.", 1.5, "moderate", "apple-relay-ranges");
  if (anonymizer?.source === "maxmind") {
    if (anonymizer.isAnonymousVpn && !lists?.vpn) add(evidence, "maxmind-vpn", "network", "Anonymous VPN (MaxMind)", `MaxMind classifies the network as an anonymous VPN${anonymizer.providerName && anonymizer.providerName !== "Unknown" ? ` (${anonymizer.providerName})` : ""}.`, 3.6, "strong", "maxmind");
    if (anonymizer.isPublicProxy) add(evidence, "maxmind-proxy", "network", "Public proxy (MaxMind)", "MaxMind classifies the address as a public proxy.", 3, "strong", "maxmind");
    if (anonymizer.isResidentialProxy) add(evidence, "maxmind-residential-proxy", "network", "Residential proxy (MaxMind)", "MaxMind classifies the address as a residential proxy exit.", 2.6, "strong", "maxmind");
  }
  if (lists && lists.checked.length >= 2 && !lists.vpn && !lists.datacenter && !lists.tor && !lists.privateRelay) {
    add(evidence, "clean-reputation", "network", "Ordinary ISP address", "The address is on no VPN, datacenter, Tor or relay list. Residential proxies and small VPNs can still be missed.", -0.7, "context", "public-lists");
  }

  if (context.ipIntel && server?.isPublicIp) evidence.push(...ipIntelEvidence(context.ipIntel, lists));

  /* --- Location consistency --------------------------------------------- */
  const browserOffset = fingerprint.timezone.offsetMinutes;
  if (geo?.utcOffsetMinutes !== null && geo?.utcOffsetMinutes !== undefined) {
    const difference = Math.abs(geo.utcOffsetMinutes - browserOffset);
    if (difference >= 60) add(evidence, "timezone-mismatch", "location", "Browser and IP timezones disagree", `The browser is set to ${fingerprint.timezone.name} (UTC${formatOffset(browserOffset)}) but the IP is located in ${geo.timezone} (UTC${formatOffset(geo.utcOffsetMinutes)}). Travellers who keep their home clock also match.`, 2, "moderate", "browser-vs-ip-geolocation");
    else if (difference === 0) add(evidence, "timezone-consistent", "location", "Timezone matches the IP location", `Browser and IP both use UTC${formatOffset(browserOffset)}.`, -0.5, "context", "browser-vs-ip-geolocation");
  }
  const historyCountries = context.deviceHistory
    .filter((item) => isCleanScan(item, context.reputationOf))
    .map((item) => item.serverNetwork?.geoIp?.countryCode)
    .filter((value): value is string => Boolean(value && value !== "Unknown"));
  if (geo?.countryCode && geo.countryCode !== "Unknown" && historyCountries.length && !historyCountries.includes(geo.countryCode)) {
    add(evidence, "country-departure", "location", "Device appears from a new country", `This device was previously seen from ${Array.from(new Set(historyCountries)).join(", ")}; now from ${geo.countryCode}.`, 1.2, "moderate", "device-history");
  }

  /* --- Latency geometry (constraint-based geolocation) ------------------ */
  const landmarks = (fingerprint.landmarks?.measurements || []).filter((item) => item.minMs !== null);
  if (landmarks.length >= 3 && geo?.latitude !== null && geo?.latitude !== undefined && geo.longitude !== null && geo.longitude !== undefined) {
    let excess = Infinity;
    let nearest: string | null = null;
    let impossible: { city: string; rtt: number; needed: number } | null = null;
    for (const landmark of landmarks) {
      const distance = haversineKm(geo.latitude, geo.longitude, landmark.latitude, landmark.longitude);
      const needed = minimumRttMs(distance);
      const rtt = landmark.minMs!;
      if (rtt - needed < excess) { excess = rtt - needed; nearest = landmark.city; }
      if (distance > 1_500 && rtt < needed * 0.8 && (!impossible || needed - rtt > impossible.needed - impossible.rtt)) impossible = { city: landmark.city, rtt, needed };
    }
    details.excessLatencyMs = Math.round(excess);
    details.nearestLandmark = nearest;
    if (impossible) add(evidence, "geo-impossible", "path", "IP location is physically impossible", `A ${Math.round(impossible.rtt)} ms round trip to ${impossible.city} is faster than light in fibre allows from ${geo.city || geo.country} (needs ≥ ${Math.round(impossible.needed)} ms). The address is not where geolocation places it, typical of VPN "virtual locations".`, 1.6, "moderate", "latency-geolocation");
    if (excess > 180) add(evidence, "excess-latency-high", "path", "Large latency the IP location cannot explain", `Even the best-placed landmark (${nearest}) answers ${Math.round(excess)} ms slower than ${geo.city || geo.country} allows. Traffic is likely travelling through a distant relay first.`, 2.4, "strong", "latency-geolocation");
    else if (excess > 100) add(evidence, "excess-latency", "path", "Latency the IP location cannot fully explain", `About ${Math.round(excess)} ms of extra round-trip time beyond the distance from ${geo.city || geo.country} to the nearest landmark (${nearest}). Slow mobile links can add some of this.`, 1.3, "moderate", "latency-geolocation");
    else if (excess < 50) add(evidence, "latency-consistent", "path", "Latency fits the IP location", `Round trips match a client located near ${geo.city || geo.country} (≈${Math.max(0, Math.round(excess))} ms of last-mile delay).`, -0.9, "context", "latency-geolocation");
  }

  // Without an IP location, the browser's own timezone says roughly where the
  // client should be. A nearest landmark far slower than that region allows
  // means the traffic is detouring through a relay.
  else if (landmarks.length >= 3) {
    const anchor = timezoneAnchor(fingerprint.timezone.name);
    if (anchor) {
      const floor = Math.min(...landmarks.map((item) => item.minMs!));
      const expected = Math.min(...landmarks.map((item) => minimumRttMs(haversineKm(anchor.latitude, anchor.longitude, item.latitude, item.longitude))));
      const excess = floor - expected;
      const nearest = landmarks.find((item) => item.minMs === floor)?.city;
      details.excessLatencyMs = Math.round(excess);
      details.nearestLandmark = nearest;
      const explain = `The browser timezone (${fingerprint.timezone.name}) puts the client in ${anchor.region}, where some cloud region should answer within about ${Math.round(expected + 60)} ms. The closest landmark (${nearest}) takes ${Math.round(floor)} ms.`;
      if (excess > 200) add(evidence, "timezone-latency-high", "location", "Latency does not fit the browser's timezone", `${explain} Traffic is probably leaving through a distant relay first; a clock set to another country also does this.`, 2, "moderate", "browser-timezone-latency");
      else if (excess > 120) add(evidence, "timezone-latency", "location", "Latency only partly fits the browser's timezone", `${explain} A slow connection can add some of this.`, 1, "weak", "browser-timezone-latency");
    }
  }

  /* --- Path ---------------------------------------------------------------- */
  const sameFamily = (address: string) => (address.includes(":") === ip.includes(":"));
  // Browsers may report IPv6 candidates in brackets; compare bare addresses.
  const srflx = fingerprint.webrtcCandidates
    .filter((candidate) => candidate.candidateType === "srflx" && candidate.isPublic)
    .map((candidate) => ({ ...candidate, address: candidate.address.replace(/^\[|\]$/g, "").toLowerCase() }))
    .filter((candidate) => sameFamily(candidate.address));
  const httpAddress = ip.toLowerCase();
  if (server?.isPublicIp && srflx.some((candidate) => candidate.address !== httpAddress)) {
    const leaked = srflx.find((candidate) => candidate.address !== httpAddress)!.address;
    add(evidence, "webrtc-mismatch", "path", "WebRTC reveals a different public address", `STUN saw ${leaked}, but the web request came from ${ip}. Typical of browser-extension proxies and split-tunnel VPNs.`, 2.7, "strong", "webrtc-stun");
  } else if (server?.isPublicIp && srflx.length && srflx.every((candidate) => candidate.address === httpAddress)) {
    add(evidence, "webrtc-consistent", "path", "WebRTC path matches", "STUN and the web request see the same public address.", -0.3, "context", "webrtc-stun");
  }
  const forwarding = Object.keys(server?.proxyHeaders || {});
  if (forwarding.length) add(evidence, "proxy-headers", "path", "Forwarding proxy headers", `The request carried ${forwarding.join(", ")}, which forwarding proxies add.`, 1.5, "moderate", "http-headers");
  const appRtt = current.clientLatency?.minMs;
  if (appRtt && server?.tcpRttMs && appRtt - server.tcpRttMs > 50) {
    add(evidence, "rtt-layer-gap", "path", "Application vs TCP latency gap", `Browser round trip ${appRtt} ms exceeds the TCP handshake round trip ${server.tcpRttMs} ms by ${Math.round(appRtt - server.tcpRttMs)} ms (CalcuLatency threshold 50 ms).`, 2.2, "strong", "calculatency");
  }

  /* --- Device history (needs linked earlier scans) ----------------------- */
  const home = context.deviceHistory.filter((item) => isCleanScan(item, context.reputationOf));
  const homeNetworks = Array.from(new Set(home.map((item) => networkPrefix(ipOf(item))).filter((value): value is string => Boolean(value))));
  details.homeNetworks = homeNetworks;
  const currentNetwork = networkPrefix(ip);
  if (homeNetworks.length && currentNetwork) {
    if (!homeNetworks.includes(currentNetwork)) add(evidence, "home-departure", "history", "Device left its usual network", `This device was previously seen on ${homeNetworks.join(", ")}; now on ${currentNetwork}. Switching Wi-Fi or mobile data also does this, so it is strongest together with other signals.`, 1.4, "moderate", "device-history");
    else add(evidence, "home-network", "history", "Device is on its usual network", `${currentNetwork} is a network this device normally uses.`, -1, "context", "device-history");
  }
  const baseline = median(home.map((item) => item.clientLatency?.minMs).filter((value): value is number => typeof value === "number"));
  details.baselineRttMs = baseline;
  if (baseline !== null && appRtt) {
    const jump = appRtt - baseline;
    if (jump >= 50 && appRtt >= baseline * 1.15) add(evidence, "rtt-jump", "history", "Slower than this device usually is", `Round trip ${appRtt} ms vs this device's usual ${Math.round(baseline)} ms (+${Math.round(jump)} ms). A tunnel adds a detour; congestion can too.`, 1, "moderate", "device-history");
    else if (Math.abs(jump) <= 20) add(evidence, "rtt-usual", "history", "Latency as usual for this device", `Round trip within ${Math.round(Math.abs(jump))} ms of this device's usual ${Math.round(baseline)} ms.`, -0.3, "context", "device-history");
  }
  const floorNow = landmarks.length ? Math.min(...landmarks.map((item) => item.minMs!)) : null;
  const floorBaseline = median(home.map((item) => {
    const measured = (item.fingerprint.landmarks?.measurements || []).filter((landmark) => landmark.minMs !== null).map((landmark) => landmark.minMs!);
    return measured.length >= 3 ? Math.min(...measured) : null;
  }).filter((value): value is number => value !== null));
  if (floorNow !== null && floorBaseline !== null && floorNow - floorBaseline >= 60) {
    add(evidence, "landmark-floor-jump", "history", "Nearest landmark much farther than usual", `The closest cloud region now answers in ${Math.round(floorNow)} ms vs ${Math.round(floorBaseline)} ms usually for this device: traffic takes a detour.`, 1.2, "moderate", "device-history");
  }

  /* --- Population: exits shared by unrelated devices --------------------- */
  const exit = exitPrefix(ip);
  if (exit) {
    const byDevice = new Map<string, ResearchObservation[]>();
    for (const { observation, deviceId } of context.population) {
      if (deviceId === context.currentDeviceId || observation.observationId === current.observationId) continue;
      byDevice.set(deviceId, [...(byDevice.get(deviceId) || []), observation]);
    }
    let visitors = 0;
    for (const scans of byDevice.values()) {
      if (!scans.some((item) => exitPrefix(ipOf(item)) === exit)) continue;
      // Does this network count as the other device's home? (its most used clean network)
      const counts = new Map<string, number>();
      for (const item of scans) {
        const prefix = exitPrefix(ipOf(item));
        if (prefix && isCleanScan(item, context.reputationOf)) counts.set(prefix, (counts.get(prefix) || 0) + 1);
      }
      const theirHome = Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0];
      if (theirHome && theirHome !== exit) visitors += 1;
    }
    details.sharedExitDevices = visitors;
    if (visitors >= 2) add(evidence, "shared-exit", "network", "Shared by devices that live elsewhere", `${visitors} other devices have appeared from ${exit} while normally using other networks. That is how a VPN exit looks.`, 1.8, "moderate", "population-graph");
  }

  /* --- Integrity (weak) ----------------------------------------------------- */
  if (server?.clientConsistency?.status === "suspicious") add(evidence, "client-header-mismatch", "integrity", "Client claims are inconsistent", server.clientConsistency.notes.join(" "), 0.45, "weak", "server-browser-comparison");
  if (fingerprint.environmentChecks?.osMatchStatus === "suspicious") add(evidence, "os-environment-mismatch", "integrity", "OS environment inconsistency", fingerprint.environmentChecks.notes.join(" "), 0.25, "context", "browser-fingerprint");

  /* --- Combine ------------------------------------------------------------ */
  const subScores: Record<EvidenceGroup, number> = { network: 0, path: 0, location: 0, history: 0, integrity: 0 };
  for (const item of evidence) subScores[item.group] += item.logLikelihoodRatio;
  for (const group of Object.keys(subScores) as EvidenceGroup[]) {
    subScores[group] = Math.max(GROUP_CAPS[group].negative, Math.min(GROUP_CAPS[group].positive, subScores[group]));
  }
  const priorProbability = clamp(context.priorProbability ?? 0.05, 0.001, 0.5);
  const probability = sigmoid(logit(priorProbability) + Object.values(subScores).reduce((sum, value) => sum + value, 0));
  const parts = [
    Boolean(server?.trusted && server.isPublicIp),
    Boolean(lists?.checked.length),
    Boolean(geo),
    landmarks.length >= 3,
    fingerprint.webrtcStatus === "configured",
    homeNetworks.length > 0,
    Boolean(appRtt),
  ];
  const completeness = parts.filter(Boolean).length / parts.length;
  const strong = evidence.some((item) => item.strength === "strong" && item.logLikelihoodRatio > 0);
  // Several moderate signals that agree are enough to speak, even with few checks available.
  const positive = evidence.reduce((sum, item) => sum + Math.max(0, item.logLikelihoodRatio), 0);
  const abstain = !strong && completeness < 0.4 && positive < 2.5;
  const band = abstain ? "unknown" : probability >= 0.85 ? "high" : probability >= 0.35 ? "elevated" : "low";
  // A match on the Tor or Apple relay lists identifies the network outright.
  const kind: NonNullable<RiskAssessment["kind"]> = lists?.tor || anonymizer?.isTorExitNode ? "tor"
    : lists?.privateRelay ? "private-relay"
      : abstain ? "unknown"
        : band === "low" ? "none"
          : lists?.vpn || anonymizer?.isAnonymousVpn || evidence.some((item) => ["shared-exit", "home-departure", "excess-latency-high"].includes(item.id)) ? "vpn"
            : forwarding.length || anonymizer?.isPublicProxy || anonymizer?.isResidentialProxy ? "proxy"
              : lists?.datacenter ? "datacenter" : "vpn";
  return {
    score: Math.round(probability * 100),
    probability,
    priorProbability,
    calibrated: false,
    modelVersion: VPN_MODEL_VERSION,
    completeness,
    abstain,
    band,
    action: band === "high" ? "review" : band === "elevated" ? "step-up" : band === "unknown" ? "observe" : "allow",
    headline: headline(kind, band),
    subScores,
    evidence,
    kind,
    details,
  };
}

function headline(kind: NonNullable<RiskAssessment["kind"]>, band: RiskAssessment["band"]): string {
  if (kind === "private-relay") return "iCloud Private Relay in use";
  if (kind === "tor") return band === "high" ? "Strong signs of Tor" : "Tor exit node";
  if (band === "unknown") return "Not enough evidence to judge";
  if (band === "low") return "No VPN or proxy detected";
  const strength = band === "high" ? "Strong" : "Some";
  if (kind === "proxy") return `${strength} signs of a proxy`;
  if (kind === "datacenter") return `${strength} signs of a hosted or VPN network`;
  return `${strength} signs of a VPN`;
}

function formatOffset(minutes: number): string {
  const sign = minutes >= 0 ? "+" : "−";
  const absolute = Math.abs(minutes);
  return `${sign}${Math.floor(absolute / 60)}${absolute % 60 ? `:${String(absolute % 60).padStart(2, "0")}` : ""}`;
}

function logit(probability: number): number { return Math.log(probability / (1 - probability)); }
function sigmoid(value: number): number { return 1 / (1 + Math.exp(-value)); }
function clamp(value: number, minimum: number, maximum: number): number { return Math.min(maximum, Math.max(minimum, value)); }
