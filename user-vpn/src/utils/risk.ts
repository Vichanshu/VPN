import type { ClientLatency, FingerprintData } from "./fingerprint";
import type { HistoryFeatures } from "./history";
import type { DeviceLocation, NetworkPathProbe, ServerNetworkData } from "./network";
import type { ObservationMatch } from "./similarity";

export type EvidenceGroup = "network" | "path" | "location" | "history" | "integrity";

export interface RiskEvidence {
  id: string;
  group: EvidenceGroup;
  label: string;
  detail: string;
  logLikelihoodRatio: number;
  strength: "strong" | "moderate" | "weak" | "context";
  source: string;
}

export interface RiskAssessment {
  score: number;
  probability: number;
  priorProbability: number;
  calibrated: boolean;
  modelVersion: string;
  completeness: number;
  abstain: boolean;
  band: "low" | "elevated" | "high" | "unknown";
  action: "allow" | "observe" | "step-up" | "review";
  headline: string;
  subScores: Record<EvidenceGroup, number>;
  evidence: RiskEvidence[];
  /** Most likely kind of anonymizer, from the device-anchored VPN model. */
  kind?: "vpn" | "private-relay" | "tor" | "proxy" | "datacenter" | "none" | "unknown";
  /** Measurements behind the latency and device-history signals, for display. */
  details?: {
    excessLatencyMs?: number | null;
    nearestLandmark?: string | null;
    homeNetworks?: string[];
    baselineRttMs?: number | null;
    sharedExitDevices?: number;
  };
}

const GROUP_CAPS: Record<EvidenceGroup, number> = { network: 5, path: 4, location: 1.5, history: 2, integrity: 0.8 };

export function assessVpnRisk(input: {
  fingerprint: FingerprintData;
  server: ServerNetworkData;
  bestMatch: ObservationMatch | null;
  pathProbes: NetworkPathProbe[];
  deviceLocation: DeviceLocation | null;
  history: HistoryFeatures;
  clientLatency?: ClientLatency | null;
  priorProbability?: number;
}): RiskAssessment {
  const { fingerprint, server, bestMatch, pathProbes, deviceLocation, history } = input;
  const latency = input.clientLatency || null;
  const evidence: RiskEvidence[] = [];
  const anonymizer = server.anonymizer;

  if (anonymizer.isTorExitNode) add(evidence, "tor-exit", "network", "Tor exit address", "The canonical server-observed IP is on the maintained Tor exit list.", 5, "strong", anonymizer.source);
  if (anonymizer.isAnonymousVpn) add(evidence, "anonymous-vpn", "network", "Anonymous VPN network", providerDetail(anonymizer.providerName, anonymizer.confidence), confidenceAdjusted(3.8, anonymizer.confidence), "strong", anonymizer.source);
  if (anonymizer.isPublicProxy) add(evidence, "public-proxy", "network", "Public proxy network", providerDetail(anonymizer.providerName, anonymizer.confidence), confidenceAdjusted(3, anonymizer.confidence), "strong", anonymizer.source);
  if (anonymizer.isResidentialProxy) add(evidence, "residential-proxy", "network", "Residential proxy network", providerDetail(anonymizer.providerName, anonymizer.confidence), confidenceAdjusted(2.6, anonymizer.confidence), "strong", anonymizer.source);
  if (anonymizer.isHostingProvider) {
    const authoritative = anonymizer.source === "maxmind";
    add(evidence, "hosting-network", "network", "Hosting or datacenter network", `${server.geoIp?.org || "The observed network"} is classified as hosting infrastructure. Cloud workloads and corporate gateways can also match.`, authoritative ? 1.35 : 0.65, authoritative ? "moderate" : "weak", anonymizer.source);
  }

  const publicCandidate = fingerprint.webrtcCandidates.find((candidate) => candidate.candidateType === "srflx" && candidate.isPublic && candidate.address !== server.ip);
  if (server.isPublicIp && publicCandidate) add(evidence, "webrtc-path-discrepancy", "path", "WebRTC public path differs", `STUN observed ${publicCandidate.address}, while HTTPS ingress observed ${server.ip}. This is compatible with split routing or a proxy bypass.`, 2.7, "strong", "webrtc-stun");

  const trustedProbes = pathProbes.filter((probe) => probe.trusted && probe.network);
  const ipv4 = trustedProbes.find((probe) => probe.kind === "ipv4")?.network;
  const ipv6 = trustedProbes.find((probe) => probe.kind === "ipv6")?.network;
  if (ipv4?.geoIp && ipv6?.geoIp) {
    const classMismatch = anonymizerClass(ipv4) !== anonymizerClass(ipv6) && anonymizerClass(ipv4) !== "unknown" && anonymizerClass(ipv6) !== "unknown";
    const asnMismatch = known(ipv4.geoIp.asn) && known(ipv6.geoIp.asn) && ipv4.geoIp.asn !== ipv6.geoIp.asn;
    const countryMismatch = known(ipv4.geoIp.countryCode) && known(ipv6.geoIp.countryCode) && ipv4.geoIp.countryCode !== ipv6.geoIp.countryCode;
    if (classMismatch) add(evidence, "dual-stack-class-mismatch", "path", "IPv4/IPv6 network-class mismatch", `IPv4 is ${anonymizerClass(ipv4)} while IPv6 is ${anonymizerClass(ipv6)}.`, 2.5, "strong", "signed-first-party-probes");
    else if (asnMismatch && countryMismatch) add(evidence, "dual-stack-route-mismatch", "path", "IPv4/IPv6 paths diverge", `IPv4 and IPv6 resolved to different ASNs and countries (${ipv4.geoIp.asn}/${ipv4.geoIp.countryCode} vs ${ipv6.geoIp.asn}/${ipv6.geoIp.countryCode}).`, 1.65, "moderate", "signed-first-party-probes");
  }

  // CalcuLatency (Ramesh et al., USENIX Security 2024): with a proxy the
  // server's TCP handshake terminates at the exit node while the HTTPS round
  // trip continues to the client. They report a 50 ms gap separating 89.1% of
  // VPN measurements at a 0.95% false-positive rate. Our application RTT uses
  // fetch rather than WebSocket pings, so the likelihood ratio is discounted.
  if (latency && server.tcpRttMs) {
    const gap = latency.minMs - server.tcpRttMs;
    if (gap > 50) add(evidence, "latency-layer-gap", "path", "Application vs TCP latency gap", `Browser round trip ${latency.minMs} ms exceeds the ingress TCP round trip ${server.tcpRttMs} ms by ${Math.round(gap)} ms, compatible with a relay between client and server.`, 2.2, "strong", "calculatency-rtt");
  }

  // Speed-of-light feasibility (SNITCH, NDSS-style geolocation checks): a
  // round trip shorter than light in fibre needs for the GeoIP distance means
  // the egress is not where GeoIP places it, as with VPN "virtual locations".
  const serverLatitude = Number(process.env.SERVER_LATITUDE);
  const serverLongitude = Number(process.env.SERVER_LONGITUDE);
  const fastestRtt = server.tcpRttMs ?? latency?.minMs ?? null;
  if (fastestRtt !== null && Number.isFinite(serverLatitude) && Number.isFinite(serverLongitude) && process.env.SERVER_LATITUDE && server.geoIp?.latitude != null && server.geoIp.longitude != null) {
    const distanceKm = Math.max(0, haversineKm(serverLatitude, serverLongitude, server.geoIp.latitude, server.geoIp.longitude) - (server.geoIp.accuracyRadiusKm || 50));
    const minimumRtt = distanceKm / 100; // ~200 km/ms in fibre, both directions
    if (minimumRtt > 15 && fastestRtt < minimumRtt * 0.8) add(evidence, "geo-latency-infeasible", "location", "GeoIP location is physically infeasible", `A ${Math.round(fastestRtt)} ms round trip cannot reach ${server.geoIp.city || server.geoIp.country} (needs at least ~${Math.round(minimumRtt)} ms). The egress is closer than GeoIP claims.`, 1.4, "moderate", "latency-geolocation");
  }

  const geoOffset = server.geoIp?.utcOffsetMinutes;
  if (geoOffset !== null && geoOffset !== undefined) {
    const difference = Math.abs(geoOffset - fingerprint.timezone.offsetMinutes);
    if (difference >= 120) add(evidence, "timezone-mismatch", "location", "Timezone offset mismatch", `Browser and IP-location UTC offsets differ by ${Math.round(difference / 60)} hour(s). Travel and manual timezone settings are common benign causes.`, 0.35, "weak", "browser-and-geoip");
  }

  if (deviceLocation && server.geoIp?.latitude !== null && server.geoIp?.latitude !== undefined && server.geoIp.longitude !== null) {
    const distanceKm = haversineKm(deviceLocation.latitude, deviceLocation.longitude, server.geoIp.latitude, server.geoIp.longitude);
    const uncertaintyKm = deviceLocation.accuracyMeters / 1_000 + (server.geoIp.accuracyRadiusKm || 100);
    if (distanceKm > Math.max(250, uncertaintyKm * 2)) add(evidence, "consented-location-mismatch", "location", "Device and IP locations materially differ", `Fresh permissioned location is about ${Math.round(distanceKm)} km from IP geolocation after accounting for reported uncertainty. Location can be emulated and GeoIP can be wrong.`, 1.5, "moderate", "permissioned-geolocation");
  }

  if (history.rapidCountryChanges > 0) add(evidence, "rapid-country-change", "history", "Rapid country transition", `${history.rapidCountryChanges} country transition(s) occurred within two hours for this controlled device label.`, 1.2, "moderate", "server-history");
  if (history.distinctAsns30d >= 4 && history.networkTransitions24h >= 2) add(evidence, "network-velocity", "history", "High network velocity", `${history.distinctAsns30d} ASNs were observed in 30 days with ${history.networkTransitions24h} IP transition(s) in 24 hours.`, 0.75, "weak", "server-history");
  if (history.anonymizerTransitions30d >= 2) add(evidence, "anonymizer-alternation", "history", "Repeated anonymizer transitions", `The device label switched network classifications ${history.anonymizerTransitions30d} times in 30 days.`, 0.9, "moderate", "server-history");
  const linkedDevice = bestMatch?.linkage ? bestMatch.linkage.posterior >= 0.9 && bestMatch.linkage.verdict !== "insufficient-evidence" : (bestMatch?.deviceSimilarity.score ?? 0) >= 86;
  if (bestMatch?.ipChanged && linkedDevice) add(evidence, "stable-device-network-change", "history", "Stable device, changed network", `${bestMatch.linkage ? `${Math.round(bestMatch.linkage.posterior * 100)}% same-device posterior` : `${bestMatch.deviceSimilarity.score}% device similarity`} was observed while the canonical IP changed. Mobility and shared hardware remain benign explanations.`, 0.45, "context", "fingerprint-history");

  if (server.clientConsistency?.status === "suspicious") add(evidence, "client-header-mismatch", "integrity", "Client claims are inconsistent", server.clientConsistency.notes.join(" "), 0.45, "weak", "server-browser-comparison");
  if (fingerprint.environmentChecks?.osMatchStatus === "suspicious") add(evidence, "os-environment-mismatch", "integrity", "OS environment inconsistency", fingerprint.environmentChecks.notes.join(" "), 0.25, "context", "browser-fingerprint");
  if (fingerprint.webgl.rendererFamily === "software-renderer") add(evidence, "software-renderer", "integrity", "Software WebGL renderer", "Software rendering can indicate a VM, remote browser, headless session, or an ordinary compatibility fallback. It is not direct VPN evidence.", 0.15, "context", "webgl");

  const priorProbability = clamp(input.priorProbability ?? configuredPrior(), 0.001, 0.5);
  const subScores = groupedLikelihoods(evidence);
  const logOdds = logit(priorProbability) + Object.values(subScores).reduce((sum, value) => sum + value, 0);
  const probability = sigmoid(logOdds);
  const completeness = evidenceCompleteness(server, fingerprint, pathProbes, history, deviceLocation);
  const strongEvidence = evidence.some((item) => item.strength === "strong");
  const abstain = !strongEvidence && completeness < 0.45;
  const band = abstain ? "unknown" : probability >= 0.85 ? "high" : probability >= 0.35 ? "elevated" : "low";
  const action = band === "high" ? "review" : band === "elevated" ? "step-up" : band === "unknown" ? "observe" : "allow";
  return {
    score: Math.round(probability * 100), probability, priorProbability, calibrated: false,
    modelVersion: "bayes-lr-baseline-3.1.0", completeness, abstain, band, action,
    headline: abstain ? "Insufficient authoritative evidence" : band === "high" ? "Strong anonymizer-compatible evidence" : band === "elevated" ? "Step-up verification recommended" : "No strong anonymizer evidence observed",
    subScores, evidence,
  };
}

function add(evidence: RiskEvidence[], id: string, group: EvidenceGroup, label: string, detail: string, logLikelihoodRatio: number, strength: RiskEvidence["strength"], source: string) { evidence.push({ id, group, label, detail, logLikelihoodRatio, strength, source }); }
function groupedLikelihoods(evidence: RiskEvidence[]): Record<EvidenceGroup, number> {
  const result: Record<EvidenceGroup, number> = { network: 0, path: 0, location: 0, history: 0, integrity: 0 };
  for (const item of evidence) result[item.group] = Math.min(GROUP_CAPS[item.group], result[item.group] + item.logLikelihoodRatio);
  return result;
}
function evidenceCompleteness(server: ServerNetworkData, fingerprint: FingerprintData, probes: NetworkPathProbe[], history: HistoryFeatures, location: DeviceLocation | null): number {
  const parts = [server.trusted && server.isPublicIp, server.anonymizer.source !== "unavailable", Boolean(server.geoIp), fingerprint.webrtcStatus === "configured", probes.some((probe) => probe.trusted), history.comparableObservations > 0, Boolean(location), Boolean(server.headers["user-agent"]), Boolean(server.tcpRttMs)];
  return parts.filter(Boolean).length / parts.length;
}
function providerDetail(provider: string, confidence: number | null): string { return `${known(provider) ? provider : "The observed network"} is classified as an anonymizer${confidence === null ? "" : ` with provider confidence ${confidence}/99`}.`; }
function confidenceAdjusted(base: number, confidence: number | null): number { return confidence === null ? base : base * clamp(confidence / 80, 0.45, 1.2); }
function anonymizerClass(network: ServerNetworkData): string {
  const item = network.anonymizer;
  if (item.isTorExitNode) return "tor";
  if (item.isAnonymousVpn) return "vpn";
  if (item.isResidentialProxy) return "residential-proxy";
  if (item.isPublicProxy) return "public-proxy";
  if (item.isHostingProvider) return "hosting";
  return item.source === "unavailable" ? "unknown" : "ordinary";
}
function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const radians = (degrees: number) => degrees * Math.PI / 180;
  const deltaLat = radians(lat2 - lat1);
  const deltaLon = radians(lon2 - lon1);
  const a = Math.sin(deltaLat / 2) ** 2 + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  return 6_371 * 2 * Math.asin(Math.sqrt(a));
}
function configuredPrior(): number { const value = Number(process.env.VPN_RISK_PRIOR || "0.05"); return Number.isFinite(value) ? value : 0.05; }
function logit(probability: number): number { return Math.log(probability / (1 - probability)); }
function sigmoid(value: number): number { return 1 / (1 + Math.exp(-value)); }
function clamp(value: number, minimum: number, maximum: number): number { return Math.min(maximum, Math.max(minimum, value)); }
function known(value: string): boolean { return Boolean(value && value !== "Unknown" && value !== "unavailable"); }
