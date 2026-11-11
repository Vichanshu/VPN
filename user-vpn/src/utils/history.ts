import type { ResearchObservation } from "./fingerprint";

export interface HistoryFeatures {
  comparableObservations: number;
  distinctIps24h: number;
  distinctAsns30d: number;
  distinctCountries30d: number;
  networkTransitions24h: number;
  anonymizerTransitions30d: number;
  rapidCountryChanges: number;
  stableDeviceIpChanges: number;
}

export function deriveHistoryFeatures(current: ResearchObservation, previous: ResearchObservation[]): HistoryFeatures {
  const now = Date.parse(current.serverReceivedAt || current.fingerprint.collectedAt);
  const sameLabel = previous.filter((item) => item.deviceLabel === current.deviceLabel).sort((a, b) => observationTime(b) - observationTime(a));
  const within24h = sameLabel.filter((item) => now - observationTime(item) <= 24 * 60 * 60_000);
  const within30d = sameLabel.filter((item) => now - observationTime(item) <= 30 * 24 * 60 * 60_000);
  let rapidCountryChanges = 0;
  const timeline = [current, ...within30d].sort((a, b) => observationTime(a) - observationTime(b));
  for (let index = 1; index < timeline.length; index += 1) {
    const before = timeline[index - 1];
    const after = timeline[index];
    const elapsed = observationTime(after) - observationTime(before);
    if (country(before) && country(after) && country(before) !== country(after) && elapsed >= 0 && elapsed < 2 * 60 * 60_000) rapidCountryChanges += 1;
  }
  return {
    comparableObservations: sameLabel.length,
    distinctIps24h: distinct(within24h.map(ip)).size,
    distinctAsns30d: distinct(within30d.map(asn)).size,
    distinctCountries30d: distinct(within30d.map(country)).size,
    networkTransitions24h: countTransitions([current, ...within24h].sort((a, b) => observationTime(a) - observationTime(b)), ip),
    anonymizerTransitions30d: countTransitions([current, ...within30d].sort((a, b) => observationTime(a) - observationTime(b)), anonymizerClass),
    rapidCountryChanges,
    stableDeviceIpChanges: within30d.filter((item) => ip(item) && ip(item) !== ip(current)).length,
  };
}

function observationTime(observation: ResearchObservation): number { return Date.parse(observation.serverReceivedAt || observation.fingerprint.collectedAt) || 0; }
function ip(observation: ResearchObservation): string { return observation.serverNetwork?.ip || observation.effectivePublicIp || ""; }
function asn(observation: ResearchObservation): string { return observation.serverNetwork?.geoIp?.asn || observation.fingerprint.geoIp?.asn || ""; }
function country(observation: ResearchObservation): string { return observation.serverNetwork?.geoIp?.countryCode || observation.fingerprint.geoIp?.countryCode || ""; }
function anonymizerClass(observation: ResearchObservation): string {
  const data = observation.serverNetwork?.anonymizer;
  if (!data) return "unknown";
  if (data.isTorExitNode) return "tor";
  if (data.isAnonymousVpn) return "vpn";
  if (data.isResidentialProxy) return "residential-proxy";
  if (data.isPublicProxy) return "public-proxy";
  if (data.isHostingProvider) return "hosting";
  return "ordinary";
}
function distinct(values: string[]): Set<string> { return new Set(values.filter(Boolean)); }
function countTransitions(observations: ResearchObservation[], selector: (observation: ResearchObservation) => string): number {
  let transitions = 0;
  let previous = "";
  for (const observation of observations) {
    const current = selector(observation);
    if (previous && current && current !== previous) transitions += 1;
    if (current) previous = current;
  }
  return transitions;
}
