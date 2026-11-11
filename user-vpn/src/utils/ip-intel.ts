import type { GeoCheck, AtlasSample } from "./ripe-atlas.ts";
import type { IpinfoResult } from "./ipinfo.ts";
import type { ReputationResult } from "./ip-lists.ts";
import type { RiskEvidence } from "./risk.ts";

/**
 * IP intelligence: one record per address that merges the local lists,
 * IPinfo and the RIPE Atlas geolocation check, plus the evidence they imply.
 * Pure data and scoring only (no network, no storage), so it can be tested and
 * shared by the standalone checker and by the scan model.
 */

export type AtlasState =
  | { status: "not-run"; message: string }
  | { status: "running"; measurementId: number; startedAt: string; probes: AtlasSample[]; message: string }
  | { status: "done"; measurementId: number; finishedAt: string; samples: AtlasSample[]; geo: GeoCheck }
  | { status: "failed"; message: string };

export type IpinfoState =
  | { status: "ok"; result: IpinfoResult }
  | { status: "unavailable"; message: string };

export interface IpIntel {
  ip: string;
  checkedAt: string;
  /** True when the IPinfo part was served from the 7-day cache. */
  fromCache: boolean;
  isPublic: boolean;
  lists: ReputationResult | null;
  ipinfo: IpinfoState;
  atlas: AtlasState;
}

export interface IpVerdict {
  probability: number;
  score: number;
  band: "low" | "elevated" | "high" | "unknown";
  kind: "vpn" | "tor" | "private-relay" | "proxy" | "datacenter" | "none" | "unknown";
  headline: string;
  evidence: RiskEvidence[];
}

const HOSTING_NAME = /(vps)|\b(hosting|datacenter|data center|cloud|colo(cation)?|amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|vultr|choopa|ovh|hetzner|leaseweb|contabo|cdn77|datapacket|zenlayer|quadranet|psychz|clouvider|oracle|alibaba|tencent)\b/i;
const VPN_NAME = /\b(vpn|nordvpn|expressvpn|mullvad|proton|surfshark|cyberghost|private internet access|ipvanish|m247|tefincom|packethub|windscribe|hide\.me|ivpn|tunnelbear|privatevpn)\b/i;

function add(evidence: RiskEvidence[], id: string, group: RiskEvidence["group"], label: string, detail: string, logLikelihoodRatio: number, strength: RiskEvidence["strength"], source: string) {
  evidence.push({ id, group, label, detail, logLikelihoodRatio, strength, source });
}

/**
 * Evidence from IPinfo and RIPE Atlas only. The scan model adds the list
 * evidence itself, so these never double count it.
 */
export function ipIntelEvidence(intel: Pick<IpIntel, "ipinfo" | "atlas">, lists?: Pick<ReputationResult, "datacenter"> | null): RiskEvidence[] {
  const evidence: RiskEvidence[] = [];
  if (intel.ipinfo.status === "ok") {
    const info = intel.ipinfo.result;
    const privacy = info.privacy;
    if (privacy) {
      if (privacy.tor) add(evidence, "ipinfo-tor", "network", "Tor exit (IPinfo)", "IPinfo's privacy detection marks the address as a Tor exit.", 5, "strong", "ipinfo");
      if (privacy.vpn) add(evidence, "ipinfo-vpn", "network", "VPN (IPinfo)", `IPinfo's privacy detection marks the address as a VPN${privacy.service ? ` (${privacy.service})` : ""}.`, 4, "strong", "ipinfo");
      if (privacy.proxy) add(evidence, "ipinfo-proxy", "network", "Proxy (IPinfo)", "IPinfo's privacy detection marks the address as a proxy.", 3, "strong", "ipinfo");
      if (privacy.relay) add(evidence, "ipinfo-relay", "network", "Privacy relay (IPinfo)", "IPinfo marks the address as an anonymising relay such as iCloud Private Relay.", 1.5, "moderate", "ipinfo");
      if (privacy.hosting && !lists?.datacenter) add(evidence, "ipinfo-hosting", "network", "Hosting network (IPinfo)", "IPinfo classifies the address as hosting or datacenter, not a home or mobile ISP.", 2.2, "moderate", "ipinfo");
      if (!privacy.vpn && !privacy.proxy && !privacy.tor && !privacy.relay && !privacy.hosting) add(evidence, "ipinfo-clean", "network", "No privacy flags (IPinfo)", "IPinfo's privacy detection found no VPN, proxy, Tor, relay or hosting flag.", -0.8, "context", "ipinfo");
    } else {
      const owner = [info.asnName, info.org].filter(Boolean).join(" ");
      if (owner && VPN_NAME.test(owner)) add(evidence, "asn-vpn-name", "network", "Network owner looks like a VPN provider", `The registered owner (${info.org}) is named like a VPN or VPN-hosting company. IPinfo's privacy module is not included in this plan, so this is a name-based hint only.`, 1.6, "moderate", "ipinfo-asn");
      else if (owner && HOSTING_NAME.test(owner) && !lists?.datacenter) add(evidence, "asn-hosting-name", "network", "Network owner looks like a hosting company", `The registered owner (${info.org}) is named like a cloud or hosting provider. This is a name-based hint only.`, 0.9, "weak", "ipinfo-asn");
    }
  }
  if (intel.atlas.status === "done") {
    const geo = intel.atlas.geo;
    if (geo.verdict === "inconsistent") {
      const worst = geo.violations[0];
      add(evidence, "atlas-geo-impossible", "location", "RIPE Atlas contradicts the IP location", `${geo.reason} (${geo.violations.length} of ${geo.usableProbes} probes disagree${worst ? `; worst: ${worst.country} probe ${worst.rttMs} ms vs ${worst.distanceKm} km claimed` : ""}).`, 3, "strong", "ripe-atlas");
    } else if (geo.verdict === "consistent") {
      add(evidence, "atlas-geo-consistent", "location", "RIPE Atlas confirms the IP location", geo.reason, -1, "context", "ripe-atlas");
    }
  }
  return evidence;
}

const LIST_EVIDENCE: Array<[keyof Pick<ReputationResult, "tor" | "vpn" | "datacenter" | "privateRelay">, string, string, number, RiskEvidence["strength"]]> = [
  ["tor", "Tor exit node", "The address is on the Tor Project's exit list.", 5, "strong"],
  ["vpn", "Known VPN network", "The address is inside a netblock attributed to a commercial VPN provider (X4BNet list).", 4, "strong"],
  ["datacenter", "Datacenter / hosting network", "The address belongs to a hosting or VPN provider's network, not a home or mobile ISP (X4BNet list).", 2.8, "strong"],
  ["privateRelay", "iCloud Private Relay", "The address is an Apple iCloud Private Relay egress, a privacy relay rather than a chosen VPN.", 1.5, "moderate"],
];

const GROUP_CAPS = { network: [-1.2, 5.5], location: [-1, 3] } as const;

function sigmoid(value: number): number { return 1 / (1 + Math.exp(-value)); }

/** Standalone verdict for the IP checker page (no browser or device history). */
export function scoreIpIntel(intel: IpIntel, priorProbability = 0.05): IpVerdict {
  const evidence: RiskEvidence[] = [];
  if (intel.lists) {
    for (const [key, label, detail, lr, strength] of LIST_EVIDENCE) {
      if (key === "datacenter" && intel.lists.vpn) continue;
      if (intel.lists[key]) add(evidence, `${key}-list`, "network", label, detail, lr, strength, "public-lists");
    }
  }
  evidence.push(...ipIntelEvidence(intel, intel.lists));

  const totals = { network: 0, location: 0 };
  for (const item of evidence) if (item.group === "network" || item.group === "location") totals[item.group] += item.logLikelihoodRatio;
  const capped = (group: keyof typeof totals) => Math.max(GROUP_CAPS[group][0], Math.min(GROUP_CAPS[group][1], totals[group]));
  const prior = Math.min(0.5, Math.max(0.001, priorProbability));
  const probability = sigmoid(Math.log(prior / (1 - prior)) + capped("network") + capped("location"));

  const anySource = Boolean(intel.lists?.checked.length) || intel.ipinfo.status === "ok";
  const strong = evidence.some((item) => item.strength === "strong" && item.logLikelihoodRatio > 0);
  const band: IpVerdict["band"] = !intel.isPublic || (!anySource && !strong) ? "unknown" : probability >= 0.85 ? "high" : probability >= 0.35 ? "elevated" : "low";
  const privacy = intel.ipinfo.status === "ok" ? intel.ipinfo.result.privacy : null;
  const kind: IpVerdict["kind"] = band === "unknown" ? "unknown"
    : intel.lists?.tor || privacy?.tor ? "tor"
      : intel.lists?.privateRelay || (privacy?.relay && !intel.lists?.vpn) ? "private-relay"
        : band === "low" ? "none"
          : intel.lists?.vpn || privacy?.vpn || evidence.some((item) => item.id === "asn-vpn-name" || item.id === "atlas-geo-impossible") ? "vpn"
            : privacy?.proxy ? "proxy"
              : intel.lists?.datacenter || privacy?.hosting ? "datacenter" : "vpn";
  const headline = band === "unknown" ? "Not enough evidence to judge"
    : kind === "tor" ? "Tor exit node"
      : kind === "private-relay" ? "iCloud Private Relay"
        : band === "low" ? "No VPN or proxy detected"
          : `${band === "high" ? "Strong" : "Some"} signs of ${kind === "proxy" ? "a proxy" : kind === "datacenter" ? "a hosted or VPN network" : "a VPN"}`;
  return { probability, score: Math.round(probability * 100), band, kind, headline, evidence };
}
