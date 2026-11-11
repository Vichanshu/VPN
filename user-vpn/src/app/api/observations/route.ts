import {
  CONSENT_VERSION,
  FINGERPRINT_SCHEMA_VERSION,
  type ObservationSubmission,
  type ResearchObservation,
} from "@/utils/fingerprint";
import type { ClientConsistency } from "@/utils/network";
import { recentObservations, saveObservation } from "@/utils/research-store";
import { cachedDeviceIds, cachedLinkageModel, deviceHistoryFor, linkObservations } from "@/utils/linkage-service";
import { assessVpn } from "@/utils/vpn-detection";
import { checkReputation, loadIpLists } from "@/utils/ip-lists";
import { lookupIpIntel, startAtlasCheck, withDevNetworkFallback } from "@/utils/ip-intel-service";
import { protectFingerprintComponents } from "@/utils/protected-fingerprint";
import { observeServerNetwork, verifyAndEnrichProbe, verifyScanChallenge } from "@/utils/server-network";

export const dynamic = "force-dynamic";

type RateGlobal = typeof globalThis & { __vpnResearchRate?: Map<string, { count: number; resetsAt: number }> };

/**
 * Visitor-side capture. Stores the same record the admin lab stores (including
 * the VPN assessment) but returns nothing about the verdict: visitors never
 * see the score, only the admin dashboard does.
 */
export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 300_000) return Response.json({ error: "Payload too large" }, { status: 413 });
    const payload: unknown = await request.json();
    if (!isSubmission(payload)) return Response.json({ error: "Invalid observation" }, { status: 400 });

    let serverNetwork = await observeServerNetwork(request);
    if (!verifyScanChallenge(payload.scanChallenge, serverNetwork, request.headers)) return Response.json({ error: "Expired or invalid scan challenge" }, { status: 400 });
    if (!allowObservation(serverNetwork)) return Response.json({ error: "Rate limit exceeded" }, { status: 429 });
    serverNetwork = await withDevNetworkFallback(request, serverNetwork, typeof payload.devPublicIp === "string" ? payload.devPublicIp : undefined);
    serverNetwork.clientConsistency = compareClientClaims(payload, serverNetwork.headers);
    const pathProbes = await Promise.all(payload.pathProbes.slice(0, 2).map((probe) => verifyAndEnrichProbe(probe)));
    const observation: ResearchObservation = {
      observationId: crypto.randomUUID(),
      deviceLabel: payload.deviceLabel.trim(),
      browserMode: payload.browserMode,
      vpnGroundTruth: "unknown",
      fingerprint: payload.fingerprint,
      serverSeenIp: serverNetwork.ip,
      effectivePublicIp: serverNetwork.isPublicIp ? serverNetwork.ip : "Unknown",
      serverReceivedAt: new Date().toISOString(),
      studyId: "public-visitors",
      consentVersion: CONSENT_VERSION,
      serverNetwork,
      pathProbes,
      deviceLocation: payload.deviceLocation,
      groundTruthDetails: { providerCode: "", protocol: "", exitCountry: "" },
      protectedComponents: protectFingerprintComponents(payload.fingerprint),
      clientLatency: payload.clientLatency,
    };

    const previousObservations = await recentObservations(1000);
    const linkageModel = cachedLinkageModel(previousObservations);
    const linked = previousObservations.map((previous) => ({ previous, linkage: linkObservations(observation, previous, linkageModel) }));
    const deviceIds = cachedDeviceIds(previousObservations, linkageModel);
    const device = deviceHistoryFor(linked, deviceIds);
    const lists = process.env.PUBLIC_IP_LISTS === "false" ? {} : await loadIpLists();
    const ipIntel = serverNetwork.isPublicIp ? await lookupIpIntel(serverNetwork.ip).catch(() => null) : null;
    observation.riskAssessment = assessVpn({
      current: observation,
      ipIntel,
      deviceHistory: device.history,
      currentDeviceId: device.deviceId,
      population: previousObservations.map((item) => ({ observation: item, deviceId: deviceIds.get(item.observationId) || item.observationId })),
      reputationOf: (ip) => checkReputation(lists, ip),
      priorProbability: configuredVpnPrior(),
    });
    if (ipIntel && ipIntel.atlas.status === "not-run" && observation.riskAssessment.probability >= 0.2 && observation.riskAssessment.probability < 0.85) {
      void startAtlasCheck(ipIntel.ip).catch(() => undefined);
    }

    await saveObservation(observation);
    return Response.json({ ok: true });
  } catch (error) {
    console.error("[visitor-capture]", error instanceof Error ? error.message : error);
    return Response.json({ error: "Could not save the measurement" }, { status: 503 });
  }
}

function isSubmission(value: unknown): value is ObservationSubmission {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ObservationSubmission>;
  const location = candidate.deviceLocation;
  const latency = candidate.clientLatency;
  const latencyValid = latency === null || latency === undefined || (
    Number.isFinite(latency.minMs) && latency.minMs >= 0 && latency.minMs <= 60_000 &&
    Number.isFinite(latency.medianMs) && latency.medianMs >= latency.minMs && latency.medianMs <= 60_000 &&
    Number.isInteger(latency.samples) && latency.samples > 0 && latency.samples <= 50
  );
  const locationValid = location === null || location === undefined || (
    Number.isFinite(location.latitude) && location.latitude >= -90 && location.latitude <= 90 &&
    Number.isFinite(location.longitude) && location.longitude >= -180 && location.longitude <= 180 &&
    Number.isFinite(location.accuracyMeters) && location.accuracyMeters >= 0 && location.accuracyMeters <= 100_000
  );
  return Boolean(
    candidate.consentAcknowledged === true &&
    typeof candidate.deviceLabel === "string" && candidate.deviceLabel.trim().length > 0 && candidate.deviceLabel.length <= 60 &&
    ["normal", "private", "unknown"].includes(candidate.browserMode || "") &&
    candidate.fingerprint?.schemaVersion === FINGERPRINT_SCHEMA_VERSION &&
    typeof candidate.fingerprint.userAgent === "string" && candidate.fingerprint.userAgent.length <= 1_000 &&
    Array.isArray(candidate.pathProbes) && candidate.pathProbes.length <= 2 &&
    locationValid && latencyValid && typeof candidate.scanChallenge === "string"
  );
}

function compareClientClaims(payload: ObservationSubmission, headers: Record<string, string>): ClientConsistency {
  const notes: string[] = [];
  const serverUserAgent = headers["user-agent"];
  if (serverUserAgent && serverUserAgent !== "Unknown" && serverUserAgent !== payload.fingerprint.userAgent) {
    notes.push("JavaScript User-Agent differs from the first-party HTTP User-Agent header.");
  }
  const platformHint = (headers["sec-ch-ua-platform"] || "").replaceAll('"', "").toLowerCase();
  const os = payload.fingerprint.osFamily.toLowerCase();
  if (platformHint && platformHint !== "unknown") {
    const compatible = (platformHint.includes("windows") && os.includes("windows")) ||
      (platformHint.includes("mac") && os.includes("mac")) ||
      (platformHint.includes("android") && os.includes("android")) ||
      (platformHint.includes("linux") && os.includes("linux")) ||
      (platformHint.includes("chrome") && os.includes("chrome"));
    if (!compatible) notes.push(`Client Hint platform ${platformHint} conflicts with parsed OS ${payload.fingerprint.osFamily}.`);
  }
  return { status: notes.length ? "suspicious" : serverUserAgent && serverUserAgent !== "Unknown" ? "consistent" : "indeterminate", notes };
}

function configuredVpnPrior(): number {
  const value = Number(process.env.VPN_RISK_PRIOR || "0.05");
  return Number.isFinite(value) && value > 0 && value < 1 ? value : 0.05;
}

function allowObservation(network: { trusted: boolean; isPublicIp: boolean; ip: string }): boolean {
  if (!network.trusted || !network.isPublicIp) return true;
  const shared = globalThis as RateGlobal;
  shared.__vpnResearchRate ??= new Map();
  const now = Date.now();
  const existing = shared.__vpnResearchRate.get(network.ip);
  if (!existing || existing.resetsAt <= now) {
    shared.__vpnResearchRate.set(network.ip, { count: 1, resetsAt: now + 10 * 60_000 });
    return true;
  }
  existing.count += 1;
  return existing.count <= 30;
}
