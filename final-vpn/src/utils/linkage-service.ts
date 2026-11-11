import "server-only";

import type { ResearchObservation } from "./fingerprint";
import { groupSameDevice, linkObservations, scoreAllPairs, trainLinkageModel, type LinkageModel, type LinkageResult } from "./linkage";

type LinkageGlobal = typeof globalThis & {
  __linkageModel?: { key: string; model: LinkageModel; expiresAt: number };
  __deviceIds?: { key: string; ids: Map<string, string>; expiresAt: number };
};

function cacheKey(observations: ResearchObservation[]): string {
  return `${observations.length}:${observations[0]?.observationId || "empty"}:${process.env.LINKAGE_PRIOR || ""}`;
}

/**
 * Training compares every labelled pair (bounded), so the model is cached
 * until the dataset changes or five minutes pass.
 */
/**
 * Public visitors have no real device name (each browser gets its own random
 * label), so training would count the same laptop in two browsers as two
 * different devices. They are scored against the model but never train it.
 */
const UNLABELLED_STUDY = "public-visitors";

export function cachedLinkageModel(allObservations: ResearchObservation[]): LinkageModel {
  const observations = allObservations.filter((item) => item.studyId !== UNLABELLED_STUDY);
  const shared = globalThis as LinkageGlobal;
  const key = cacheKey(observations);
  const cached = shared.__linkageModel;
  if (cached && cached.key === key && cached.expiresAt > Date.now()) return cached.model;
  const configuredPrior = Number(process.env.LINKAGE_PRIOR);
  const model = trainLinkageModel(observations, {
    maxObservations: 400,
    maxDifferentPairs: 30_000,
    prior: Number.isFinite(configuredPrior) && configuredPrior > 0 && configuredPrior < 1 ? configuredPrior : undefined,
  });
  shared.__linkageModel = { key, model, expiresAt: Date.now() + 5 * 60_000 };
  return model;
}

export interface LinkedHistory {
  linkedObservations: number;
  firstSeen: string | null;
  browsers: string[];
  publicIps: string[];
  asns: string[];
  countries: string[];
  labels: string[];
}

/** Summarises where the same physical device appears to have been seen before. */
export function linkedHistory(matches: Array<{ previous: ResearchObservation; linkage: LinkageResult }>, threshold = 0.9): LinkedHistory {
  const linked = matches.filter((item) => item.linkage.posterior >= threshold && item.linkage.verdict !== "insufficient-evidence").map((item) => item.previous);
  const times = linked.map((item) => item.serverReceivedAt || item.fingerprint.collectedAt).sort();
  const distinct = (values: Array<string | undefined>) => Array.from(new Set(values.filter((value): value is string => Boolean(value && value !== "Unknown"))));
  return {
    linkedObservations: linked.length,
    firstSeen: times[0] || null,
    browsers: distinct(linked.map((item) => `${item.fingerprint.browserFamily}${item.browserMode === "private" ? " (private)" : ""}`)),
    publicIps: distinct(linked.map((item) => item.serverNetwork?.ip || item.effectivePublicIp)),
    asns: distinct(linked.map((item) => item.serverNetwork?.geoIp?.asn)),
    countries: distinct(linked.map((item) => item.serverNetwork?.geoIp?.countryCode)),
    labels: distinct(linked.map((item) => item.deviceLabel)),
  };
}

export { linkObservations };

/**
 * Inferred physical-device id for every stored scan (same-device sets at
 * 85%, plus mutual closest matches). Used to recognise VPN exits that
 * several unrelated devices pass through. Cached with the model.
 */
export function cachedDeviceIds(observations: ResearchObservation[], model: LinkageModel): Map<string, string> {
  const shared = globalThis as LinkageGlobal;
  const key = cacheKey(observations);
  if (shared.__deviceIds && shared.__deviceIds.key === key && shared.__deviceIds.expiresAt > Date.now()) return shared.__deviceIds.ids;
  const ids = new Map<string, string>();
  for (const set of groupSameDevice(scoreAllPairs(observations, model), 0.85, 3, true)) {
    for (const id of set.observationIds) ids.set(id, set.clusterId);
  }
  shared.__deviceIds = { key, ids, expiresAt: Date.now() + 5 * 60_000 };
  return ids;
}

/**
 * Earlier scans of the visiting device: every scan the model is at least 85%
 * sure about, plus the inferred device of the closest match when that match
 * is more likely than not.
 */
export function deviceHistoryFor(linked: Array<{ previous: ResearchObservation; linkage: LinkageResult }>, deviceIds: Map<string, string>): { history: ResearchObservation[]; deviceId?: string } {
  const usable = linked.filter((item) => item.linkage.verdict !== "insufficient-evidence");
  const best = [...usable].sort((a, b) => b.linkage.posterior - a.linkage.posterior)[0];
  const deviceId = best && best.linkage.posterior > 0.5 ? deviceIds.get(best.previous.observationId) : undefined;
  const history = usable
    .filter((item) => item.linkage.posterior >= 0.85 || (deviceId !== undefined && deviceIds.get(item.previous.observationId) === deviceId))
    .map((item) => item.previous);
  return { history, deviceId };
}
