import type { FingerprintData, ResearchObservation } from "./fingerprint";
import type { LinkageResult } from "./linkage";

export interface SimilarityComponent {
  name: string;
  weight: number;
  similarity: number;
  available: boolean;
  current: string;
  previous: string;
}

export interface SimilarityResult {
  score: number;
  confidence: "high" | "medium" | "low" | "insufficient";
  verdict: "likely-same-device" | "similar-device" | "different-device" | "insufficient-evidence";
  comparableWeight: number;
  components: SimilarityComponent[];
}

export interface ObservationMatch {
  observationId: string;
  deviceLabel: string;
  browserFamily: string;
  browserMode: string;
  vpnGroundTruth: string;
  collectedAt: string;
  deviceSimilarity: SimilarityResult;
  sameBrowserSimilarity: SimilarityResult | null;
  ipChanged: boolean;
  previousIp: string;
  /** Probabilistic same-device linkage (schema 5 model). */
  linkage?: LinkageResult;
}

function available(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  return value !== null && value !== undefined && value !== "" && value !== "unknown" && value !== "Unknown" && value !== "unavailable";
}

function exact(a: unknown, b: unknown): number {
  return a === b ? 1 : 0;
}

function jaccard(a: string[], b: string[]): number {
  const first = new Set(a);
  const second = new Set(b);
  const union = new Set([...first, ...second]);
  if (union.size === 0) return 1;
  let intersection = 0;
  for (const item of first) if (second.has(item)) intersection += 1;
  return intersection / union.size;
}

function numericCloseness(a: number, b: number, tolerance: number): number {
  const distance = Math.abs(a - b);
  return Math.max(0, 1 - distance / tolerance);
}

function component(name: string, weight: number, a: unknown, b: unknown, similarity: number): SimilarityComponent {
  return {
    name,
    weight,
    similarity,
    available: available(a) && available(b),
    current: Array.isArray(a) ? a.join(", ") : String(a ?? "unavailable"),
    previous: Array.isArray(b) ? b.join(", ") : String(b ?? "unavailable"),
  };
}

function ndssTaskAgreement(current: FingerprintData, previous: FingerprintData, maskTaskIds: string[] = []): { current: string; previous: string; similarity: number } {
  const first = current.ndss2017;
  const second = previous.ndss2017;
  if (!first || !second) return { current: "unavailable", previous: "unavailable", similarity: 0 };
  const firstTasks = new Map(first.tasks.filter((task) => task.crossBrowserEligible && (task.status === "collected" || task.status === "capability-only")).map((task) => [task.id, task.hash]));
  const secondTasks = new Map(second.tasks.filter((task) => task.crossBrowserEligible && (task.status === "collected" || task.status === "capability-only")).map((task) => [task.id, task.hash]));
  const shared = Array.from(firstTasks.keys()).filter((id) => secondTasks.has(id) && (maskTaskIds.length === 0 || maskTaskIds.includes(id)));
  if (shared.length < 3) return { current: "unavailable", previous: "unavailable", similarity: 0 };
  const matches = shared.filter((id) => firstTasks.get(id) === secondTasks.get(id)).length;
  return {
    current: `${matches}/${shared.length} task hashes agree`,
    previous: `${matches}/${shared.length} task hashes agree`,
    similarity: matches / shared.length,
  };
}

function ndssWritingSystems(current: FingerprintData, previous: FingerprintData): { current: string[]; previous: string[]; similarity: number } {
  const first = current.ndss2017?.writingSystems.supported || [];
  const second = previous.ndss2017?.writingSystems.supported || [];
  return { current: first, previous: second, similarity: jaccard(first, second) };
}

function summarize(components: SimilarityComponent[]): SimilarityResult {
  const comparable = components.filter((item) => item.available);
  const comparableWeight = comparable.reduce((sum, item) => sum + item.weight, 0);
  if (comparableWeight < 35) {
    return { score: 0, confidence: "insufficient", verdict: "insufficient-evidence", comparableWeight, components };
  }

  const score = Math.round(
    100 * comparable.reduce((sum, item) => sum + item.weight * item.similarity, 0) / comparableWeight,
  );
  const confidence = comparableWeight >= 75 ? "high" : comparableWeight >= 55 ? "medium" : "low";
  const verdict = score >= 86
    ? "likely-same-device"
    : score >= 68
      ? "similar-device"
      : "different-device";
  return { score, confidence, verdict, comparableWeight, components };
}

export function compareDevices(current: FingerprintData, previous: FingerprintData, maskTaskIds: string[] = []): SimilarityResult {
  const taskAgreement = ndssTaskAgreement(current, previous, maskTaskIds);
  const writingSystems = ndssWritingSystems(current, previous);
  const components = [
    component("Operating system", 18, current.osFamily, previous.osFamily, exact(current.osFamily, previous.osFamily)),
    component("CPU architecture", 10, current.architecture, previous.architecture, exact(current.architecture, previous.architecture)),
    component("Bitness", 5, current.bitness, previous.bitness, exact(current.bitness, previous.bitness)),
    component("CPU core bucket", 10, current.hardwareBucket, previous.hardwareBucket, exact(current.hardwareBucket, previous.hardwareBucket)),
    component("Memory bucket", 8, current.memoryBucket, previous.memoryBucket, exact(current.memoryBucket, previous.memoryBucket)),
    component("Long screen edge", 8, current.screen.maxDimensionBucket, previous.screen.maxDimensionBucket, numericCloseness(current.screen.maxDimensionBucket, previous.screen.maxDimensionBucket, 300)),
    component("Short screen edge", 8, current.screen.minDimensionBucket, previous.screen.minDimensionBucket, numericCloseness(current.screen.minDimensionBucket, previous.screen.minDimensionBucket, 300)),
    component("Pixel ratio", 5, current.screen.pixelRatioBucket, previous.screen.pixelRatioBucket, numericCloseness(current.screen.pixelRatioBucket, previous.screen.pixelRatioBucket, 1)),
    component("Color depth", 5, current.colorDepth, previous.colorDepth, exact(current.colorDepth, previous.colorDepth)),
    component("Touch capability", 5, current.touchPoints > 0, previous.touchPoints > 0, exact(current.touchPoints > 0, previous.touchPoints > 0)),
    component("GPU family", 14, current.webgl.rendererFamily, previous.webgl.rendererFamily, exact(current.webgl.rendererFamily, previous.webgl.rendererFamily)),
    component("Color gamut", 3, current.display?.colorGamut, previous.display?.colorGamut, exact(current.display?.colorGamut, previous.display?.colorGamut)),
    component("Pointer class", 3, current.display?.pointer, previous.display?.pointer, exact(current.display?.pointer, previous.display?.pointer)),
    component("NDSS screen ratio", 4, current.ndss2017?.screen.widthHeightRatio, previous.ndss2017?.screen.widthHeightRatio, numericCloseness(current.ndss2017?.screen.widthHeightRatio || 0, previous.ndss2017?.screen.widthHeightRatio || 0, 0.02)),
    component("NDSS writing-system support", 7, writingSystems.current, writingSystems.previous, writingSystems.similarity),
    component("NDSS task agreement", 8, taskAgreement.current, taskAgreement.previous, taskAgreement.similarity),
    component("NDSS audio destination", 4, current.ndss2017?.audioDestination.sampleRate, previous.ndss2017?.audioDestination.sampleRate, exact(current.ndss2017?.audioDestination.sampleRate, previous.ndss2017?.audioDestination.sampleRate)),
  ];
  return summarize(components);
}

export function compareSameBrowser(current: FingerprintData, previous: FingerprintData): SimilarityResult {
  const components = [
    ...compareDevices(current, previous).components,
    component("Browser family", 15, current.browserFamily, previous.browserFamily, exact(current.browserFamily, previous.browserFamily)),
    component("Browser major", 4, current.browserMajor, previous.browserMajor, exact(current.browserMajor, previous.browserMajor)),
    component("Canvas rendering", 12, current.canvas.hash, previous.canvas.hash, exact(current.canvas.hash, previous.canvas.hash)),
    component("WebGL parameters", 10, current.webgl.parameterHash, previous.webgl.parameterHash, exact(current.webgl.parameterHash, previous.webgl.parameterHash)),
    component("WebGL render", 5, current.webgl.renderHash, previous.webgl.renderHash, exact(current.webgl.renderHash, previous.webgl.renderHash)),
    component("Font set", 8, current.fonts, previous.fonts, jaccard(current.fonts, previous.fonts)),
    component("Capability set", 6, current.capabilities, previous.capabilities, jaccard(current.capabilities, previous.capabilities)),
    component("Media codec set", 5, current.mediaCapabilities, previous.mediaCapabilities, jaccard(current.mediaCapabilities || [], previous.mediaCapabilities || [])),
    component("Audio rendering", 4, current.audio?.hash, previous.audio?.hash, exact(current.audio?.hash, previous.audio?.hash)),
  ];
  return summarize(components);
}

export function compareObservations(current: ResearchObservation, previous: ResearchObservation, maskTaskIds: string[] = []): ObservationMatch {
  const sameBrowser = current.fingerprint.browserFamily === previous.fingerprint.browserFamily;
  return {
    observationId: previous.observationId,
    deviceLabel: previous.deviceLabel,
    browserFamily: previous.fingerprint.browserFamily,
    browserMode: previous.browserMode,
    vpnGroundTruth: previous.vpnGroundTruth,
    collectedAt: previous.serverReceivedAt || previous.fingerprint.collectedAt,
    deviceSimilarity: compareDevices(current.fingerprint, previous.fingerprint, maskTaskIds),
    sameBrowserSimilarity: sameBrowser ? compareSameBrowser(current.fingerprint, previous.fingerprint) : null,
    ipChanged: Boolean(current.effectivePublicIp && previous.effectivePublicIp && current.effectivePublicIp !== previous.effectivePublicIp),
    previousIp: previous.effectivePublicIp,
  };
}
