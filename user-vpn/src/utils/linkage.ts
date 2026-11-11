import type { FingerprintData, ResearchObservation } from "./fingerprint";

/**
 * Probabilistic device linkage: "were these two observations produced by the
 * same physical device?"
 *
 * Design, following the 2018-2026 literature (FP-STALKER, Andriamilanto et
 * al., ThresholdFP 2025, DrawnApart 2022, Cao et al. 2017):
 *
 * 1. Each feature is compared with a type-appropriate similarity and the
 *    result is put in one of four agreement bins (exact / close / partial /
 *    different), so evolving values degrade gracefully instead of breaking an
 *    exact hash.
 * 2. Every bin has a likelihood under "same device" and "different device".
 *    Expert priors (stability, collision rate) are blended with counts from
 *    the labelled study data (Dirichlet smoothing), so the model is usable
 *    from the first capture and becomes data-driven as labels accumulate.
 * 3. Features have a scope: device features are compared across any browsers,
 *    engine features only within one rendering engine, browser features only
 *    within one browser family. Randomized (farbled) features are excluded
 *    rather than counted as a mismatch.
 * 4. Log-likelihood ratios are summed per family and capped, which limits
 *    double counting of correlated features (fonts, emoji and voices all
 *    follow the OS image).
 * 5. The posterior uses an open-world prior (1 / number of known devices) and
 *    optional Platt calibration with a prior-shift correction.
 */

export const LINKAGE_MODEL_VERSION = "linkage-nb-2026.10";

export type LinkScope = "device" | "engine" | "browser";
export type ComparisonContext = "same-browser" | "same-engine" | "cross-browser";
export type LinkFamily =
  | "platform" | "model" | "defaults" | "hardware" | "display" | "gpu" | "gpu-timing" | "os-assets"
  | "locale" | "audio-hw" | "engine-render" | "browser-config" | "network";

type Value = string | number | boolean | string[] | number[];
type OsStratum = "iOS/iPadOS" | "Android" | "macOS" | "Windows" | "Linux" | "ChromeOS";
const OS_STRATA = new Set<string>(["iOS/iPadOS", "Android", "macOS", "Windows", "Linux", "ChromeOS"]);
const MOBILE_OS = new Set<string>(["iOS/iPadOS", "Android"]);
const CONTEXTS: ComparisonContext[] = ["same-browser", "same-engine", "cross-browser"];
const BIN_EDGES = [0.97, 0.85, 0.5];
const BIN_NAMES = ["exact", "close", "partial", "different"] as const;
const PRIOR_STRENGTH = 12;
/** Positive matches weaker than this are pooled into the capped "defaults" group. */
const WEAK_MATCH_LLR = 0.75;
const LLR_LIMIT = 6;

export const FAMILY_CAPS: Record<LinkFamily, { positive: number; negative: number }> = {
  platform: { positive: 2.5, negative: -6 },
  // Its own group so a different phone model is never capped away by OS evidence.
  model: { positive: 3.5, negative: -9 },
  defaults: { positive: 1.5, negative: 0 },
  hardware: { positive: 2.5, negative: -5 },
  display: { positive: 3, negative: -4.5 },
  gpu: { positive: 3.5, negative: -5 },
  "gpu-timing": { positive: 2, negative: -1.5 },
  "os-assets": { positive: 4, negative: -3.5 },
  locale: { positive: 1.2, negative: -2 },
  "audio-hw": { positive: 1.2, negative: -2 },
  "engine-render": { positive: 5, negative: -4 },
  "browser-config": { positive: 1.5, negative: -2.5 },
  network: { positive: 0.7, negative: -0.3 },
};

export const FAMILY_LABELS: Record<LinkFamily, string> = {
  platform: "OS & platform",
  model: "Device model",
  defaults: "Common settings (pooled)",
  hardware: "CPU, memory, input",
  display: "Display",
  gpu: "GPU identity",
  "gpu-timing": "GPU timing (DrawnApart/WebGPU)",
  "os-assets": "Fonts, emoji, voices",
  locale: "Locale & timezone",
  "audio-hw": "Audio hardware",
  "engine-render": "Engine rendering",
  "browser-config": "Browser configuration",
  network: "Network context",
};

interface FeatureSpec {
  id: string;
  label: string;
  family: LinkFamily;
  scope: LinkScope;
  /** Exact-equality features only ever produce the exact or different bin. */
  binary: boolean;
  /** P(exact | same device) within one browser, one engine, and across engines. */
  stability: [number, number, number];
  /** P(exact | different devices). */
  collision: number;
  /**
   * P(exact | different devices that run the same OS). Some platforms are
   * near-uniform: every iPhone on one iOS release shares fonts, emoji,
   * canvas/WebGL output and GPU name, so a match there proves little.
   * "*" applies to any shared OS.
   */
  collisionByOs?: Partial<Record<OsStratum | "*", number>>;
  value: (observation: ResearchObservation) => Value | null;
  compare?: (a: Value, b: Value) => number | null;
  /**
   * The value is chosen by the operating system (fonts, voices, driver
   * strings, display scaling, audio mode), so it is only compared when both
   * scans run the same OS. A dual-boot machine then keeps its hardware
   * evidence instead of losing every OS-level signal at once.
   */
  osDependent?: boolean;
  /**
   * Fixed by the hardware model and its firmware (screen, GPU, rendering,
   * system fonts). When both scans report the same phone model these match
   * for every unit of that model, so they are not counted again on top of
   * the model match; personal settings and timing decide instead.
   */
  modelDetermined?: boolean;
  /** Comparator used instead of `compare` when either scan is Brave. */
  braveCompare?: (a: Value, b: Value) => number | null;
  /** True when a randomizing defence makes this observation's value unreliable. */
  protectedBy?: (fingerprint: FingerprintData) => boolean;
}

/* ----------------------------------------------------------------------- */
/* Comparators                                                              */
/* ----------------------------------------------------------------------- */

function exact(a: Value, b: Value): number {
  return stringify(a) === stringify(b) ? 1 : 0;
}

function jaccard(a: Value, b: Value): number | null {
  const first = new Set(a as string[]);
  const second = new Set(b as string[]);
  const union = new Set([...first, ...second]);
  if (!union.size) return null;
  let shared = 0;
  for (const item of first) if (second.has(item)) shared += 1;
  return shared / union.size;
}

function closeness(tolerance: number) {
  return (a: Value, b: Value): number => Math.max(0, 1 - Math.abs(Number(a) - Number(b)) / tolerance);
}

/** Fraction of positions that agree within a tolerance (rounded metrics). */
function vectorAgreement(tolerance: number) {
  return (a: Value, b: Value): number | null => {
    const first = a as number[];
    const second = b as number[];
    if (!first.length || first.length !== second.length) return null;
    return first.filter((value, index) => Math.abs(value - second[index]) <= tolerance).length / first.length;
  };
}

/**
 * Share of the smaller set found in the larger one. Brave hides a random
 * subset of fonts per site, so its list is a subset of the true one.
 */
function containment(a: Value, b: Value): number | null {
  const first = new Set(a as string[]);
  const second = new Set(b as string[]);
  const smaller = first.size <= second.size ? first : second;
  const larger = smaller === first ? second : first;
  if (!smaller.size) return null;
  let shared = 0;
  for (const item of smaller) if (larger.has(item)) shared += 1;
  return shared / smaller.size;
}

/** Pearson correlation for timing profiles; uninformative flat profiles abstain. */
export function profileCorrelation(a: Value, b: Value): number | null {
  const first = a as number[];
  const second = b as number[];
  if (first.length < 8 || first.length !== second.length) return null;
  const meanA = first.reduce((sum, value) => sum + value, 0) / first.length;
  const meanB = second.reduce((sum, value) => sum + value, 0) / second.length;
  let covariance = 0, varianceA = 0, varianceB = 0;
  for (let index = 0; index < first.length; index += 1) {
    covariance += (first[index] - meanA) * (second[index] - meanB);
    varianceA += (first[index] - meanA) ** 2;
    varianceB += (second[index] - meanB) ** 2;
  }
  const spreadA = Math.sqrt(varianceA / first.length);
  const spreadB = Math.sqrt(varianceB / second.length);
  if (spreadA < 0.01 || spreadB < 0.01) return null;
  return Math.max(0, covariance / Math.sqrt(varianceA * varianceB));
}

function stringify(value: Value): string {
  return Array.isArray(value) ? value.join("|") : String(value);
}

function known(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return false;
  if (typeof value === "string") return !["unknown", "Unknown", "unavailable", "unsupported", "disabled", "failed", "n/a"].includes(value);
  if (typeof value === "number") return Number.isFinite(value) && value >= 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function orNull<T extends Value>(value: T | null | undefined): T | null {
  return known(value) ? (value as T) : null;
}

/* ----------------------------------------------------------------------- */
/* Feature catalogue                                                        */
/* ----------------------------------------------------------------------- */

const fp = (observation: ResearchObservation) => observation.fingerprint;
const modern = (observation: ResearchObservation) => observation.fingerprint.modern;

export const FEATURES: FeatureSpec[] = [
  // Platform
  { id: "os", label: "Operating system", family: "platform", scope: "device", binary: true, stability: [0.995, 0.99, 0.99], collision: 0.35, collisionByOs: { "*": 0.95 },
    value: (o) => orNull(fp(o).osFamily) },
  { id: "os-version", label: "OS version (client hints)", family: "platform", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.93, 0.9, 0.9], collision: 0.12, collisionByOs: { "iOS/iPadOS": 0.4, Android: 0.3, macOS: 0.35, Windows: 0.3 },
    value: (o) => { const version = modern(o)?.clientHints?.platformVersion; return version ? version.split(".").slice(0, 2).map(Number) : null; },
    compare: (a, b) => { const [x, y] = [a as number[], b as number[]]; return x[0] !== y[0] ? 0 : x[1] === y[1] ? 1 : 0.9; } },
  { id: "architecture", label: "CPU architecture / bitness", family: "platform", scope: "device", binary: true, stability: [0.99, 0.98, 0.98], collision: 0.5, collisionByOs: { "*": 0.85 },
    value: (o) => known(fp(o).architecture) ? `${fp(o).architecture}/${fp(o).bitness}` : null },
  { id: "device-model", label: "Device model (hints or user agent)", family: "model", scope: "device", binary: true, stability: [0.998, 0.995, 0.995], collision: 0.05,
    value: (o) => deviceModel(fp(o)) },

  // Hardware
  { id: "cpu-cores", label: "Logical CPU cores", family: "hardware", scope: "device", modelDetermined: true, binary: true, protectedBy: isBrave, stability: [0.99, 0.95, 0.85], collision: 0.25, collisionByOs: { "iOS/iPadOS": 0.6, Android: 0.4, macOS: 0.35 },
    value: (o) => orNull(fp(o).hardwareConcurrency ?? null) },
  { id: "memory", label: "Device memory bucket", family: "hardware", scope: "device", binary: true, protectedBy: isBrave, stability: [0.99, 0.97, 0.95], collision: 0.45, collisionByOs: { Android: 0.55, "*": 0.5 },
    // Chromium caps the reported value at 8 GB; some forks report 16 or 32.
    value: (o) => { const memory = fp(o).deviceMemory; return memory ? Math.min(memory, 8) : null; } },
  { id: "refresh-rate", label: "Display refresh rate", family: "hardware", scope: "device", osDependent: true, binary: true, stability: [0.9, 0.85, 0.82], collision: 0.6, collisionByOs: { "iOS/iPadOS": 0.8, Android: 0.7, macOS: 0.75 },
    // Phones switch adaptively between 48/60/90/120 Hz, so only desktops count.
    value: (o) => isMobile(fp(o)) ? null : orNull(modern(o)?.refreshRate.hz ?? null) },
  { id: "pointer-polling", label: "Pointer polling rate", family: "hardware", scope: "device", osDependent: true, binary: false, stability: [0.8, 0.75, 0.7], collision: 0.35,
    // Off-standard estimates jitter (159 vs 161 Hz is one mouse), but two
    // different standard rates (120 vs 125 Hz) are two different devices.
    value: (o) => orNull(modern(o)?.pointer.pollingHz ?? null),
    compare: (a, b) => {
      const [x, y] = [Number(a), Number(b)];
      if (x === y) return 1;
      if (STANDARD_POLLING_RATES.has(x) && STANDARD_POLLING_RATES.has(y)) return 0;
      const gap = Math.abs(x - y) / Math.max(x, y);
      return gap <= 0.06 ? 1 : gap <= 0.15 ? 0.9 : 0;
    } },

  // Display
  { id: "screen", label: "Physical screen resolution", family: "display", scope: "device", protectedBy: isBraveDesktop, modelDetermined: true, binary: false, stability: [0.95, 0.94, 0.92], collision: 0.12, collisionByOs: { "iOS/iPadOS": 0.3, Android: 0.15, macOS: 0.3 },
    // Physical pixels (CSS size × device pixel ratio), so OS display scaling
    // and browser zoom cancel out: 1536×864 at 125% is the same 1920×1080 panel.
    value: (o) => {
      const { width, height, pixelRatioBucket } = fp(o).screen;
      const ratio = pixelRatioBucket > 0 ? pixelRatioBucket : 1;
      return [Math.round(Math.max(width, height) * ratio), Math.round(Math.min(width, height) * ratio), isMobile(fp(o)) ? 1 : 0];
    },
    // A phone or tablet has one fixed panel, so any real difference means a
    // different model. Desktops change with external monitors.
    compare: (a, b) => {
      const [x, y] = [a as number[], b as number[]];
      // The stored pixel ratio is rounded to 0.25, so allow 2% slack.
      if (Math.abs(x[0] - y[0]) <= x[0] * 0.02 && Math.abs(x[1] - y[1]) <= x[1] * 0.02) return 1;
      if (x[2] === 1 && y[2] === 1) return 0;
      return Math.max(0, 1 - (Math.abs(x[0] - y[0]) + Math.abs(x[1] - y[1])) / 1200);
    } },
  { id: "pixel-ratio", label: "Device pixel ratio", family: "display", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.9, 0.85, 0.82], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.8, Android: 0.4, macOS: 0.85 },
    value: (o) => fp(o).screen.pixelRatioBucket, compare: closeness(1) },
  { id: "screen-insets", label: "Taskbar / dock insets", family: "display", scope: "device", protectedBy: isBraveDesktop, osDependent: true, binary: true, stability: [0.9, 0.88, 0.85], collision: 0.25, collisionByOs: { "iOS/iPadOS": 0.85, Android: 0.3, macOS: 0.4 },
    // On phones these reflect the browser's own toolbars, not the device.
    value: (o) => { const insets = modern(o)?.screenInsets; return insets && !isMobile(fp(o)) ? [insets.horizontal, insets.vertical, insets.left, insets.top] : null; } },
  { id: "display-profile", label: "Colour gamut, pointer, touch", family: "display", scope: "device", modelDetermined: true, binary: true, stability: [0.97, 0.93, 0.9], collision: 0.3, collisionByOs: { "iOS/iPadOS": 0.85, Android: 0.5, macOS: 0.7 },
    // Colour depth and dynamic range are left out: they depend on the engine
    // (Chromium reports 30-bit, Safari 24; older forks lack the HDR query).
    value: (o) => fp(o).display ? [fp(o).display!.colorGamut, fp(o).display!.pointer, String(fp(o).touchPoints > 0)] : null },

  // GPU identity
  { id: "gpu-family", label: "GPU vendor family", family: "gpu", scope: "device", modelDetermined: true, binary: true, protectedBy: isBrave, stability: [0.99, 0.95, 0.9], collision: 0.3, collisionByOs: { "iOS/iPadOS": 0.98, macOS: 0.9, Android: 0.5 },
    value: (o) => orNull(fp(o).webgl.rendererFamily) },
  { id: "gpu-renderer", label: "GPU model tokens", family: "gpu", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.97, 0.85, 0.7], collision: 0.08, collisionByOs: { "iOS/iPadOS": 0.95, macOS: 0.4, Android: 0.3 },
    value: (o) => orNull(modern(o)?.gpu.rendererTokens ?? null), compare: jaccard,
    protectedBy: (f) => Boolean(f.modern?.protections.brave || f.modern?.gpu.masked) },
  { id: "webgpu-adapter", label: "WebGPU vendor / architecture", family: "gpu", scope: "device", modelDetermined: true, binary: true, stability: [0.97, 0.9, 0.8], collision: 0.2, collisionByOs: { "iOS/iPadOS": 0.95, macOS: 0.8, Android: 0.4 },
    value: (o) => { const gpu = modern(o)?.webgpu; return gpu?.status === "collected" && (gpu.vendor || gpu.architecture) ? `${gpu.vendor}/${gpu.architecture}` : null; },
    protectedBy: (f) => Boolean(f.modern?.protections.brave) },
  { id: "webgpu-subgroups", label: "WebGPU subgroup sizes", family: "gpu", scope: "device", protectedBy: isBrave, modelDetermined: true, osDependent: true, binary: true, stability: [0.98, 0.9, 0.85], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.95, macOS: 0.9 },
    value: (o) => { const gpu = modern(o)?.webgpu; return gpu?.subgroupMinSize ? [gpu.subgroupMinSize, gpu.subgroupMaxSize ?? 0] : null; } },

  // GPU timing (non-deterministic, weak per comparison)
  { id: "gpu-timing", label: "DrawnApart EU timing profile", family: "gpu-timing", scope: "device", binary: false, stability: [0.35, 0.3, 0.25], collision: 0.06,
    value: (o) => { const timing = modern(o)?.gpuTiming; return timing?.status === "collected" ? timing.profile : null; }, compare: profileCorrelation },
  { id: "webgpu-scheduling", label: "WebGPU atomic scheduling profile", family: "gpu-timing", scope: "device", binary: false, stability: [0.35, 0.3, 0.25], collision: 0.06,
    value: (o) => { const scheduling = modern(o)?.webgpu.scheduling; return scheduling?.status === "collected" ? scheduling.profile : null; }, compare: profileCorrelation },

  // OS assets
  { id: "fonts", label: "Installed font inventory", family: "os-assets", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.85, 0.7, 0.6], collision: 0.08, collisionByOs: { "iOS/iPadOS": 0.85, Android: 0.5, macOS: 0.3 },
    value: (o) => modern(o)?.fonts.detected.length ? modern(o)!.fonts.detected : null, compare: jaccard, braveCompare: containment },
  { id: "legacy-fonts", label: "Core font probe (schema 4)", family: "os-assets", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.9, 0.75, 0.65], collision: 0.25, collisionByOs: { "iOS/iPadOS": 0.95, Android: 0.7, macOS: 0.6 },
    value: (o) => orNull(fp(o).fonts), compare: jaccard, braveCompare: containment },
  { id: "emoji-version", label: "Emoji font release", family: "os-assets", scope: "device", modelDetermined: true, osDependent: true, binary: true, stability: [0.97, 0.92, 0.85], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.8, Android: 0.6, macOS: 0.8 },
    value: (o) => orNull(modern(o)?.emoji.maxVersion ?? null) },
  { id: "emoji-metrics", label: "Emoji glyph metrics", family: "os-assets", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.95, 0.8, 0.55], collision: 0.25, collisionByOs: { "iOS/iPadOS": 0.9, Android: 0.6, macOS: 0.9 },
    value: (o) => orNull(modern(o)?.emoji.widths ?? null), compare: vectorAgreement(0.5) },
  { id: "writing-systems", label: "Writing-system glyph support", family: "os-assets", scope: "device", modelDetermined: true, osDependent: true, binary: false, stability: [0.95, 0.85, 0.75], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.95, Android: 0.8, macOS: 0.95 },
    value: (o) => orNull(fp(o).ndss2017?.writingSystems.supported ?? null), compare: jaccard },
    // Brave injects fake voice names. On same-model phones the default lists are
  // identical and one or two names are the only personal signal, so a Brave
  // list cannot be compared at all.
{ id: "local-voices", label: "Local speech voices", family: "os-assets", scope: "device", osDependent: true, binary: false, stability: [0.95, 0.75, 0.6], collision: 0.2, collisionByOs: { "iOS/iPadOS": 0.5, Android: 0.4, macOS: 0.4 },
    value: (o) => orNull(modern(o)?.voices.local ?? null), compare: jaccard, protectedBy: isBrave },
  { id: "generic-fonts", label: "Default generic font metrics", family: "os-assets", scope: "engine", modelDetermined: true, osDependent: true, binary: false, stability: [0.95, 0.75, 0.5], collision: 0.3, collisionByOs: { "iOS/iPadOS": 0.8, Android: 0.5, macOS: 0.7 },
    value: (o) => { const widths = modern(o)?.systemStyle.genericWidths; return widths && Object.keys(widths).length ? Object.keys(widths).sort().map((key) => widths[key]) : null; },
    compare: vectorAgreement(0.5) },

  // Locale
  { id: "timezone", label: "Timezone", family: "locale", scope: "device", binary: true, stability: [0.97, 0.96, 0.95], collision: 0.3,
    value: (o) => known(fp(o).timezone.name) ? canonicalTimeZone(fp(o).timezone.name) : null },
  { id: "language", label: "Primary language", family: "locale", scope: "device", binary: true, stability: [0.97, 0.85, 0.75], collision: 0.4,
    value: (o) => orNull(fp(o).languages[0]?.toLowerCase().split("-")[0] ?? null) },
  { id: "intl-format", label: "Locale formatting (calendar, hour cycle)", family: "locale", scope: "device", osDependent: true, binary: true, stability: [0.97, 0.85, 0.75], collision: 0.4,
    value: (o) => { const intl = modern(o)?.intl; return intl ? [intl.locale, intl.calendar, intl.numberingSystem, intl.hourCycle] : null; } },

  // Audio hardware
  { id: "audio-destination", label: "Audio output sample rate / channels", family: "audio-hw", scope: "device", modelDetermined: true, osDependent: true, binary: true, stability: [0.97, 0.85, 0.8], collision: 0.5, collisionByOs: { "iOS/iPadOS": 0.9, macOS: 0.7 },
    value: (o) => { const destination = fp(o).ndss2017?.audioDestination; return destination?.sampleRate ? [destination.sampleRate, destination.maxChannelCount ?? -1] : null; } },
  { id: "media-devices", label: "Media device counts", family: "audio-hw", scope: "browser", binary: true, stability: [0.9, 0, 0], collision: 0.5, collisionByOs: { "iOS/iPadOS": 0.8, Android: 0.6 },
    // Browsers decide how many devices to reveal before permission (Chrome
    // shows one per kind), so counts are only compared within one browser.
    value: (o) => { const devices = modern(o)?.mediaDevices; return devices ? [devices.audioinput, devices.videoinput, devices.audiooutput] : null; } },

  // Engine rendering (same engine only)
  { id: "canvas-hash", label: "Canvas rendering hash", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.92, 0.7, 0], collision: 0.03, collisionByOs: { "iOS/iPadOS": 0.5, macOS: 0.3, Android: 0.2 },
    value: (o) => orNull(fp(o).canvas.hash), protectedBy: (f) => Boolean(f.modern?.protections.canvasNoise) || f.canvas.repeatable === false },
  { id: "canvas-grid", label: "Noise-tolerant canvas grid", family: "engine-render", scope: "engine", modelDetermined: true, binary: false, stability: [0.95, 0.75, 0], collision: 0.15, collisionByOs: { "iOS/iPadOS": 0.7, macOS: 0.5, Android: 0.4 },
    value: (o) => orNull(modern(o)?.canvasRobust.grid ?? null), compare: vectorAgreement(1.5) },
  { id: "webgl-params", label: "WebGL parameters", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.95, 0.8, 0], collision: 0.08, collisionByOs: { "iOS/iPadOS": 0.8, macOS: 0.4, Android: 0.3 },
    value: (o) => orNull(fp(o).webgl.parameterHash), protectedBy: (f) => Boolean(f.modern?.protections.brave) },
  { id: "webgl-render", label: "WebGL clear-colour render", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.97, 0.9, 0], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.95, macOS: 0.9 },
    value: (o) => orNull(fp(o).webgl.renderHash ?? null) },
  { id: "audio-hash", label: "Audio DSP hash", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.92, 0.6, 0], collision: 0.05, collisionByOs: { "iOS/iPadOS": 0.7, macOS: 0.5, Android: 0.3 },
    value: (o) => fp(o).audio?.status === "collected" ? fp(o).audio!.hash : null, protectedBy: (f) => Boolean(f.modern?.protections.audioNoise) || isBrave(f) },
  { id: "audio-summary", label: "Audio DSP summary (rounded)", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.95, 0.6, 0], collision: 0.08, collisionByOs: { "iOS/iPadOS": 0.7, macOS: 0.5, Android: 0.3 },
    // Brave shifts audio by a per-session amount, so repeated renders within one
    // scan still agree and the noise check cannot see it.
    value: (o) => orNull(modern(o)?.audioRobust.summary ?? null), protectedBy: (f) => Boolean(f.modern?.protections.audioNoise) || isBrave(f) },
  { id: "math", label: "JS math library", family: "engine-render", scope: "engine", modelDetermined: true, binary: true, stability: [0.99, 0.9, 0], collision: 0.6, collisionByOs: { "iOS/iPadOS": 0.8, macOS: 0.8, Android: 0.8 },
    value: (o) => orNull(modern(o)?.math.hash ?? null) },
  { id: "ndss-tasks", label: "NDSS 2017 task hashes", family: "engine-render", scope: "engine", protectedBy: isBrave, modelDetermined: true, binary: false, stability: [0.9, 0.6, 0], collision: 0.1, collisionByOs: { "iOS/iPadOS": 0.6, macOS: 0.4, Android: 0.3 },
    value: (o) => { const tasks = fp(o).ndss2017?.tasks.filter((task) => task.status === "collected"); return tasks?.length ? tasks.map((task) => `${task.id}:${task.hash.slice(0, 16)}`) : null; },
    compare: jaccard },

  // Browser configuration (same browser family only)
  { id: "browser-version", label: "Browser major version", family: "browser-config", scope: "browser", binary: false, stability: [0.85, 0, 0], collision: 0.25,
    value: (o) => Number(fp(o).browserMajor) || null, compare: (a, b) => Number(a) === Number(b) ? 1 : Math.abs(Number(a) - Number(b)) <= 2 ? 0.9 : 0.3 },
  { id: "capabilities", label: "API capability set", family: "browser-config", scope: "browser", binary: false, stability: [0.95, 0, 0], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.9 },
    value: (o) => orNull(fp(o).capabilities), compare: jaccard },
  { id: "codecs", label: "Media codec set", family: "browser-config", scope: "browser", binary: false, stability: [0.97, 0, 0], collision: 0.5, collisionByOs: { "iOS/iPadOS": 0.9 },
    value: (o) => orNull(fp(o).mediaCapabilities ?? null), compare: jaccard },
  { id: "system-colors", label: "CSS system colours", family: "browser-config", scope: "browser", binary: true, stability: [0.9, 0, 0], collision: 0.4, collisionByOs: { "iOS/iPadOS": 0.9 },
    value: (o) => { const colors = modern(o)?.systemStyle.colors; return colors && Object.keys(colors).length ? Object.keys(colors).sort().map((key) => colors[key]) : null; } },

  // Network context (weak: households, offices, and labs share egress)
  { id: "ip-prefix", label: "Same egress network prefix", family: "network", scope: "device", binary: true, stability: [0.5, 0.5, 0.5], collision: 0.25,
    value: (o) => ipPrefix(o.serverNetwork?.ip || o.effectivePublicIp) },
];

const FEATURE_BY_ID = new Map(FEATURES.map((spec) => [spec.id, spec]));
const DEVICE_MODEL_INDEX = FEATURES.findIndex((spec) => spec.id === "device-model");
/** Must match the classes the collector snaps estimates to. */
const STANDARD_POLLING_RATES = new Set([60, 90, 120, 125, 250, 500, 1000, 2000, 4000, 8000]);
const HARDWARE_FAMILIES = new Set<LinkFamily>(["hardware", "display", "gpu", "platform"]);

/**
 * Engines disagree on IANA aliases: Chromium reports "Asia/Calcutta" where
 * Firefox and Safari report "Asia/Kolkata" for the same device and setting.
 */
const TIME_ZONE_ALIASES: Record<string, string> = {
  "Asia/Calcutta": "Asia/Kolkata", "Asia/Saigon": "Asia/Ho_Chi_Minh", "Asia/Katmandu": "Asia/Kathmandu", "Asia/Rangoon": "Asia/Yangon",
  "Asia/Dacca": "Asia/Dhaka", "Asia/Thimbu": "Asia/Thimphu", "Asia/Ulan_Bator": "Asia/Ulaanbaatar", "Asia/Macao": "Asia/Macau",
  "Europe/Kiev": "Europe/Kyiv", "America/Buenos_Aires": "America/Argentina/Buenos_Aires", "America/Indianapolis": "America/Indiana/Indianapolis",
  "America/Godthab": "America/Nuuk", "Atlantic/Faeroe": "Atlantic/Faroe", "Pacific/Ponape": "Pacific/Pohnpei", "Pacific/Truk": "Pacific/Chuuk",
  "Africa/Asmera": "Africa/Asmara", "US/Eastern": "America/New_York", "US/Central": "America/Chicago", "US/Mountain": "America/Denver",
  "US/Pacific": "America/Los_Angeles", "Etc/UTC": "UTC", "Etc/GMT": "UTC", "GMT": "UTC", "Etc/Universal": "UTC",
};

export function canonicalTimeZone(name: string): string {
  return TIME_ZONE_ALIASES[name] || name;
}

function ipPrefix(ip: string | undefined): string | null {
  if (!ip || ip === "Unknown") return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").slice(0, 3).join(".");
  if (ip.includes(":")) return ip.toLowerCase().split(":").slice(0, 3).join(":");
  return null;
}

/**
 * Phone model from client hints (Chrome) or, failing that, from the user
 * agent: built-in browsers such as HeyTap and Vivo still send
 * "Android 16; RMX3867 Build/…". Chrome's reduced agent says only "K".
 */
function deviceModel(fingerprint: FingerprintData): string | null {
  const hinted = fingerprint.modern?.clientHints?.model?.trim();
  if (hinted) return hinted.toUpperCase();
  const match = (fingerprint.userAgent || "").match(/Android [\d.]+; (?:[a-z]{2}-[a-z]{2}; )?([^;)]+?)(?: Build\/[^;)]*)?\)/);
  const model = match?.[1].trim();
  return model && model !== "K" ? model.toUpperCase() : null;
}

/* ----------------------------------------------------------------------- */
/* Context                                                                  */
/* ----------------------------------------------------------------------- */

function isMobile(fingerprint: FingerprintData): boolean {
  return MOBILE_OS.has(fingerprint.osFamily);
}

/** Brave presents a Chrome user agent; its own API flag gives it away. */
function isBrave(fingerprint: FingerprintData): boolean {
  return fingerprint.browserFamily === "Brave" || Boolean(fingerprint.modern?.protections.brave);
}

/**
 * Chromium forks that present a Chrome user agent but add their own token.
 * Phone makers' built-in browsers (HeyTap on Realme/OPPO/OnePlus, Vivo,
 * Samsung, Mi) often run a much older Chromium than Chrome itself.
 */
const UA_FORKS: Array<[RegExp, string]> = [
  [/HeyTapBrowser\//, "HeyTap"], [/VivoBrowser\//, "Vivo Browser"], [/SamsungBrowser\//, "Samsung Internet"],
  [/MiuiBrowser\/|XiaoMi\//, "Mi Browser"], [/UCBrowser\//, "UC Browser"], [/YaBrowser\//, "Yandex"],
  [/OPR\/|OPT\//, "Opera"], [/Edg(?:A|iOS)?\//, "Edge"], [/Vivaldi\//, "Vivaldi"], [/DuckDuckGo\//, "DuckDuckGo"],
  [/; wv\)/, "Android WebView"],
];

/** Brave on desktop also reports a randomized screen size and insets. */
function isBraveDesktop(fingerprint: FingerprintData): boolean {
  return isBrave(fingerprint) && !isMobile(fingerprint);
}

export function browserOf(fingerprint: FingerprintData): string {
  if (isBrave(fingerprint)) return "Brave";
  for (const [pattern, name] of UA_FORKS) if (pattern.test(fingerprint.userAgent || "")) return name;
  return fingerprint.browserFamily;
}

export function engineOf(fingerprint: FingerprintData): string {
  const browser = browserOf(fingerprint);
  if (fingerprint.osFamily === "iOS/iPadOS") return "webkit";
  if (browser === "Firefox") return "gecko";
  if (browser === "Safari") return "webkit";
  return "blink";
}

/** Major version of the rendering engine, when the user agent reveals it. */
function engineVersion(fingerprint: FingerprintData): number | null {
  const agent = fingerprint.userAgent || "";
  const engine = engineOf(fingerprint);
  const match = engine === "gecko" ? agent.match(/Firefox\/(\d+)/)
    : engine === "blink" ? agent.match(/Chrome\/(\d+)/)
      : agent.match(/(?:iPhone OS|CPU OS|Version\/)(\d+)/);
  return match ? Number(match[1]) : null;
}

/**
 * Two browsers only count as "the same engine" when they share an engine at
 * a similar version: Chromium 115 (bundled in many phone browsers) and
 * Chromium 155 render canvas, WebGL and math differently.
 */
export function comparisonContext(a: FingerprintData, b: FingerprintData): ComparisonContext {
  if (browserOf(a) === browserOf(b)) return "same-browser";
  if (engineOf(a) !== engineOf(b)) return "cross-browser";
  const [first, second] = [engineVersion(a), engineVersion(b)];
  return first !== null && second !== null && Math.abs(first - second) > 6 ? "cross-browser" : "same-engine";
}

/** Pairs on the same OS are scored against that OS's own collision rates. */
function stratumOf(a: FingerprintData, b: FingerprintData): OsStratum | null {
  return a.osFamily === b.osFamily && OS_STRATA.has(a.osFamily) ? (a.osFamily as OsStratum) : null;
}

function eligible(spec: FeatureSpec, context: ComparisonContext): boolean {
  if (spec.scope === "device") return true;
  if (spec.scope === "engine") return context !== "cross-browser";
  return context === "same-browser";
}

function contextIndex(context: ComparisonContext): number {
  return CONTEXTS.indexOf(context);
}

/* ----------------------------------------------------------------------- */
/* Model                                                                    */
/* ----------------------------------------------------------------------- */

interface FeatureCounts {
  /** same[contextIndex][bin] */
  same: number[][];
  diff: number[];
  /** Different-device pairs that share an OS, per OS. */
  diffByOs: Record<string, number[]>;
}

export interface LinkageModel {
  version: string;
  trainedAt: string;
  observations: number;
  deviceLabels: number;
  samePairs: Record<ComparisonContext, number>;
  differentPairs: number;
  counts: Record<string, FeatureCounts>;
  prior: number;
  calibration: { slope: number; intercept: number; trainingPositiveRate: number; pairs: number } | null;
}

export interface LinkageFeature {
  id: string;
  label: string;
  family: LinkFamily;
  status: "used" | "unavailable" | "protected" | "out-of-scope" | "by-model";
  similarity: number | null;
  bin: (typeof BIN_NAMES)[number] | null;
  logLikelihoodRatio: number;
  current: string;
  previous: string;
}

export interface LinkageResult {
  modelVersion: string;
  context: ComparisonContext;
  posterior: number;
  calibrated: boolean;
  logLikelihoodRatio: number;
  verdict: "same-device" | "probably-same" | "inconclusive" | "different-device" | "insufficient-evidence";
  confidence: "high" | "medium" | "low";
  comparableFamilies: number;
  usedFeatures: number;
  families: Array<{ family: LinkFamily; label: string; raw: number; capped: number }>;
  features: LinkageFeature[];
  notes: string[];
}

function emptyCounts(): FeatureCounts {
  return { same: CONTEXTS.map(() => [0, 0, 0, 0]), diff: [0, 0, 0, 0], diffByOs: {} };
}

function addDiff(counts: FeatureCounts, stratum: string | null, bin: number, delta: number): void {
  counts.diff[bin] += delta;
  if (stratum) (counts.diffByOs[stratum] ??= [0, 0, 0, 0])[bin] += delta;
}

function binOf(similarity: number): number {
  return similarity >= BIN_EDGES[0] ? 0 : similarity >= BIN_EDGES[1] ? 1 : similarity >= BIN_EDGES[2] ? 2 : 3;
}

function priorSame(spec: FeatureSpec, context: ComparisonContext): number[] {
  const stability = Math.min(0.995, Math.max(0.05, spec.stability[contextIndex(context)]));
  if (spec.binary) return [stability, 0, 0, 1 - stability];
  const rest = 1 - stability;
  return [stability, rest * 0.45, rest * 0.33, rest * 0.22];
}

function priorDiff(spec: FeatureSpec, stratum: OsStratum | null): number[] {
  const configured = stratum ? spec.collisionByOs?.[stratum] ?? spec.collisionByOs?.["*"] : undefined;
  const collision = Math.min(0.95, Math.max(0.005, configured ?? spec.collision));
  if (spec.binary) return [collision, 0, 0, 1 - collision];
  const rest = 1 - collision;
  return [collision, rest * 0.12, rest * 0.28, rest * 0.6];
}

function featureLlr(spec: FeatureSpec, context: ComparisonContext, stratum: OsStratum | null, bin: number, counts: FeatureCounts): number {
  const same = counts.same[contextIndex(context)];
  // Same-OS pairs use only same-OS impostors: cross-OS pairs would make
  // matches on uniform platforms look far rarer than they are.
  const diff = stratum ? counts.diffByOs[stratum] || [0, 0, 0, 0] : counts.diff;
  const sameTotal = same.reduce((sum, value) => sum + value, 0);
  const diffTotal = diff.reduce((sum, value) => sum + value, 0);
  const sameProbability = (same[bin] + PRIOR_STRENGTH * priorSame(spec, context)[bin]) / (sameTotal + PRIOR_STRENGTH);
  const diffProbability = (diff[bin] + PRIOR_STRENGTH * priorDiff(spec, stratum)[bin]) / (diffTotal + PRIOR_STRENGTH);
  const llr = Math.log(Math.max(sameProbability, 1e-4) / Math.max(diffProbability, 1e-4));
  return Math.max(-LLR_LIMIT, Math.min(LLR_LIMIT, llr));
}

/** Per-observation extracted values, computed once and reused for every pair. */
interface Extracted {
  observation: ResearchObservation;
  values: Array<Value | null>;
  protectedFlags: boolean[];
}

function extract(observation: ResearchObservation): Extracted {
  return {
    observation,
    values: FEATURES.map((spec) => {
      try {
        return spec.value(observation);
      } catch {
        return null;
      }
    }),
    protectedFlags: FEATURES.map((spec) => Boolean(spec.protectedBy?.(observation.fingerprint))),
  };
}

interface PairBins {
  context: ComparisonContext;
  stratum: OsStratum | null;
  /** Both scans are phones or tablets. */
  mobile: boolean;
  /** Hardware-fixed signals are grouped and capped like a model match (phones, or different OSes). */
  hardwareOnly: boolean;
  /** -1 unavailable, -2 protected, -3 out of scope, -4 settled by the model name, otherwise the bin index. */
  bins: Int8Array;
  similarities: Float32Array;
}

function comparePair(a: Extracted, b: Extracted): PairBins {
  const context = comparisonContext(a.observation.fingerprint, b.observation.fingerprint);
  const sameOs = a.observation.fingerprint.osFamily === b.observation.fingerprint.osFamily;
  // When both scans name their phone model, that name settles the hardware
  // question (same or different) and the signals it fixes are not recounted.
  const bothModels = a.values[DEVICE_MODEL_INDEX] !== null && b.values[DEVICE_MODEL_INDEX] !== null;
  const mobile = isMobile(a.observation.fingerprint) && isMobile(b.observation.fingerprint);
  // Across operating systems only hardware is comparable, and matching specs
  // mean "same configuration", not "same unit" (dual-boot vs identical laptops).
  const hardwareOnly = mobile || !sameOs;
  const brave = isBrave(a.observation.fingerprint) || isBrave(b.observation.fingerprint);
  const bins = new Int8Array(FEATURES.length);
  const similarities = new Float32Array(FEATURES.length);
  FEATURES.forEach((spec, index) => {
    similarities[index] = NaN;
    if (!eligible(spec, context)) { bins[index] = -3; return; }
    // Rendering and OS-chosen values only mean something on the same OS.
    if (!sameOs && (spec.osDependent || spec.scope !== "device")) { bins[index] = -3; return; }
    if (bothModels && spec.modelDetermined) { bins[index] = -4; return; }
    const first = a.values[index];
    const second = b.values[index];
    if (first === null || second === null) { bins[index] = -1; return; }
    if (a.protectedFlags[index] || b.protectedFlags[index]) { bins[index] = -2; return; }
    const similarity = ((brave && spec.braveCompare) || spec.compare || exact)(first, second);
    if (similarity === null || !Number.isFinite(similarity)) { bins[index] = -1; return; }
    similarities[index] = similarity;
    bins[index] = binOf(similarity);
  });
  return { context, stratum: stratumOf(a.observation.fingerprint, b.observation.fingerprint), mobile, hardwareOnly, bins, similarities };
}

/** Deterministic pseudo-random pair sampling so evaluations are reproducible. */
function sampler(total: number, maximum: number): (index: number) => boolean {
  if (total <= maximum) return () => true;
  const keepRate = maximum / total;
  return (index) => ((Math.imul(index + 1, 2654435761) >>> 0) / 0x100000000) < keepRate;
}

export interface TrainingOptions {
  maxObservations?: number;
  maxDifferentPairs?: number;
  prior?: number;
}

interface CollectedPairs {
  labels: string[];
  pairs: Array<{ left: number; right: number; pair: PairBins; same: boolean }>;
  totalCounts: Record<string, FeatureCounts>;
  sameByLabel: Map<string, Record<string, FeatureCounts>>;
  diffByLabel: Map<string, Record<string, FeatureCounts>>;
  diffByLabelPair: Map<string, Record<string, FeatureCounts>>;
  samePairs: Record<ComparisonContext, number>;
  differentPairs: number;
  sampled: boolean;
}

/**
 * Compares every same-device pair and a deterministic sample of
 * different-device pairs, and keeps per-device count buckets so that any
 * pair can later be scored by a model that never saw either of its devices.
 */
function collectPairs(rows: Extracted[], maxDifferentPairs: number): CollectedPairs {
  const labels = rows.map((row) => row.observation.deviceLabel);
  const totalPairs = (rows.length * (rows.length - 1)) / 2;
  const keep = sampler(totalPairs, maxDifferentPairs);
  const collected: CollectedPairs = {
    labels,
    pairs: [],
    totalCounts: Object.fromEntries(FEATURES.map((spec) => [spec.id, emptyCounts()])),
    sameByLabel: new Map(),
    diffByLabel: new Map(),
    diffByLabelPair: new Map(),
    samePairs: { "same-browser": 0, "same-engine": 0, "cross-browser": 0 },
    differentPairs: 0,
    sampled: totalPairs > maxDifferentPairs,
  };
  const bucket = (map: Map<string, Record<string, FeatureCounts>>, key: string) => {
    if (!map.has(key)) map.set(key, Object.fromEntries(FEATURES.map((spec) => [spec.id, emptyCounts()])));
    return map.get(key)!;
  };
  let pairIndex = 0;
  for (let left = 0; left < rows.length; left += 1) {
    for (let right = left + 1; right < rows.length; right += 1, pairIndex += 1) {
      const same = labels[left] === labels[right];
      if (!same && !keep(pairIndex)) continue;
      const pair = comparePair(rows[left], rows[right]);
      collected.pairs.push({ left, right, pair, same });
      if (same) collected.samePairs[pair.context] += 1;
      else collected.differentPairs += 1;
      const targets = same
        ? [collected.totalCounts, bucket(collected.sameByLabel, labels[left])]
        : [collected.totalCounts, bucket(collected.diffByLabel, labels[left]), bucket(collected.diffByLabel, labels[right]), bucket(collected.diffByLabelPair, labelPairKey(labels[left], labels[right]))];
      FEATURES.forEach((spec, index) => {
        const bin = pair.bins[index];
        if (bin < 0) return;
        for (const target of targets) {
          if (same) target[spec.id].same[contextIndex(pair.context)][bin] += 1;
          else addDiff(target[spec.id], pair.stratum, bin, 1);
        }
      });
    }
  }
  return collected;
}

/** Scores each collected pair with counts that exclude both of its devices. */
function heldOutScores(collected: CollectedPairs) {
  return collected.pairs.map(({ left, right, pair, same }) => {
    const counts = leaveOut(collected.totalCounts, collected.labels[left], collected.labels[right], collected.sameByLabel, collected.diffByLabel, collected.diffByLabelPair);
    return { left, right, same, context: pair.context, ...aggregate(pair, counts) };
  });
}

export function trainLinkageModel(observations: ResearchObservation[], options: TrainingOptions = {}): LinkageModel {
  const rows = observations.slice(0, options.maxObservations ?? 400).map(extract);
  const collected = collectPairs(rows, options.maxDifferentPairs ?? 30_000);
  const labels = new Set(collected.labels).size;
  const model: LinkageModel = {
    version: LINKAGE_MODEL_VERSION,
    trainedAt: new Date().toISOString(),
    observations: rows.length,
    deviceLabels: labels,
    samePairs: collected.samePairs,
    differentPairs: collected.differentPairs,
    counts: collected.totalCounts,
    prior: options.prior ?? openWorldPrior(labels),
    calibration: null,
  };
  // Platt scaling needs both classes in reasonable numbers. It is fitted on
  // held-out scores (each pair scored without its own devices): in-sample
  // scores are optimistic and made the fit swing with every feature change.
  const positives = collected.pairs.filter((item) => item.same).length;
  const negatives = collected.pairs.length - positives;
  if (positives >= 25 && negatives >= 25) {
    const fit = plattFit(heldOutScores(collected).map((item) => ({ llr: item.total, label: item.same ? 1 : 0 })));
    if (fit) model.calibration = { ...fit, trainingPositiveRate: positives / collected.pairs.length, pairs: collected.pairs.length };
  }
  return model;
}

/**
 * Probability that a stored observation belongs to the visiting device before
 * looking at any evidence: one in (known devices + the possibility of a new
 * one), assuming a population of at least ten devices.
 */
export function openWorldPrior(deviceCount: number): number {
  return Math.max(0.002, 1 / Math.max(10, deviceCount + 1));
}

function aggregate(pair: PairBins, counts: Record<string, FeatureCounts>) {
  const raw = new Map<LinkFamily, number>();
  const llrs = new Float64Array(FEATURES.length);
  let used = 0;
  let weakPool = 0;
  FEATURES.forEach((spec, index) => {
    const bin = pair.bins[index];
    if (bin < 0) return;
    const featureCounts = counts[spec.id] || emptyCounts();
    const llr = featureLlr(spec, pair.context, pair.stratum, bin, featureCounts);
    llrs[index] = llr;
    // Model-determined signals on phones, or hardware compared across OSes,
    // only identify a configuration, so together they count at most as much
    // as a matching model name.
    // The OS itself stays outside the group: a different OS is its own evidence.
    const grouped = pair.hardwareOnly && spec.id !== "os" && (spec.modelDetermined || (!spec.osDependent && HARDWARE_FAMILIES.has(spec.family)));
    const family = grouped ? "model" : spec.family;
    // Small positive matches (a default pixel ratio, en-US, the current
    // browser version) are mostly one fact, "a default setup", so they are
    // pooled and capped instead of adding up as if independent.
    if (llr > 0 && llr < WEAK_MATCH_LLR && family !== "model") {
      weakPool += llr;
      return;
    }
    raw.set(family, (raw.get(family) || 0) + llr);
    used += 1;
  });
  if (weakPool > 0) raw.set("defaults", weakPool);
  let total = 0;
  const families = Array.from(raw.entries()).map(([family, value]) => {
    const capped = Math.max(FAMILY_CAPS[family].negative, Math.min(FAMILY_CAPS[family].positive, value));
    total += capped;
    return { family, label: FAMILY_LABELS[family], raw: value, capped };
  });
  return { total, families, llrs, used };
}

/** Too few independent signal groups to say anything about the pair. */
function isInsufficient(comparableFamilies: number, used: number): boolean {
  return comparableFamilies < 3 || used < 5;
}

/**
 * Whether the support for "same device" comes from more than a hardware
 * look-alike. It needs at least two independent kinds of supporting evidence,
 * at least one of them beyond the hardware/model group and the network
 * (screen size + a shared mobile-carrier IP block is not enough). Pooled
 * weak "defaults" matches never count as a kind of their own.
 */
function hasIndependentSupport(families: Array<{ family: LinkFamily; capped: number }>): boolean {
  const supporting = families.filter((family) => family.family !== "defaults" && family.capped >= 0.25);
  return supporting.length >= 2 && supporting.some((family) => family.family !== "model" && family.family !== "network");
}

/**
 * A "same device" claim needs support from several independent kinds of
 * evidence. Screen size plus a shared mobile-carrier IP block, for example,
 * is two weak kinds and stays at most "can't tell" (50%). A matching named
 * phone model (e.g. "RMX3392" on both) is a specific identifier on its own,
 * so the rule only applies when no model name matched.
 */
function cappedPosterior(total: number, families: Array<{ family: LinkFamily; capped: number }>, model: Pick<LinkageModel, "prior" | "calibration">, namedModelMatch: boolean): number {
  const posterior = posteriorFrom(total, model);
  return !namedModelMatch && !hasIndependentSupport(families) ? Math.min(posterior, 0.5) : posterior;
}

function namedModelMatches(pair: PairBins): boolean {
  return pair.bins[DEVICE_MODEL_INDEX] === 0;
}

function posteriorFrom(total: number, model: Pick<LinkageModel, "prior" | "calibration">): number {
  if (model.calibration) {
    const { slope, intercept, trainingPositiveRate } = model.calibration;
    // Prior-shift correction: the calibration set over-represents same-device
    // pairs, so swap its base rate for the open-world prior.
    return sigmoid(slope * total + intercept - logit(trainingPositiveRate) + logit(model.prior));
  }
  return sigmoid(logit(model.prior) + total);
}

export function linkObservations(current: ResearchObservation, previous: ResearchObservation, model: LinkageModel): LinkageResult {
  const first = extract(current);
  const second = extract(previous);
  const pair = comparePair(first, second);
  const { total, families, llrs, used } = aggregate(pair, model.counts);
  const posterior = cappedPosterior(total, families, model, namedModelMatches(pair));
  const comparableFamilies = families.length;
  const notes: string[] = [];
  const protections = [current, previous].flatMap((observation) => observation.fingerprint.modern?.protections.notes || []);
  if (protections.length) notes.push(...Array.from(new Set(protections)));
  if (!model.calibration) notes.push("Posterior is an uncalibrated naive-Bayes estimate until at least 25 same-device and 25 different-device labelled pairs exist.");
  if (pair.bins.some((bin) => bin === -4)) notes.push("Both scans report their phone model, so the model name decides the hardware question; screen, GPU, rendering and system fonts are not counted again. With the same model, only personal settings, memory variant, timing and network separate two phones.");
  else if (!pair.mobile && pair.hardwareOnly) notes.push("Different operating systems: only hardware is comparable, and matching specs can mean a dual-boot machine or two laptops of the same configuration, so together they count at most as much as a model match.");
  else if (pair.mobile) notes.push("Phone signals fixed by the hardware model (screen, GPU, rendering, system fonts) are grouped as \"Device model\" and together count at most as much as a matching model name.");
  if (!namedModelMatches(pair) && !hasIndependentSupport(families)) notes.push("Only a hardware look-alike (and possibly the network) supports a match, so the result is held at \"can't tell\" (50% at most).");
  if (pair.context === "cross-browser") notes.push("Cross-engine comparison: only device-scope features (hardware, OS assets, display, locale, GPU identity and timing) are used.");

  const features: LinkageFeature[] = FEATURES.map((spec, index) => {
    const bin = pair.bins[index];
    return {
      id: spec.id,
      label: spec.label,
      family: spec.family,
      status: bin >= 0 ? "used" : bin === -2 ? "protected" : bin === -3 ? "out-of-scope" : bin === -4 ? "by-model" : "unavailable",
      similarity: bin >= 0 ? Number(pair.similarities[index].toFixed(3)) : null,
      bin: bin >= 0 ? BIN_NAMES[bin] : null,
      logLikelihoodRatio: bin >= 0 ? Number(llrs[index].toFixed(3)) : 0,
      current: display(first.values[index]),
      previous: display(second.values[index]),
    };
  });
  const insufficient = isInsufficient(comparableFamilies, used);
  const verdict: LinkageResult["verdict"] = insufficient
    ? "insufficient-evidence"
    : posterior >= 0.9 ? "same-device" : posterior >= 0.5 ? "probably-same" : posterior >= 0.1 ? "inconclusive" : "different-device";
  const margin = Math.abs(logit(Math.min(0.9999, Math.max(0.0001, posterior))));
  const confidence = !insufficient && comparableFamilies >= 6 && margin >= 3 ? "high" : !insufficient && comparableFamilies >= 4 && margin >= 1.5 ? "medium" : "low";
  return {
    modelVersion: LINKAGE_MODEL_VERSION,
    context: pair.context,
    posterior,
    calibrated: Boolean(model.calibration),
    logLikelihoodRatio: Number(total.toFixed(3)),
    verdict,
    confidence,
    comparableFamilies,
    usedFeatures: used,
    families: families.sort((a, b) => Math.abs(b.capped) - Math.abs(a.capped)),
    features,
    notes,
  };
}

function display(value: Value | null): string {
  if (value === null) return "unavailable";
  const text = Array.isArray(value) ? value.join(", ") : String(value);
  return text.length > 90 ? `${text.slice(0, 87)}…` : text;
}

/* ----------------------------------------------------------------------- */
/* Evaluation: leave-both-devices-out                                       */
/* ----------------------------------------------------------------------- */

export interface LinkageMetrics {
  context: ComparisonContext | "all";
  positives: number;
  negatives: number;
  rocAuc: number | null;
  equalErrorRate: number | null;
  tprAtFpr1: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export interface LinkageEvaluation {
  modelVersion: string;
  observations: number;
  deviceLabels: number;
  pairsScored: number;
  sampled: boolean;
  rank1Accuracy: number | null;
  rank1Queries: number;
  metrics: LinkageMetrics[];
  familyImportance: Array<{ family: LinkFamily; label: string; meanGenuine: number; meanImpostor: number; separation: number }>;
  note: string;
}

/**
 * Every pair is scored with counts that exclude both devices in the pair, so
 * no device ever contributes to its own likelihood estimate. Counts are
 * additive, which makes this exact leave-out cheap.
 */
export function evaluateLinkage(observations: ResearchObservation[], options: TrainingOptions = {}): LinkageEvaluation {
  const rows = observations.slice(0, options.maxObservations ?? 300).map(extract);
  const collected = collectPairs(rows, options.maxDifferentPairs ?? 60_000);
  const { labels, sampled } = collected;
  const deviceLabels = new Set(labels).size;
  const prior = options.prior ?? openWorldPrior(deviceLabels);
  const scored = heldOutScores(collected).map((item) => ({ ...item, posterior: sigmoid(logit(prior) + item.total) }));

  const metrics: LinkageMetrics[] = (["all", ...CONTEXTS] as Array<ComparisonContext | "all">).map((context) =>
    metricsFor(context, scored.filter((item) => context === "all" || item.context === context)));

  let rank1Correct = 0;
  let rank1Queries = 0;
  if (!sampled) {
    for (let index = 0; index < rows.length; index += 1) {
      if (!labels.some((label, other) => other !== index && label === labels[index])) continue;
      let best: { score: number; same: boolean } | null = null;
      for (const item of scored) {
        if (item.left !== index && item.right !== index) continue;
        if (!best || item.total > best.score) best = { score: item.total, same: item.same };
      }
      if (best) { rank1Queries += 1; if (best.same) rank1Correct += 1; }
    }
  }

  const familyImportance = (Object.keys(FAMILY_CAPS) as LinkFamily[]).map((family) => {
    const genuine: number[] = [];
    const impostor: number[] = [];
    for (const item of scored) {
      const value = item.families.find((entry) => entry.family === family)?.capped;
      if (value === undefined) continue;
      (item.same ? genuine : impostor).push(value);
    }
    const meanGenuine = mean(genuine);
    const meanImpostor = mean(impostor);
    return { family, label: FAMILY_LABELS[family], meanGenuine, meanImpostor, separation: meanGenuine - meanImpostor };
  }).filter((item) => Number.isFinite(item.separation)).sort((a, b) => b.separation - a.separation);

  return {
    modelVersion: LINKAGE_MODEL_VERSION,
    observations: rows.length,
    deviceLabels,
    pairsScored: scored.length,
    sampled,
    rank1Accuracy: rank1Queries ? rank1Correct / rank1Queries : null,
    rank1Queries,
    metrics,
    familyImportance,
    note: "Leave-both-devices-out: each pair is scored by a model that never saw either device. Labels are the study's manual device labels.",
  };
}

function labelPairKey(a: string, b: string): string {
  return a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`;
}

function leaveOut(
  total: Record<string, FeatureCounts>,
  first: string,
  second: string,
  sameByLabel: Map<string, Record<string, FeatureCounts>>,
  diffByLabel: Map<string, Record<string, FeatureCounts>>,
  diffByLabelPair: Map<string, Record<string, FeatureCounts>>,
): Record<string, FeatureCounts> {
  const labelsOut = first === second ? [first] : [first, second];
  const pairBucket = first === second ? undefined : diffByLabelPair.get(labelPairKey(first, second));
  const output: Record<string, FeatureCounts> = {};
  for (const spec of FEATURES) {
    const base = total[spec.id];
    const counts: FeatureCounts = {
      same: base.same.map((row) => [...row]),
      diff: [...base.diff],
      diffByOs: Object.fromEntries(Object.entries(base.diffByOs).map(([os, row]) => [os, [...row]])),
    };
    const applyDiff = (source: FeatureCounts, sign: number) => {
      for (let bin = 0; bin < 4; bin += 1) counts.diff[bin] += sign * source.diff[bin];
      for (const [os, row] of Object.entries(source.diffByOs)) {
        const target = counts.diffByOs[os] ??= [0, 0, 0, 0];
        for (let bin = 0; bin < 4; bin += 1) target[bin] += sign * row[bin];
      }
    };
    for (const label of labelsOut) {
      const same = sameByLabel.get(label)?.[spec.id];
      const diff = diffByLabel.get(label)?.[spec.id];
      if (same) for (let bin = 0; bin < 4; bin += 1) for (let context = 0; context < CONTEXTS.length; context += 1) counts.same[context][bin] -= same.same[context][bin];
      if (diff) applyDiff(diff, -1);
    }
    // Pairs between the two excluded devices were subtracted twice above.
    if (pairBucket) applyDiff(pairBucket[spec.id], 1);
    output[spec.id] = counts;
  }
  return output;
}

function metricsFor(context: ComparisonContext | "all", rows: Array<{ same: boolean; total: number; posterior: number }>): LinkageMetrics {
  const positives = rows.filter((row) => row.same).length;
  const negatives = rows.length - positives;
  const base: LinkageMetrics = { context, positives, negatives, rocAuc: null, equalErrorRate: null, tprAtFpr1: null, precision: null, recall: null, f1: null };
  if (!positives || !negatives) return base;
  const sorted = [...rows].sort((a, b) => b.total - a.total);
  // ROC by threshold sweep (ties are grouped so AUC is the Mann-Whitney value).
  let truePositive = 0, falsePositive = 0, area = 0, previousFpr = 0, previousTpr = 0;
  let equalErrorRate: number | null = null;
  let tprAtFpr1 = 0;
  for (let index = 0; index < sorted.length; index += 1) {
    if (sorted[index].same) truePositive += 1; else falsePositive += 1;
    if (index + 1 < sorted.length && sorted[index + 1].total === sorted[index].total) continue;
    const tpr = truePositive / positives;
    const fpr = falsePositive / negatives;
    area += (fpr - previousFpr) * (tpr + previousTpr) / 2;
    if (fpr <= 0.01) tprAtFpr1 = Math.max(tprAtFpr1, tpr);
    if (equalErrorRate === null && 1 - tpr <= fpr) equalErrorRate = (fpr + (1 - tpr)) / 2;
    previousFpr = fpr;
    previousTpr = tpr;
  }
  const predicted = rows.filter((row) => row.posterior >= 0.5);
  const hits = predicted.filter((row) => row.same).length;
  const precision = predicted.length ? hits / predicted.length : null;
  const recall = hits / positives;
  return {
    ...base,
    rocAuc: area,
    equalErrorRate,
    tprAtFpr1,
    precision,
    recall,
    f1: precision !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null,
  };
}

/* ----------------------------------------------------------------------- */
/* Clustering: link observations into inferred devices                      */
/* ----------------------------------------------------------------------- */

export interface DeviceCluster {
  clusterId: string;
  observationIds: string[];
  labels: string[];
  browsers: string[];
  networks: string[];
  purity: number;
  /** Lowest same-device posterior among the links that formed the set. */
  weakestLink: number | null;
}

/** Same-device posterior for every pair of observations, scored once. */
export interface PairPosteriors {
  observations: ResearchObservation[];
  /** Row-major n × n matrix; the diagonal is 1. */
  posteriors: number[];
}

export function scoreAllPairs(observations: ResearchObservation[], model: LinkageModel, limit = 300): PairPosteriors {
  const rows = observations.slice(0, limit).map(extract);
  const size = rows.length;
  const posteriors = new Array<number>(size * size).fill(1);
  for (let left = 0; left < size; left += 1) {
    for (let right = left + 1; right < size; right += 1) {
      const pair = comparePair(rows[left], rows[right]);
      const result = aggregate(pair, model.counts);
      // Pairs without enough evidence never link, whatever their percentage.
      const posterior = isInsufficient(result.families.length, result.used) ? 0 : cappedPosterior(result.total, result.families, model, namedModelMatches(pair));
      posteriors[left * size + right] = posterior;
      posteriors[right * size + left] = posterior;
    }
  }
  return { observations: rows.map((row) => row.observation), posteriors };
}

/**
 * Groups observations into same-device sets at a confidence threshold.
 * FP-STALKER-style: each observation joins its strongest neighbours (up to
 * three) at or above the threshold, so a device seen in several browsers is
 * not split by browser, while a single weak link cannot chain whole groups.
 * Union-find keeps membership transitive.
 */
export function groupSameDevice(pairs: PairPosteriors, threshold = 0.85, neighbours = 3, mutualBest = false): DeviceCluster[] {
  const size = pairs.observations.length;
  const parent = Array.from({ length: size }, (_, index) => index);
  const find = (index: number): number => (parent[index] === index ? index : (parent[index] = find(parent[index])));
  const links: Array<[number, number, number]> = [];
  for (let left = 0; left < size; left += 1) {
    const candidates: Array<{ index: number; posterior: number }> = [];
    for (let right = 0; right < size; right += 1) {
      const posterior = pairs.posteriors[left * size + right];
      if (left !== right && posterior >= threshold) candidates.push({ index: right, posterior });
    }
    candidates.sort((a, b) => b.posterior - a.posterior);
    for (const candidate of candidates.slice(0, neighbours)) {
      parent[find(left)] = find(candidate.index);
      links.push([left, candidate.index, candidate.posterior]);
    }
  }
  // Optionally also join two scans that are each other's closest match and
  // more likely than not the same device. The closest match is right far more
  // often than the absolute probability suggests when a browser (Brave)
  // hides most signals; a "can't tell" pair (held at exactly 50%) never joins.
  if (mutualBest) {
    const closest = Array.from({ length: size }, (_, left) => {
      let best = -1;
      let bestPosterior = -1;
      for (let right = 0; right < size; right += 1) {
        const posterior = pairs.posteriors[left * size + right];
        if (left !== right && posterior > bestPosterior) { best = right; bestPosterior = posterior; }
      }
      return best;
    });
    for (let left = 0; left < size; left += 1) {
      const right = closest[left];
      const posterior = right >= 0 ? pairs.posteriors[left * size + right] : 0;
      if (right > left && closest[right] === left && posterior > 0.5 && posterior < threshold) {
        parent[find(left)] = find(right);
        links.push([left, right, posterior]);
      }
    }
  }
  const groups = new Map<number, number[]>();
  for (let index = 0; index < size; index += 1) groups.set(find(index), [...(groups.get(find(index)) || []), index]);
  const weakest = new Map<number, number>();
  for (const [left, , posterior] of links) {
    const root = find(left);
    weakest.set(root, Math.min(weakest.get(root) ?? 1, posterior));
  }
  return Array.from(groups.entries()).map(([root, indexes]) => {
    const items = indexes.map((index) => pairs.observations[index]);
    const labelCounts = new Map<string, number>();
    for (const item of items) labelCounts.set(item.deviceLabel, (labelCounts.get(item.deviceLabel) || 0) + 1);
    return {
      clusterId: items[items.length - 1].observationId.slice(0, 8),
      observationIds: items.map((item) => item.observationId),
      labels: Array.from(labelCounts.keys()),
      browsers: Array.from(new Set(items.map((item) => `${browserOf(item.fingerprint)}${item.browserMode === "private" ? " (private)" : ""}`))),
      networks: Array.from(new Set(items.map((item) => item.serverNetwork?.geoIp?.asn || item.effectivePublicIp).filter((value) => value && value !== "Unknown"))),
      purity: Math.max(...labelCounts.values()) / items.length,
      weakestLink: items.length > 1 ? weakest.get(root) ?? null : null,
    };
  }).sort((a, b) => b.observationIds.length - a.observationIds.length);
}

export function clusterObservations(observations: ResearchObservation[], model: LinkageModel, threshold = 0.9, neighbours = 3): DeviceCluster[] {
  return groupSameDevice(scoreAllPairs(observations, model), threshold, neighbours);
}

/* ----------------------------------------------------------------------- */
/* Math                                                                     */
/* ----------------------------------------------------------------------- */

/**
 * Platt scaling, made robust for small, nearly separable study data:
 * - Platt's (1999) smoothed targets instead of hard 0/1 labels, so a perfect
 *   separation cannot push the fit to infinity;
 * - L2 shrinkage toward the identity map (slope 1, intercept 0);
 * - damped Newton steps with a backtracking line search;
 * - rejection of any fit outside sane bounds or worse than the identity.
 * An unrestricted Newton fit diverged on real data (slope ≈ 40,000), which
 * turned every comparison into ~0%.
 */
function plattFit(rows: Array<{ llr: number; label: 0 | 1 }>): { slope: number; intercept: number } | null {
  const positives = rows.filter((row) => row.label === 1).length;
  const negatives = rows.length - positives;
  const high = (positives + 1) / (positives + 2);
  const low = 1 / (negatives + 2);
  const targets = rows.map((row) => (row.label ? high : low));
  const shrink = 0.5;
  const loss = (slope: number, intercept: number) => {
    let total = shrink * ((slope - 1) ** 2 + intercept ** 2);
    rows.forEach((row, index) => {
      const z = slope * row.llr + intercept;
      // log(1 + e^z) computed stably
      const softplus = z > 0 ? z + Math.log1p(Math.exp(-z)) : Math.log1p(Math.exp(z));
      total += softplus - targets[index] * z;
    });
    return total;
  };
  let slope = 1;
  let intercept = 0;
  let current = loss(slope, intercept);
  const identityLoss = current;
  for (let iteration = 0; iteration < 100; iteration += 1) {
    let gradientSlope = 2 * shrink * (slope - 1), gradientIntercept = 2 * shrink * intercept;
    let hss = 2 * shrink, hsi = 0, hii = 2 * shrink;
    rows.forEach((row, index) => {
      const probability = sigmoid(slope * row.llr + intercept);
      const error = probability - targets[index];
      const weight = probability * (1 - probability);
      gradientSlope += error * row.llr;
      gradientIntercept += error;
      hss += weight * row.llr * row.llr;
      hsi += weight * row.llr;
      hii += weight;
    });
    const determinant = hss * hii - hsi * hsi;
    if (!(determinant > 1e-12)) break;
    const stepSlope = (hii * gradientSlope - hsi * gradientIntercept) / determinant;
    const stepIntercept = (hss * gradientIntercept - hsi * gradientSlope) / determinant;
    let scale = 1;
    let accepted = false;
    while (scale > 1e-4) {
      const candidate = loss(slope - scale * stepSlope, intercept - scale * stepIntercept);
      if (candidate <= current) {
        slope -= scale * stepSlope;
        intercept -= scale * stepIntercept;
        accepted = current - candidate < 1e-9;
        current = candidate;
        break;
      }
      scale /= 2;
    }
    if (scale <= 1e-4 || accepted) break;
  }
  if (!Number.isFinite(slope) || !Number.isFinite(intercept)) return null;
  if (slope < 0.05 || slope > 5 || Math.abs(intercept) > 20) return null;
  if (current > identityLoss) return null;
  return { slope, intercept };
}

function mean(values: number[]): number {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : NaN;
}

function sigmoid(value: number): number {
  return 1 / (1 + Math.exp(-value));
}

function logit(probability: number): number {
  return Math.log(probability / (1 - probability));
}

export function featureSpec(id: string): FeatureSpec | undefined {
  return FEATURE_BY_ID.get(id);
}
