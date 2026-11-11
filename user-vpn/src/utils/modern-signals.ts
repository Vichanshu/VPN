/**
 * Device-linkage collectors derived from 2022-2026 fingerprinting research.
 *
 * Every collector returns compact, comparison-ready summaries (hashes, small
 * vectors, sets, buckets) rather than raw pixels or audio. Collectors that run
 * timing micro-benchmarks are opt-in because they take ~1 s and load the GPU.
 *
 * Research basis (see RESEARCH_2022_2026.md for citations):
 * - DrawnApart (NDSS 2022): per-execution-unit GPU timing traces.
 * - AtomicIncrement (WiSec 2025) / LockedApart (2025): WebGPU compute scheduling.
 * - Cascading Spy Sheets (NDSS 2025) and Fashion Faux Pas (S&P 2023): system
 *   font/style probing that survives JavaScript API hardening.
 * - Device Fingerprinting with Peripheral Timestamps (S&P 2022): input polling.
 * - FP-Inconsistent (2024/25) and FP-Scanner (2018): detect randomization
 *   instead of trusting noisy values.
 */

export const MODERN_SIGNALS_VERSION = "2026.10-1";
export const FONT_LIST_VERSION = "fonts-2026.10-170";

export type CollectorStatus = "collected" | "disabled" | "unsupported" | "failed";

export interface ModernSignals {
  version: string;
  durationMs: number;
  clientHints: {
    platformVersion: string;
    model: string;
    formFactors: string[];
    wow64: boolean | null;
    fullVersionList: string[];
  } | null;
  screenInsets: { horizontal: number; vertical: number; left: number; top: number };
  refreshRate: { hz: number | null; samples: number };
  pointer: { pollingHz: number | null; samples: number };
  gpu: { rendererTokens: string[]; masked: boolean };
  webgpu: {
    status: CollectorStatus;
    vendor: string;
    architecture: string;
    device: string;
    description: string;
    features: string[];
    limitsHash: string;
    subgroupMinSize: number | null;
    subgroupMaxSize: number | null;
    isFallbackAdapter: boolean | null;
    scheduling: { status: CollectorStatus; profile: number[]; dispatches: number };
  };
  gpuTiming: {
    status: CollectorStatus;
    method: "readpixels-sync" | "none";
    points: number;
    rounds: number;
    workload: number;
    medianMs: number | null;
    profile: number[];
  };
  fonts: { listVersion: string; probed: number; detected: string[] };
  emoji: { widths: number[]; maxVersion: string; hash: string };
  systemStyle: {
    genericWidths: Record<string, number>;
    colors: Record<string, string>;
    colorScheme: string;
    contrast: string;
    forcedColors: boolean;
  };
  intl: { locale: string; calendar: string; numberingSystem: string; hourCycle: string; timeZone: string };
  math: { hash: string };
  voices: { status: CollectorStatus; local: string[]; remoteCount: number };
  mediaDevices: { audioinput: number; videoinput: number; audiooutput: number } | null;
  canvasRobust: { status: CollectorStatus; grid: number[]; noiseDetected: boolean; solidFillDeviation: number };
  audioRobust: { status: CollectorStatus; summary: number | null; noiseDetected: boolean };
  protections: {
    brave: boolean;
    canvasNoise: boolean;
    audioNoise: boolean;
    possibleFirefoxRfp: boolean;
    webglMasked: boolean;
    notes: string[];
  };
}

export interface ModernSignalOptions {
  /** DrawnApart / WebGPU scheduling probes. Slow and GPU-heavy, so opt-in. */
  hardwareTimingProbes: boolean;
  /** Local speech voice inventory. Treated as high entropy, so opt-in. */
  highEntropyResearch: boolean;
}

const FONT_PROBES = [
  // Windows system and Office
  "Arial", "Arial Narrow", "Arial Black", "Bahnschrift", "Calibri", "Calibri Light", "Cambria", "Candara", "Cascadia Code", "Cascadia Mono",
  "Comic Sans MS", "Consolas", "Constantia", "Corbel", "Ebrima", "Franklin Gothic Medium", "Gabriola", "Gadugi", "Georgia", "HoloLens MDL2 Assets",
  "Impact", "Ink Free", "Javanese Text", "Leelawadee UI", "Lucida Console", "Lucida Sans Unicode", "Malgun Gothic", "Marlett", "Microsoft Himalaya", "Microsoft JhengHei",
  "Microsoft New Tai Lue", "Microsoft PhagsPa", "Microsoft Sans Serif", "Microsoft Tai Le", "Microsoft YaHei", "Microsoft Yi Baiti", "MingLiU-ExtB", "Mongolian Baiti", "MS Gothic", "MV Boli",
  "Myanmar Text", "Nirmala UI", "Palatino Linotype", "Segoe Fluent Icons", "Segoe MDL2 Assets", "Segoe Print", "Segoe Script", "Segoe UI", "Segoe UI Emoji", "Segoe UI Historic",
  "Segoe UI Symbol", "Segoe UI Variable Display", "SimSun", "Sitka Text", "Sylfaen", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana", "Webdings",
  "Wingdings", "Yu Gothic", "Aptos", "Century Gothic", "Garamond", "Gill Sans MT", "Book Antiqua", "Bookman Old Style", "Century", "Haettenschweiler",
  "Lucida Bright", "Lucida Calligraphy", "Lucida Handwriting", "Monotype Corsiva", "Agency FB", "Algerian", "Bauhaus 93", "Broadway", "Castellar", "Edwardian Script ITC",
  "Elephant", "Harrington", "Jokerman", "Magneto", "Old English Text MT", "Onyx", "Playbill", "Ravie", "Showcard Gothic", "Stencil",
  "Tw Cen MT", "Vivaldi", "Wide Latin", "Arial Rounded MT Bold",
  // macOS / iOS
  "American Typewriter", "Andale Mono", "Apple Chancery", "Apple Color Emoji", "Apple SD Gothic Neo", "AppleGothic", "Avenir", "Avenir Next", "Baskerville", "Big Caslon",
  "Bradley Hand", "Chalkboard", "Chalkboard SE", "Charter", "Cochin", "Copperplate", "Didot", "Futura", "Galvji", "Geneva",
  "Gill Sans", "Helvetica", "Helvetica Neue", "Herculanum", "Hiragino Sans", "Hoefler Text", "Kohinoor Devanagari", "Lucida Grande", "Luminari", "Marker Felt",
  "Menlo", "Monaco", "Noteworthy", "Optima", "Papyrus", "Phosphate", "PingFang SC", "Rockwell", "Savoye LET", "SF Pro",
  "SF Mono", "Skia", "Snell Roundhand", "Trattatello", "Zapfino",
  // Linux / Android
  "DejaVu Sans", "DejaVu Serif", "DejaVu Sans Mono", "Liberation Sans", "Liberation Serif", "Liberation Mono", "Noto Sans", "Noto Serif", "Noto Color Emoji", "Noto Sans CJK SC",
  "Ubuntu", "Ubuntu Mono", "Cantarell", "Droid Sans", "FreeSans", "Nimbus Sans", "URW Bookman", "Roboto",
  // User-installed / design tooling
  "Myriad Pro", "Minion Pro", "Adobe Garamond Pro", "Source Sans Pro", "Source Code Pro", "Open Sans", "Lato", "Montserrat", "Raleway", "Fira Sans",
  "Fira Code", "JetBrains Mono", "Inter",
];

/** One single-codepoint emoji per Unicode emoji release, oldest first. */
const EMOJI_VERSIONS: Array<[string, string]> = [
  ["11.0", "\u{1F970}"], ["12.0", "\u{1F971}"], ["13.0", "\u{1F972}"], ["14.0", "\u{1FAE0}"], ["15.0", "\u{1FAE8}"], ["16.0", "\u{1FAE9}"],
];
const EMOJI_METRIC_SET = ["😀", "👍🏽", "🏳️‍🌈", "🇮🇳", "👨‍👩‍👧", "🧑‍💻", "❤️", "🫠"];
const GENERIC_FAMILIES = ["serif", "sans-serif", "monospace", "cursive", "fantasy", "system-ui", "ui-monospace", "ui-serif", "ui-rounded", "math", "emoji"];
const SYSTEM_COLORS = ["AccentColor", "AccentColorText", "Canvas", "CanvasText", "Highlight", "HighlightText", "LinkText", "ButtonFace", "Field", "GrayText", "Mark"];
const REFRESH_CLASSES = [30, 48, 50, 60, 72, 75, 90, 100, 120, 144, 165, 180, 240, 360];
const POLLING_CLASSES = [60, 90, 120, 125, 250, 500, 1000, 2000, 4000, 8000];

type PointerGlobal = typeof globalThis & { __fpPointerIntervals?: number[]; __fpPointerObserver?: boolean };

/**
 * Passive input-device observer (Monaco, S&P 2022 inspired). Records only the
 * intervals between coalesced pointer events, never positions or targets.
 */
export function startPointerObserver(): () => void {
  const shared = globalThis as PointerGlobal;
  if (shared.__fpPointerObserver || typeof window === "undefined") return () => undefined;
  shared.__fpPointerObserver = true;
  shared.__fpPointerIntervals = [];
  let previous = 0;
  const handler = (event: PointerEvent) => {
    const events = typeof event.getCoalescedEvents === "function" ? event.getCoalescedEvents() : [event];
    for (const item of events.length ? events : [event]) {
      if (previous && item.timeStamp > previous) {
        const intervals = shared.__fpPointerIntervals!;
        intervals.push(item.timeStamp - previous);
        if (intervals.length > 600) intervals.shift();
      }
      previous = item.timeStamp;
    }
  };
  window.addEventListener("pointermove", handler, { passive: true });
  return () => {
    window.removeEventListener("pointermove", handler);
    shared.__fpPointerObserver = false;
  };
}

export async function collectModernSignals(options: ModernSignalOptions): Promise<ModernSignals> {
  const started = performance.now();
  const canvasRobust = await getRobustCanvas();
  const audioRobust = await getRobustAudio();
  const webglInfo = getWebglRendererTokens();
  const timing = options.hardwareTimingProbes ? await getGpuTimingTrace() : disabledGpuTiming();
  const webgpu = await getWebGpuProfile(options.hardwareTimingProbes);
  const signals: Omit<ModernSignals, "protections" | "durationMs"> = {
    version: MODERN_SIGNALS_VERSION,
    clientHints: await getClientHints(),
    screenInsets: getScreenInsets(),
    refreshRate: await getRefreshRate(),
    pointer: getPointerPolling(),
    gpu: webglInfo,
    webgpu,
    gpuTiming: timing,
    fonts: getFontInventory(),
    emoji: await getEmojiProfile(),
    systemStyle: getSystemStyle(),
    intl: getIntlProfile(),
    math: { hash: await sha256(mathFingerprint().join("|")) },
    voices: options.highEntropyResearch ? await getLocalVoices() : { status: "disabled", local: [], remoteCount: 0 },
    mediaDevices: await getMediaDeviceCounts(),
    canvasRobust,
    audioRobust,
  };
  return {
    ...signals,
    protections: detectProtections(signals),
    durationMs: Math.round(performance.now() - started),
  };
}

/* ----------------------------------------------------------------------- */
/* Platform, display, and input                                             */
/* ----------------------------------------------------------------------- */

async function getClientHints(): Promise<ModernSignals["clientHints"]> {
  const data = (navigator as Navigator & {
    userAgentData?: { getHighEntropyValues: (hints: string[]) => Promise<Record<string, unknown>> };
  }).userAgentData;
  if (!data) return null;
  try {
    const values = await data.getHighEntropyValues(["platformVersion", "model", "formFactors", "wow64", "fullVersionList"]);
    const list = Array.isArray(values.fullVersionList) ? values.fullVersionList as Array<{ brand: string; version: string }> : [];
    return {
      platformVersion: typeof values.platformVersion === "string" ? values.platformVersion : "",
      model: typeof values.model === "string" ? values.model : "",
      formFactors: Array.isArray(values.formFactors) ? (values.formFactors as string[]).map(String).sort() : [],
      wow64: typeof values.wow64 === "boolean" ? values.wow64 : null,
      fullVersionList: list.filter((item) => !/not.?a.?brand/i.test(item.brand)).map((item) => `${item.brand}/${item.version.split(".")[0]}`).sort(),
    };
  } catch {
    return null;
  }
}

function getScreenInsets(): ModernSignals["screenInsets"] {
  const screen = window.screen as Screen & { availLeft?: number; availTop?: number };
  return {
    horizontal: screen.width - screen.availWidth,
    vertical: screen.height - screen.availHeight,
    left: screen.availLeft ?? 0,
    top: screen.availTop ?? 0,
  };
}

function getRefreshRate(): Promise<ModernSignals["refreshRate"]> {
  return new Promise((resolve) => {
    const stamps: number[] = [];
    const deadline = performance.now() + 600;
    const step = (time: number) => {
      stamps.push(time);
      if (stamps.length < 40 && performance.now() < deadline) requestAnimationFrame(step);
      else finish();
    };
    const finish = () => {
      const intervals = stamps.slice(1).map((value, index) => value - stamps[index]).filter((value) => value > 1 && value < 100);
      if (intervals.length < 8) return resolve({ hz: null, samples: intervals.length });
      resolve({ hz: snap(1000 / median(intervals), REFRESH_CLASSES, 0.08), samples: intervals.length });
    };
    requestAnimationFrame(step);
    window.setTimeout(finish, 900);
  });
}

function getPointerPolling(): ModernSignals["pointer"] {
  const intervals = ((globalThis as PointerGlobal).__fpPointerIntervals || []).filter((value) => value > 0.05 && value < 40);
  if (intervals.length < 40) return { pollingHz: null, samples: intervals.length };
  // The low quantile approximates the device report interval; coalescing and
  // idle gaps only ever make observed intervals longer.
  const sorted = [...intervals].sort((a, b) => a - b);
  const base = sorted[Math.floor(sorted.length * 0.2)];
  return { pollingHz: snap(1000 / base, POLLING_CLASSES, 0.2), samples: intervals.length };
}

async function getMediaDeviceCounts(): Promise<ModernSignals["mediaDevices"]> {
  try {
    if (!navigator.mediaDevices?.enumerateDevices) return null;
    const devices = await navigator.mediaDevices.enumerateDevices();
    return {
      audioinput: devices.filter((item) => item.kind === "audioinput").length,
      videoinput: devices.filter((item) => item.kind === "videoinput").length,
      audiooutput: devices.filter((item) => item.kind === "audiooutput").length,
    };
  } catch {
    return null;
  }
}

function getIntlProfile(): ModernSignals["intl"] {
  const options = Intl.DateTimeFormat().resolvedOptions();
  let hourCycle = "unknown";
  try {
    hourCycle = new Intl.DateTimeFormat(undefined, { hour: "numeric" }).resolvedOptions().hourCycle || "unknown";
  } catch {
    // older engines
  }
  return { locale: options.locale, calendar: options.calendar, numberingSystem: options.numberingSystem, hourCycle, timeZone: options.timeZone || "unknown" };
}

/* ----------------------------------------------------------------------- */
/* OS assets: fonts, emoji, system style, voices                            */
/* ----------------------------------------------------------------------- */

function getFontInventory(): ModernSignals["fonts"] {
  const detected: string[] = [];
  try {
    const context = document.createElement("canvas").getContext("2d");
    if (!context) return { listVersion: FONT_LIST_VERSION, probed: 0, detected };
    const sample = "mmmmmmmmmmlliWW@#0123";
    const fallbacks = ["monospace", "sans-serif", "serif"];
    const baseline = fallbacks.map((fallback) => {
      context.font = `64px ${fallback}`;
      const metrics = context.measureText(sample);
      return [metrics.width, metrics.actualBoundingBoxAscent, metrics.actualBoundingBoxDescent];
    });
    for (const font of FONT_PROBES) {
      const present = fallbacks.some((fallback, index) => {
        context.font = `64px "${font}", ${fallback}`;
        const metrics = context.measureText(sample);
        const [width, ascent, descent] = baseline[index];
        return Math.abs(metrics.width - width) > 0.05 || Math.abs(metrics.actualBoundingBoxAscent - ascent) > 0.05 || Math.abs(metrics.actualBoundingBoxDescent - descent) > 0.05;
      });
      if (present) detected.push(font);
    }
  } catch {
    // canvas text metrics unavailable
  }
  return { listVersion: FONT_LIST_VERSION, probed: FONT_PROBES.length, detected };
}

async function getEmojiProfile(): Promise<ModernSignals["emoji"]> {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 48;
    canvas.height = 48;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) return { widths: [], maxVersion: "unknown", hash: "unsupported" };
    context.font = "32px sans-serif";
    const widths = EMOJI_METRIC_SET.map((emoji) => Math.round(context.measureText(emoji).width * 2) / 2);
    let maxVersion = "<11.0";
    for (const [version, emoji] of EMOJI_VERSIONS) {
      context.clearRect(0, 0, 48, 48);
      context.textBaseline = "top";
      context.fillText(emoji, 4, 4);
      if (!hasColourGlyph(context.getImageData(0, 0, 48, 48).data)) break;
      maxVersion = version;
    }
    return { widths, maxVersion, hash: await sha256(`${widths.join(",")}|${maxVersion}`) };
  } catch {
    return { widths: [], maxVersion: "unknown", hash: "failed" };
  }
}

function hasColourGlyph(data: Uint8ClampedArray): boolean {
  let coloured = 0;
  for (let index = 0; index < data.length; index += 4) {
    if (data[index + 3] < 32) continue;
    const spread = Math.max(data[index], data[index + 1], data[index + 2]) - Math.min(data[index], data[index + 1], data[index + 2]);
    if (spread > 48) coloured += 1;
  }
  // Farbling touches a handful of pixels; a real colour glyph covers hundreds.
  return coloured > 40;
}

function getSystemStyle(): ModernSignals["systemStyle"] {
  const genericWidths: Record<string, number> = {};
  const colors: Record<string, string> = {};
  try {
    const context = document.createElement("canvas").getContext("2d");
    if (context) {
      for (const family of GENERIC_FAMILIES) {
        context.font = `40px ${family}`;
        genericWidths[family] = Math.round(context.measureText("Hamburgefonstiv 0123 ÅÉ").width * 4) / 4;
      }
    }
    const probe = document.createElement("div");
    probe.style.position = "absolute";
    probe.style.visibility = "hidden";
    document.body.appendChild(probe);
    for (const name of SYSTEM_COLORS) {
      probe.style.color = "";
      probe.style.color = name;
      colors[name] = probe.style.color ? getComputedStyle(probe).color : "unsupported";
    }
    probe.remove();
  } catch {
    // style probing unavailable
  }
  return {
    genericWidths,
    colors,
    colorScheme: window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
    contrast: ["more", "less", "custom"].find((value) => window.matchMedia(`(prefers-contrast: ${value})`).matches) || "no-preference",
    forcedColors: window.matchMedia("(forced-colors: active)").matches,
  };
}

async function getLocalVoices(): Promise<ModernSignals["voices"]> {
  if (!("speechSynthesis" in window)) return { status: "unsupported", local: [], remoteCount: 0 };
  try {
    let voices = window.speechSynthesis.getVoices();
    if (!voices.length) {
      await new Promise<void>((resolve) => {
        window.speechSynthesis.addEventListener("voiceschanged", () => resolve(), { once: true });
        window.setTimeout(resolve, 400);
      });
      voices = window.speechSynthesis.getVoices();
    }
    const local = Array.from(new Set(voices.filter((voice) => voice.localService).map((voice) => `${voice.name}|${voice.lang}`))).sort().slice(0, 120);
    return { status: "collected", local, remoteCount: voices.filter((voice) => !voice.localService).length };
  } catch {
    return { status: "failed", local: [], remoteCount: 0 };
  }
}

/* ----------------------------------------------------------------------- */
/* Rendering: noise-tolerant canvas and audio                               */
/* ----------------------------------------------------------------------- */

function drawRobustScene(): Uint8ClampedArray | null {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 64;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  const gradient = context.createLinearGradient(0, 0, 256, 64);
  gradient.addColorStop(0, "#0f766e");
  gradient.addColorStop(1, "#f59e0b");
  context.fillStyle = gradient;
  context.fillRect(0, 0, 256, 64);
  context.fillStyle = "#ffffff";
  context.font = "22px system-ui, sans-serif";
  context.fillText("Linkage Ωπ 😀 123", 8, 30);
  context.font = "italic 15px serif";
  context.fillText("fingerprint glyph shaping ﬁ", 10, 54);
  context.beginPath();
  context.arc(222, 32, 20, 0, Math.PI * 1.7);
  context.strokeStyle = "rgba(15,23,42,.8)";
  context.lineWidth = 3;
  context.stroke();
  return context.getImageData(0, 0, 256, 64).data;
}

/**
 * Average luminance over a 16x4 grid. Per-pixel randomization (Brave farbling,
 * Firefox FPP, Safari AFP) changes a few low bits; region means barely move,
 * so the grid survives where an exact hash does not.
 */
function luminanceGrid(data: Uint8ClampedArray): number[] {
  const grid: number[] = [];
  for (let row = 0; row < 4; row += 1) {
    for (let column = 0; column < 16; column += 1) {
      let total = 0;
      for (let y = row * 16; y < row * 16 + 16; y += 1) {
        for (let x = column * 16; x < column * 16 + 16; x += 1) {
          const offset = (y * 256 + x) * 4;
          total += 0.2126 * data[offset] + 0.7152 * data[offset + 1] + 0.0722 * data[offset + 2];
        }
      }
      grid.push(Math.round((total / 256) * 4) / 4);
    }
  }
  return grid;
}

async function getRobustCanvas(): Promise<ModernSignals["canvasRobust"]> {
  try {
    const first = drawRobustScene();
    const second = drawRobustScene();
    if (!first || !second) return { status: "unsupported", grid: [], noiseDetected: false, solidFillDeviation: 0 };
    let differs = false;
    for (let index = 0; index < first.length; index += 1) if (first[index] !== second[index]) { differs = true; break; }
    const solidFillDeviation = solidFillNoise();
    return { status: "collected", grid: luminanceGrid(first), noiseDetected: differs || solidFillDeviation > 0, solidFillDeviation };
  } catch {
    return { status: "failed", grid: [], noiseDetected: false, solidFillDeviation: 0 };
  }
}

/** A known solid colour must read back exactly unless readback is perturbed. */
function solidFillNoise(): number {
  const canvas = document.createElement("canvas");
  canvas.width = 32;
  canvas.height = 32;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return 0;
  context.fillStyle = "rgb(123, 45, 67)";
  context.fillRect(0, 0, 32, 32);
  const data = context.getImageData(0, 0, 32, 32).data;
  let deviating = 0;
  for (let index = 0; index < data.length; index += 4) {
    if (data[index] !== 123 || data[index + 1] !== 45 || data[index + 2] !== 67 || data[index + 3] !== 255) deviating += 1;
  }
  return deviating;
}

async function renderAudioSummary(): Promise<number | null> {
  const OfflineContext = window.OfflineAudioContext;
  if (!OfflineContext) return null;
  const context = new OfflineContext(1, 5_000, 44_100);
  const oscillator = context.createOscillator();
  const compressor = context.createDynamicsCompressor();
  oscillator.type = "triangle";
  oscillator.frequency.value = 10_000;
  compressor.threshold.value = -50;
  compressor.knee.value = 40;
  compressor.ratio.value = 12;
  compressor.attack.value = 0;
  compressor.release.value = 0.25;
  oscillator.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);
  const buffer = await context.startRendering();
  const samples = buffer.getChannelData(0);
  let total = 0;
  for (let index = 4_500; index < 5_000; index += 1) total += Math.abs(samples[index]);
  return total;
}

async function getRobustAudio(): Promise<ModernSignals["audioRobust"]> {
  try {
    const first = await renderAudioSummary();
    if (first === null) return { status: "unsupported", summary: null, noiseDetected: false };
    const second = await renderAudioSummary();
    // Rounding to 6 significant digits absorbs sub-ULP noise; a mismatch
    // between two renders is itself evidence of audio randomization.
    return { status: "collected", summary: Number(first.toPrecision(6)), noiseDetected: first !== second };
  } catch {
    return { status: "failed", summary: null, noiseDetected: false };
  }
}

function mathFingerprint(): string[] {
  const values = [
    Math.acos(0.123124234234234242), Math.acosh(1e308), Math.asin(0.123124234234234242), Math.asinh(1), Math.atanh(0.5),
    Math.atan(2), Math.sin(-1e300), Math.sinh(1), Math.cos(10.000000000123), Math.cosh(1), Math.tan(-1e300), Math.tanh(1),
    Math.exp(1), Math.expm1(1), Math.log1p(10), Math.cbrt(Math.PI), Math.pow(Math.PI, -100), Math.hypot(Math.LOG2E, -100),
  ];
  return values.map((value) => String(value));
}

/* ----------------------------------------------------------------------- */
/* GPU: renderer strings, DrawnApart timing, WebGPU                          */
/* ----------------------------------------------------------------------- */

function getWebglRendererTokens(): ModernSignals["gpu"] {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) return { rendererTokens: [], masked: false };
    const debug = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = String(debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
    const tokens = rendererTokens(renderer);
    return { rendererTokens: tokens, masked: tokens.length <= 1 || /^(apple gpu|webkit webgl|mozilla|generic renderer)$/i.test(renderer.trim()) };
  } catch {
    return { rendererTokens: [], masked: false };
  }
}

const RENDERER_STOP_WORDS = new Set([
  "angle", "direct3d11", "direct3d9", "direct3d", "d3d11", "opengl", "vulkan", "metal", "renderer", "unspecified", "version", "graphics",
  "gpu", "corporation", "inc", "the", "and", "family", "series", "with", "driver", "core", "profile", "es", "mesa", "compatibility",
]);

/** Normalise vendor-specific wrappers so Chrome/ANGLE, Firefox and Safari strings overlap. */
export function rendererTokens(renderer: string): string[] {
  let value = renderer.toLowerCase();
  const angle = value.match(/angle \((.*)\)\s*$/);
  if (angle) value = angle[1];
  value = value
    .replace(/\(0x[0-9a-f]+\)/g, " ")
    .replace(/vs_\d_\d|ps_\d_\d|\d+\.\d+(\.\d+)*/g, " ")
    .replace(/\((r|tm|c)\)/g, " ")
    .replace(/[^a-z0-9 ]+/g, " ");
  return Array.from(new Set(value.split(/\s+/).filter((token) => token.length > 1 && !RENDERER_STOP_WORDS.has(token)))).sort();
}

function disabledGpuTiming(): ModernSignals["gpuTiming"] {
  return { status: "disabled", method: "none", points: 0, rounds: 0, workload: 0, medianMs: null, profile: [] };
}

const STALL_VERTEX_SHADER = `#version 300 es
uniform int stalled;
uniform int iterations;
void main() {
  if (gl_VertexID == stalled) {
    float value = float(gl_VertexID) * 0.013 + 0.5;
    for (int index = 0; index < iterations; index++) {
      value = fract(sin(value * 12.9898 + float(index) * 0.001) * 43758.5453);
    }
    gl_Position = vec4(value * 0.0001, 0.0, 0.0, 1.0);
  } else {
    gl_Position = vec4(0.0, 0.0, 0.0, 1.0);
  }
  gl_PointSize = 1.0;
}`;
/** Upper bound keeps a stalled draw far below driver watchdog limits. */
const MAX_STALL_WORKLOAD = 128_000;
const STALL_FRAGMENT_SHADER = `#version 300 es
precision mediump float;
out vec4 colour;
void main() { colour = vec4(1.0); }`;

/**
 * DrawnApart-style trace (Laor et al., NDSS 2022). Sixteen points are drawn in
 * one call; one point at a time runs a stall loop, so the draw time follows
 * the execution unit that received it. Each draw is synchronised with a 1x1
 * readPixels (the paper's offscreen method used convertToBlob). The returned
 * profile is per-point median time divided by the trace median, which removes
 * clock speed and keeps the relative per-unit shape.
 */
async function getGpuTimingTrace(): Promise<ModernSignals["gpuTiming"]> {
  const points = 16;
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    const gl = canvas.getContext("webgl2", { antialias: false, depth: false, stencil: false, preserveDrawingBuffer: false });
    if (!gl) return { ...disabledGpuTiming(), status: "unsupported" };
    const program = buildProgram(gl, STALL_VERTEX_SHADER, STALL_FRAGMENT_SHADER);
    if (!program) return { ...disabledGpuTiming(), status: "failed" };
    gl.useProgram(program);
    const stalledLocation = gl.getUniformLocation(program, "stalled");
    const iterationsLocation = gl.getUniformLocation(program, "iterations");
    const pixel = new Uint8Array(4);
    const draw = (point: number, iterations: number) => {
      gl.uniform1i(stalledLocation, point);
      gl.uniform1i(iterationsLocation, iterations);
      const start = performance.now();
      gl.drawArrays(gl.POINTS, 0, points);
      gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
      return performance.now() - start;
    };

    // Warm up first: the initial draws include shader compilation and driver
    // state setup, which would otherwise end calibration too early.
    for (let point = 0; point < points; point += 1) draw(point, 2_000);
    await nextFrame();

    // Calibrate toward ~2.5 ms per stalled draw: long enough for coarse
    // timers, far from GPU watchdogs. Never probe beyond that: some drivers
    // silently cut long vertex loops (seen on ANGLE/Metal around 10 ms per
    // draw) and later draws then return without doing the work.
    const measure = (iterations: number) => median([0, 1, 2, 3, 4].map((point) => draw(point, iterations)));
    let workload = 2_000;
    let elapsed = measure(workload);
    while (elapsed < 2.5 && workload < MAX_STALL_WORKLOAD) {
      const candidate = Math.min(MAX_STALL_WORKLOAD, workload * 2);
      const candidateElapsed = measure(candidate);
      // More work must not be much faster; a drop means the loop was cut.
      if (elapsed >= 0.5 && candidateElapsed < elapsed * 0.6) break;
      workload = candidate;
      elapsed = candidateElapsed;
      await nextFrame();
    }

    const rounds = 7;
    const samples: number[][] = Array.from({ length: points }, () => []);
    for (let round = 0; round < rounds; round += 1) {
      for (let point = 0; point < points; point += 1) samples[point].push(draw(point, workload));
      await nextFrame();
    }
    const perPoint = samples.map((values) => median(values.slice(1)));
    const overall = median(perPoint);
    // A trace dominated by timer quantisation carries no per-unit information.
    if (gl.isContextLost() || !Number.isFinite(overall) || overall < 0.5) return { ...disabledGpuTiming(), status: "failed", workload, medianMs: Number.isFinite(overall) ? overall : null };
    return {
      status: "collected",
      method: "readpixels-sync",
      points,
      rounds,
      workload,
      medianMs: Number(overall.toFixed(3)),
      profile: perPoint.map((value) => Number((value / overall).toFixed(4))),
    };
  } catch {
    return { ...disabledGpuTiming(), status: "failed" };
  }
}

function buildProgram(gl: WebGL2RenderingContext, vertexSource: string, fragmentSource: string): WebGLProgram | null {
  const compile = (kind: number, source: string) => {
    const shader = gl.createShader(kind);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    return gl.getShaderParameter(shader, gl.COMPILE_STATUS) ? shader : null;
  };
  const vertex = compile(gl.VERTEX_SHADER, vertexSource);
  const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
  const program = gl.createProgram();
  if (!vertex || !fragment || !program) return null;
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  return gl.getProgramParameter(program, gl.LINK_STATUS) ? program : null;
}

interface MinimalGpuAdapter {
  features: Set<string>;
  limits: Record<string, number>;
  info?: Record<string, unknown>;
  isFallbackAdapter?: boolean;
  requestDevice: () => Promise<MinimalGpuDevice>;
}
interface MinimalGpuDevice {
  createShaderModule: (descriptor: { code: string }) => unknown;
  createComputePipeline: (descriptor: unknown) => { getBindGroupLayout: (index: number) => unknown };
  createBuffer: (descriptor: { size: number; usage: number }) => { mapAsync: (mode: number) => Promise<void>; getMappedRange: () => ArrayBuffer; unmap: () => void; destroy: () => void };
  createBindGroup: (descriptor: unknown) => unknown;
  createCommandEncoder: () => {
    beginComputePass: () => { setPipeline: (pipeline: unknown) => void; setBindGroup: (index: number, group: unknown) => void; dispatchWorkgroups: (x: number) => void; end: () => void };
    copyBufferToBuffer: (source: unknown, sourceOffset: number, destination: unknown, destinationOffset: number, size: number) => void;
    clearBuffer: (buffer: unknown) => void;
    finish: () => unknown;
  };
  queue: { submit: (buffers: unknown[]) => void };
  destroy: () => void;
}

const LIMIT_KEYS = [
  "maxTextureDimension2D", "maxTextureArrayLayers", "maxBindGroups", "maxStorageBufferBindingSize", "maxBufferSize",
  "maxComputeWorkgroupStorageSize", "maxComputeInvocationsPerWorkgroup", "maxComputeWorkgroupSizeX", "maxColorAttachmentBytesPerSample",
  "maxInterStageShaderVariables", "maxUniformBufferBindingSize", "minStorageBufferOffsetAlignment",
];

async function getWebGpuProfile(runScheduling: boolean): Promise<ModernSignals["webgpu"]> {
  const empty: ModernSignals["webgpu"] = {
    status: "unsupported", vendor: "", architecture: "", device: "", description: "", features: [], limitsHash: "",
    subgroupMinSize: null, subgroupMaxSize: null, isFallbackAdapter: null,
    scheduling: { status: runScheduling ? "unsupported" : "disabled", profile: [], dispatches: 0 },
  };
  const gpu = (navigator as Navigator & { gpu?: { requestAdapter: () => Promise<MinimalGpuAdapter | null> } }).gpu;
  if (!gpu) return empty;
  try {
    const adapter = await withTimeout(gpu.requestAdapter(), 1_500);
    if (!adapter) return empty;
    const info = adapter.info || {};
    const limits = Object.fromEntries(LIMIT_KEYS.map((key) => [key, Number(adapter.limits[key] ?? -1)]));
    const profile: ModernSignals["webgpu"] = {
      ...empty,
      status: "collected",
      vendor: String(info.vendor || ""),
      architecture: String(info.architecture || ""),
      device: String(info.device || ""),
      description: String(info.description || "").slice(0, 120),
      features: Array.from(adapter.features).map(String).sort(),
      limitsHash: await sha256(JSON.stringify(limits)),
      subgroupMinSize: typeof info.subgroupMinSize === "number" ? info.subgroupMinSize : null,
      subgroupMaxSize: typeof info.subgroupMaxSize === "number" ? info.subgroupMaxSize : null,
      isFallbackAdapter: typeof info.isFallbackAdapter === "boolean" ? info.isFallbackAdapter : typeof adapter.isFallbackAdapter === "boolean" ? adapter.isFallbackAdapter : null,
    };
    if (runScheduling) profile.scheduling = await getWebGpuScheduling(adapter);
    return profile;
  } catch {
    return { ...empty, status: "failed" };
  }
}

const WORKGROUPS = 256;
const SCHEDULING_SHADER = `
@group(0) @binding(0) var<storage, read_write> counter: atomic<u32>;
@group(0) @binding(1) var<storage, read_write> tickets: array<u32>;
@compute @workgroup_size(64)
fn main(@builtin(local_invocation_index) local: u32, @builtin(workgroup_id) group: vec3<u32>) {
  if (local == 0u) {
    tickets[group.x] = atomicAdd(&counter, 1u);
  }
}`;

/**
 * Inspired by AtomicIncrement (Hohentanner et al., WiSec 2025): the order in
 * which workgroups reach a shared atomic reflects how the GPU distributes
 * work. This is an approximation of that idea, not the authors' kernel: the
 * profile is each workgroup's mean ticket over several dispatches, with the
 * linear in-order trend removed, z-normalised and reduced to 32 buckets.
 */
async function getWebGpuScheduling(adapter: MinimalGpuAdapter): Promise<ModernSignals["webgpu"]["scheduling"]> {
  let device: MinimalGpuDevice | null = null;
  try {
    device = await withTimeout(adapter.requestDevice(), 1_500);
    if (!device) return { status: "failed", profile: [], dispatches: 0 };
    const STORAGE = 0x80, COPY_SRC = 0x04, COPY_DST = 0x08, MAP_READ = 0x01;
    const pipeline = device.createComputePipeline({ layout: "auto", compute: { module: device.createShaderModule({ code: SCHEDULING_SHADER }), entryPoint: "main" } });
    const counter = device.createBuffer({ size: 4, usage: STORAGE | COPY_DST });
    const tickets = device.createBuffer({ size: WORKGROUPS * 4, usage: STORAGE | COPY_SRC });
    const readback = device.createBuffer({ size: WORKGROUPS * 4, usage: MAP_READ | COPY_DST });
    const group = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [{ binding: 0, resource: { buffer: counter } }, { binding: 1, resource: { buffer: tickets } }] });
    const dispatches = 12;
    const totals = new Array<number>(WORKGROUPS).fill(0);
    for (let run = 0; run < dispatches; run += 1) {
      const encoder = device.createCommandEncoder();
      encoder.clearBuffer(counter);
      const pass = encoder.beginComputePass();
      pass.setPipeline(pipeline);
      pass.setBindGroup(0, group);
      pass.dispatchWorkgroups(WORKGROUPS);
      pass.end();
      encoder.copyBufferToBuffer(tickets, 0, readback, 0, WORKGROUPS * 4);
      device.queue.submit([encoder.finish()]);
      await readback.mapAsync(MAP_READ);
      const values = new Uint32Array(readback.getMappedRange().slice(0));
      readback.unmap();
      for (let index = 0; index < WORKGROUPS; index += 1) totals[index] += values[index];
    }
    // Remove the least-squares linear trend: every GPU tends to hand out
    // tickets roughly in dispatch order, and that shared trend would make
    // unrelated devices look correlated.
    const meanTickets = totals.map((total) => total / dispatches);
    const centre = (WORKGROUPS - 1) / 2;
    const average = meanTickets.reduce((sum, value) => sum + value, 0) / WORKGROUPS;
    let slopeNumerator = 0, slopeDenominator = 0;
    meanTickets.forEach((value, index) => { slopeNumerator += (index - centre) * (value - average); slopeDenominator += (index - centre) ** 2; });
    const slope = slopeNumerator / slopeDenominator;
    const residuals = meanTickets.map((value, index) => value - (average + slope * (index - centre)));
    const mean = residuals.reduce((sum, value) => sum + value, 0) / residuals.length;
    const deviation = Math.sqrt(residuals.reduce((sum, value) => sum + (value - mean) ** 2, 0) / residuals.length);
    // Reduce to 32 buckets so the stored profile stays small.
    const profile = Array.from({ length: 32 }, (_, bucket) => {
      const slice = residuals.slice(bucket * 8, bucket * 8 + 8);
      const value = slice.reduce((sum, item) => sum + item, 0) / slice.length;
      return deviation > 0 ? Number(((value - mean) / deviation).toFixed(3)) : 0;
    });
    counter.destroy();
    tickets.destroy();
    readback.destroy();
    return { status: "collected", profile, dispatches };
  } catch {
    return { status: "failed", profile: [], dispatches: 0 };
  } finally {
    device?.destroy();
  }
}

/* ----------------------------------------------------------------------- */
/* Protection detection                                                     */
/* ----------------------------------------------------------------------- */

function detectProtections(signals: Omit<ModernSignals, "protections" | "durationMs">): ModernSignals["protections"] {
  const notes: string[] = [];
  const brave = Boolean((navigator as Navigator & { brave?: unknown }).brave);
  const canvasNoise = signals.canvasRobust.noiseDetected;
  const audioNoise = signals.audioRobust.noiseDetected;
  const possibleFirefoxRfp = /Firefox\//.test(navigator.userAgent) && signals.intl.timeZone === "UTC" && window.screen.width === window.innerWidth;
  if (brave) notes.push("Brave detected: canvas, audio, WebGL and WebGPU values may be farbled per site and session.");
  if (canvasNoise) notes.push("Canvas readback is randomized; exact canvas hashes are excluded and the luminance grid is used instead.");
  if (audioNoise) notes.push("Audio rendering differs between identical runs; exact audio hashes are excluded.");
  if (possibleFirefoxRfp) notes.push("Firefox resistFingerprinting indicators (UTC timezone, screen equals window).");
  if (signals.gpu.masked) notes.push("WebGL renderer string is masked or generic.");
  return { brave, canvasNoise, audioNoise, possibleFirefoxRfp, webglMasked: signals.gpu.masked, notes };
}

/* ----------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ----------------------------------------------------------------------- */

function median(values: number[]): number {
  if (!values.length) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function snap(value: number, classes: number[], tolerance: number): number {
  const nearest = classes.reduce((best, candidate) => Math.abs(candidate - value) < Math.abs(best - value) ? candidate : best, classes[0]);
  return Math.abs(nearest - value) / nearest <= tolerance ? nearest : Math.round(value);
}

function nextFrame(): Promise<void> {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T | null> {
  return Promise.race([promise, new Promise<null>((resolve) => window.setTimeout(() => resolve(null), milliseconds))]);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
