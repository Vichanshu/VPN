import type { DeviceLocation, GeoIpData, NetworkPathProbe, ServerNetworkData } from "./network";
import type { RiskAssessment } from "./risk";
import { collectNdss2017Suite, type Ndss2017Suite } from "./ndss2017";
import { collectModernSignals, type ModernSignals } from "./modern-signals";
import { collectLandmarkLatency, type LandmarkProbe } from "./latency-landmarks";

export const FINGERPRINT_SCHEMA_VERSION = "5.1.0";
export const CONSENT_VERSION = "2026-08-31-v1";

export type BrowserMode = "normal" | "private" | "unknown";
export type VpnGroundTruth =
  | "none"
  | "consumer-vpn"
  | "corporate-vpn"
  | "split-tunnel"
  | "tor"
  | "public-proxy"
  | "residential-proxy"
  | "private-relay"
  | "unknown"
  | "off"
  | "on";
export type CandidateType = "host" | "srflx" | "relay" | "prflx" | "unknown";

export interface WebRTCCandidate {
  address: string;
  candidateType: CandidateType;
  protocol: string;
  addressFamily: "ipv4" | "ipv6" | "mdns" | "unknown";
  isPublic: boolean;
}

export interface FingerprintData {
  schemaVersion: string;
  collectedAt: string;
  browserFamily: string;
  browserMajor: string;
  userAgent: string;
  languages: string[];
  platform: string;
  osFamily: string;
  architecture: string;
  bitness: string;
  hardwareConcurrency: number | null;
  hardwareBucket: string;
  deviceMemory: number | null;
  memoryBucket: string;
  touchPoints: number;
  colorDepth: number;
  screen: {
    width: number;
    height: number;
    maxDimensionBucket: number;
    minDimensionBucket: number;
    pixelRatioBucket: number;
  };
  timezone: {
    name: string;
    offsetMinutes: number;
  };
  canvas: {
    hash: string;
    repeatable: boolean;
  };
  webgl: {
    vendor: string;
    renderer: string;
    rendererFamily: string;
    parameterHash: string;
    renderHash?: string;
  };
  fonts: string[];
  capabilities: string[];
  mediaCapabilities?: string[];
  display?: {
    availableWidthBucket: number;
    availableHeightBucket: number;
    orientation: string;
    colorGamut: string;
    dynamicRange: string;
    pointer: string;
    hover: string;
    reducedMotion: boolean;
  };
  storage?: {
    cookies: boolean;
    localStorage: boolean;
    sessionStorage: boolean;
    indexedDb: boolean;
  };
  audio?: {
    status: "collected" | "disabled" | "unsupported" | "failed";
    hash: string;
    sampleRate: number | null;
  };
  connection: {
    effectiveType: string;
    downlink: number | null;
    rtt: number | null;
  } | null;
  webrtcCandidates: WebRTCCandidate[];
  webrtcStatus?: "configured" | "not-configured" | "unsupported" | "failed";
  geoIp: GeoIpData | null;
  speechVoices?: {
    count: number;
    sample: string[];
    osVoiceHint: string;
  };
  environmentChecks?: {
    osMatchStatus: "consistent" | "suspicious" | "indeterminate";
    notes: string[];
  };
  signatures: {
    browser: string;
    coarseDevice: string;
  };
  collectionContext?: {
    highEntropyResearch: boolean;
    hardwareTimingProbes?: boolean;
    collectorVersion: string;
  };
  /** Consent-gated NDSS 2017 task suite. It is absent in ordinary scans. */
  ndss2017?: Ndss2017Suite;
  /** 2022-2026 device-linkage collectors (schema 5+). */
  modern?: ModernSignals;
  /** Round trips to cloud regions at known coordinates (schema 5.1+). */
  landmarks?: LandmarkProbe;
}

export interface ResearchObservation {
  observationId: string;
  deviceLabel: string;
  browserMode: BrowserMode;
  vpnGroundTruth: VpnGroundTruth;
  fingerprint: FingerprintData;
  serverSeenIp: string;
  effectivePublicIp: string;
  serverReceivedAt?: string;
  studyId?: string;
  consentVersion?: string;
  serverNetwork?: ServerNetworkData;
  pathProbes?: NetworkPathProbe[];
  deviceLocation?: DeviceLocation | null;
  groundTruthDetails?: {
    providerCode: string;
    protocol: string;
    exitCountry: string;
  };
  riskAssessment?: RiskAssessment;
  protectedComponents?: Record<string, string>;
  clientLatency?: ClientLatency | null;
}

/** Application-layer round trips measured by the browser to this origin. */
export interface ClientLatency {
  samples: number;
  minMs: number;
  medianMs: number;
}

export interface ObservationSubmission {
  deviceLabel: string;
  browserMode: BrowserMode;
  vpnGroundTruth: VpnGroundTruth;
  fingerprint: FingerprintData;
  pathProbes: NetworkPathProbe[];
  deviceLocation: DeviceLocation | null;
  highEntropyResearch: boolean;
  hardwareTimingProbes: boolean;
  latencyLandmarks?: boolean;
  consentAcknowledged: boolean;
  clientLatency: ClientLatency | null;
  studyId: string;
  groundTruthDetails: {
    providerCode: string;
    protocol: string;
    exitCountry: string;
  };
  scanChallenge: string;
  /** Local development only: the browser's own public address, used when no trusted ingress exists. */
  devPublicIp?: string;
}

const FONTS_TO_CHECK = [
  "Arial", "Helvetica", "Times New Roman", "Courier New", "Verdana", "Georgia",
  "Palatino", "Garamond", "Comic Sans MS", "Trebuchet MS", "Arial Black", "Impact",
  "Calibri", "Cambria", "Candara", "Consolas", "Constantia", "Corbel", "Lucida Grande",
  "Menlo", "Monaco", "Apple Color Emoji", "Segoe UI", "Roboto", "Ubuntu",
];

function roundTo(value: number, step: number): number {
  return Math.round(value / step) * step;
}

function numberBucket(value: number | null, boundaries: number[]): string {
  if (value === null || !Number.isFinite(value)) return "unknown";
  for (const boundary of boundaries) {
    if (value <= boundary) return `<=${boundary}`;
  }
  return `>${boundaries[boundaries.length - 1]}`;
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

function getInstalledFonts(): string[] {
  try {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    if (!context) return [];

    const text = "mmmmmmmmmmlliWW";
    const baseSize = 72;
    const fallbacks = ["monospace", "sans-serif", "serif"] as const;
    const baseline = new Map<string, number>();

    for (const fallback of fallbacks) {
      context.font = `${baseSize}px ${fallback}`;
      baseline.set(fallback, context.measureText(text).width);
    }

    return FONTS_TO_CHECK.filter((font) =>
      fallbacks.some((fallback) => {
        context.font = `${baseSize}px "${font}", ${fallback}`;
        return Math.abs(context.measureText(text).width - (baseline.get(fallback) ?? 0)) > 0.01;
      }),
    );
  } catch {
    return [];
  }
}

function isPrivateAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized.endsWith(".local")) return true;
  if (normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd")) return true;

  const parts = normalized.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

export function isPublicAddress(address: string): boolean {
  if (!address || address === "Unknown" || address.endsWith(".local")) return false;
  const looksIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address);
  const looksIpv6 = address.includes(":");
  return (looksIpv4 || looksIpv6) && !isPrivateAddress(address);
}

function candidateFamily(address: string): WebRTCCandidate["addressFamily"] {
  if (address.endsWith(".local")) return "mdns";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) return "ipv4";
  if (address.includes(":")) return "ipv6";
  return "unknown";
}

async function getWebRTCCandidates(stunUrl: string): Promise<WebRTCCandidate[]> {
  return new Promise((resolve) => {
    const candidates = new Map<string, WebRTCCandidate>();
    const PeerConnection = window.RTCPeerConnection;
    if (!PeerConnection) {
      resolve([]);
      return;
    }

    let settled = false;
    const peer = new PeerConnection({ iceServers: [{ urls: stunUrl }] });
    const finish = () => {
      if (settled) return;
      settled = true;
      peer.close();
      resolve(Array.from(candidates.values()));
    };

    peer.createDataChannel("research-probe");
    peer.onicecandidate = (event) => {
      if (!event.candidate) {
        finish();
        return;
      }

      const raw = event.candidate.candidate;
      const parts = raw.split(/\s+/);
      const typeIndex = parts.indexOf("typ");
      const rawType = event.candidate.type || (typeIndex >= 0 ? parts[typeIndex + 1] : "unknown");
      const candidateType: CandidateType = ["host", "srflx", "relay", "prflx"].includes(rawType)
        ? (rawType as CandidateType)
        : "unknown";
      const address = event.candidate.address || parts[4] || "unknown";
      const protocol = event.candidate.protocol || parts[2] || "unknown";
      const candidate: WebRTCCandidate = {
        address,
        candidateType,
        protocol,
        addressFamily: candidateFamily(address),
        isPublic: isPublicAddress(address),
      };
      candidates.set(`${candidateType}:${protocol}:${address}`, candidate);
    };

    peer.createOffer()
      .then((offer) => peer.setLocalDescription(offer))
      .catch(finish);

    window.setTimeout(finish, 2200);
  });
}

function renderCanvas(): string {
  const canvas = document.createElement("canvas");
  canvas.width = 320;
  canvas.height = 80;
  const context = canvas.getContext("2d");
  if (!context) return "unsupported";

  context.textBaseline = "alphabetic";
  context.font = "16px Arial";
  context.fillStyle = "#f97316";
  context.fillRect(10, 8, 110, 31);
  context.fillStyle = "#0891b2";
  context.fillText("VPN research fingerprint 🔐", 7, 58);
  context.fillStyle = "rgba(74, 222, 128, .68)";
  context.fillText("VPN research fingerprint 🔐", 9, 60);
  context.beginPath();
  context.arc(270, 30, 19, 0, Math.PI * 2);
  context.stroke();
  return canvas.toDataURL();
}

async function getCanvasFingerprint(): Promise<{ hash: string; repeatable: boolean }> {
  try {
    const first = renderCanvas();
    const second = renderCanvas();
    return { hash: await sha256(first), repeatable: first === second };
  } catch {
    return { hash: "unavailable", repeatable: false };
  }
}

async function getWebGLFingerprint(): Promise<FingerprintData["webgl"]> {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    if (!gl) return { vendor: "unsupported", renderer: "unsupported", rendererFamily: "unknown", parameterHash: "unavailable", renderHash: "unavailable" };

    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)) : String(gl.getParameter(gl.VENDOR));
    const renderer = debugInfo ? String(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER));
    const rendererFamily = normalizeRendererFamily(`${vendor} ${renderer}`);
    const parameters = {
      vendor,
      renderer,
      version: String(gl.getParameter(gl.VERSION)),
      shadingLanguage: String(gl.getParameter(gl.SHADING_LANGUAGE_VERSION)),
      maxTextureSize: Number(gl.getParameter(gl.MAX_TEXTURE_SIZE)),
      maxCubeMapTextureSize: Number(gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE)),
      maxRenderbufferSize: Number(gl.getParameter(gl.MAX_RENDERBUFFER_SIZE)),
      maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) as Int32Array),
      aliasedLineWidthRange: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE) as Float32Array),
      aliasedPointSizeRange: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE) as Float32Array),
      redBits: Number(gl.getParameter(gl.RED_BITS)),
      greenBits: Number(gl.getParameter(gl.GREEN_BITS)),
      blueBits: Number(gl.getParameter(gl.BLUE_BITS)),
      alphaBits: Number(gl.getParameter(gl.ALPHA_BITS)),
      depthBits: Number(gl.getParameter(gl.DEPTH_BITS)),
      stencilBits: Number(gl.getParameter(gl.STENCIL_BITS)),
      extensions: (gl.getSupportedExtensions() ?? []).sort(),
    };
    gl.clearColor(0.17, 0.43, 0.71, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const pixels = new Uint8Array(4 * 16 * 16);
    gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    return {
      vendor,
      renderer,
      rendererFamily,
      parameterHash: await sha256(stableStringify(parameters)),
      renderHash: await sha256(Array.from(pixels).join(",")),
    };
  } catch {
    return { vendor: "unavailable", renderer: "unavailable", rendererFamily: "unknown", parameterHash: "unavailable", renderHash: "unavailable" };
  }
}

function normalizeRendererFamily(value: string): string {
  const lower = value.toLowerCase();
  if (lower.includes("apple")) return "apple-gpu";
  if (lower.includes("nvidia")) return "nvidia";
  if (lower.includes("amd") || lower.includes("radeon")) return "amd";
  if (lower.includes("intel")) return "intel";
  if (lower.includes("adreno")) return "adreno";
  if (lower.includes("mali")) return "mali";
  if (lower.includes("swiftshader") || lower.includes("llvmpipe")) return "software-renderer";
  return value && value !== "unsupported" && value !== "unavailable" ? "other-gpu" : "unknown";
}

function parseBrowser(userAgent: string): { family: string; major: string } {
  // Phone makers' built-in browsers send a Chrome user agent plus their own
  // token, and usually bundle an older Chromium than Chrome itself.
  const patterns: Array<[string, RegExp]> = [
    ["HeyTap", /HeyTapBrowser\/(\d+)/],
    ["Vivo Browser", /VivoBrowser\/(\d+)/],
    ["Samsung Internet", /SamsungBrowser\/(\d+)/],
    ["Mi Browser", /(?:MiuiBrowser|XiaoMi\/MiuiBrowser)\/(\d+)/],
    ["UC Browser", /UCBrowser\/(\d+)/],
    ["Yandex", /YaBrowser\/(\d+)/],
    ["Vivaldi", /Vivaldi\/(\d+)/],
    ["DuckDuckGo", /DuckDuckGo\/(\d+)/],
    ["Android WebView", /; wv\).*Chrome\/(\d+)/],
    ["Edge", /Edg(?:A|iOS)?\/(\d+)/],
    ["Opera", /(?:OPR|OPT)\/(\d+)/],
    ["Firefox", /Firefox\/(\d+)/],
    ["Chrome", /(?:Chrome|CriOS)\/(\d+)/],
    ["Safari", /Version\/(\d+).+Safari/],
  ];
  for (const [family, pattern] of patterns) {
    const match = userAgent.match(pattern);
    if (match) return { family, major: match[1] };
  }
  return { family: "Unknown", major: "Unknown" };
}

function parseOs(userAgent: string, platform: string): string {
  const value = `${userAgent} ${platform}`.toLowerCase();
  if (value.includes("windows")) return "Windows";
  if (value.includes("iphone") || value.includes("ipad") || value.includes("ios")) return "iOS/iPadOS";
  if (value.includes("mac")) return "macOS";
  if (value.includes("android")) return "Android";
  if (value.includes("linux")) return "Linux";
  if (value.includes("cros")) return "ChromeOS";
  return "Unknown";
}

function getCapabilities(): string[] {
  const checks: Array<[string, boolean]> = [
    ["webgl2", Boolean(document.createElement("canvas").getContext("webgl2"))],
    ["webgpu", "gpu" in navigator],
    ["webrtc", "RTCPeerConnection" in window],
    ["wasm", "WebAssembly" in window],
    ["touch", navigator.maxTouchPoints > 0],
    ["indexeddb", "indexedDB" in window],
    ["serviceworker", "serviceWorker" in navigator],
    ["bluetooth", "bluetooth" in navigator],
    ["usb", "usb" in navigator],
    ["hid", "hid" in navigator],
    ["serial", "serial" in navigator],
    ["credentials", "credentials" in navigator],
  ];
  return checks.filter(([, supported]) => supported).map(([name]) => name).sort();
}

async function getHighEntropyHints(): Promise<{ architecture: string; bitness: string }> {
  try {
    const userAgentData = (navigator as Navigator & {
      userAgentData?: { getHighEntropyValues: (hints: string[]) => Promise<Record<string, string>> };
    }).userAgentData;
    if (!userAgentData) return { architecture: "unknown", bitness: "unknown" };
    const values = await userAgentData.getHighEntropyValues(["architecture", "bitness"]);
    return { architecture: values.architecture || "unknown", bitness: values.bitness || "unknown" };
  } catch {
    return { architecture: "unknown", bitness: "unknown" };
  }
}

function getMediaCapabilities(): string[] {
  const video = document.createElement("video");
  const audio = document.createElement("audio");
  const tests: Array<[string, string, HTMLMediaElement]> = [
    ["h264", 'video/mp4; codecs="avc1.42E01E"', video],
    ["vp8", 'video/webm; codecs="vp8"', video],
    ["vp9", 'video/webm; codecs="vp9"', video],
    ["av1", 'video/mp4; codecs="av01.0.05M.08"', video],
    ["hevc", 'video/mp4; codecs="hvc1.1.6.L93.B0"', video],
    ["aac", 'audio/mp4; codecs="mp4a.40.2"', audio],
    ["opus", 'audio/ogg; codecs="opus"', audio],
    ["flac", "audio/flac", audio],
  ];
  return tests
    .filter(([, mime, element]) => element.canPlayType(mime) !== "")
    .map(([name]) => name)
    .sort();
}

function mediaQueryValue(values: string[], feature: string): string {
  return values.find((value) => window.matchMedia(`(${feature}: ${value})`).matches) || "unknown";
}

function getDisplayProfile(): NonNullable<FingerprintData["display"]> {
  return {
    availableWidthBucket: roundTo(window.screen.availWidth, 100),
    availableHeightBucket: roundTo(window.screen.availHeight, 100),
    orientation: window.screen.orientation?.type || "unknown",
    colorGamut: mediaQueryValue(["rec2020", "p3", "srgb"], "color-gamut"),
    dynamicRange: mediaQueryValue(["high", "standard"], "dynamic-range"),
    pointer: mediaQueryValue(["fine", "coarse", "none"], "pointer"),
    hover: mediaQueryValue(["hover", "none"], "hover"),
    reducedMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  };
}

function storageAvailable(kind: "localStorage" | "sessionStorage"): boolean {
  try {
    const storage = window[kind];
    const key = "__vpn_research_probe__";
    storage.setItem(key, "1");
    storage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function getStorageProfile(): NonNullable<FingerprintData["storage"]> {
  return {
    cookies: navigator.cookieEnabled,
    localStorage: storageAvailable("localStorage"),
    sessionStorage: storageAvailable("sessionStorage"),
    indexedDb: "indexedDB" in window,
  };
}

async function getAudioFingerprint(enabled: boolean): Promise<NonNullable<FingerprintData["audio"]>> {
  if (!enabled) return { status: "disabled", hash: "disabled", sampleRate: null };
  const OfflineContext = window.OfflineAudioContext;
  if (!OfflineContext) return { status: "unsupported", hash: "unsupported", sampleRate: null };
  try {
    const context = new OfflineContext(1, 4_096, 44_100);
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
    const samples = Array.from(buffer.getChannelData(0).slice(512, 1_024)).map((value) => value.toFixed(7));
    return { status: "collected", hash: await sha256(samples.join(",")), sampleRate: buffer.sampleRate };
  } catch {
    return { status: "failed", hash: "failed", sampleRate: null };
  }
}

async function getSpeechVoices(): Promise<{ count: number; sample: string[]; osVoiceHint: string }> {
  if (typeof window === "undefined" || !("speechSynthesis" in window)) {
    return { count: 0, sample: [], osVoiceHint: "unsupported" };
  }
  try {
    let voices = window.speechSynthesis.getVoices();
    if (voices.length === 0) {
      await new Promise<void>((resolve) => {
        const handler = () => {
          voices = window.speechSynthesis.getVoices();
          resolve();
        };
        window.speechSynthesis.onvoiceschanged = handler;
        window.setTimeout(() => resolve(), 350);
      });
    }
    const sample = voices.slice(0, 8).map((v) => `${v.name} (${v.lang})`);
    let osVoiceHint = "unknown";
    const allNames = voices.map((v) => v.name.toLowerCase()).join(" ");
    if (
      allNames.includes("samantha") ||
      allNames.includes("karen") ||
      allNames.includes("daniel") ||
      allNames.includes("moira") ||
      allNames.includes("siri") ||
      allNames.includes("alex")
    ) {
      osVoiceHint = "macOS/iOS";
    } else if (
      allNames.includes("microsoft") ||
      allNames.includes("david") ||
      allNames.includes("zira") ||
      allNames.includes("mark") ||
      allNames.includes("cortana")
    ) {
      osVoiceHint = "Windows";
    } else if (allNames.includes("google") || allNames.includes("android")) {
      osVoiceHint = "Android/ChromeOS";
    }
    return { count: voices.length, sample, osVoiceHint };
  } catch {
    return { count: 0, sample: [], osVoiceHint: "error" };
  }
}

function evaluateEnvironment(
  osFamily: string,
  fonts: string[],
  speech: { count: number; sample: string[]; osVoiceHint: string },
  webgl: FingerprintData["webgl"]
): { osMatchStatus: "consistent" | "suspicious" | "indeterminate"; notes: string[] } {
  const notes: string[] = [];
  let suspicious = false;

  // Speech synthesis voice check vs declared OS
  if (speech.osVoiceHint !== "unknown" && speech.osVoiceHint !== "unsupported" && speech.osVoiceHint !== "error") {
    if (osFamily.includes("Windows") && speech.osVoiceHint === "macOS/iOS") {
      notes.push("User-Agent reports Windows, but system Speech Synthesis voices belong to Apple macOS/iOS.");
      suspicious = true;
    } else if ((osFamily.includes("macOS") || osFamily.includes("iOS")) && speech.osVoiceHint === "Windows") {
      notes.push("User-Agent reports macOS/iOS, but system Speech Synthesis voices belong to Microsoft Windows.");
      suspicious = true;
    }
  }

  // System font metrics vs declared OS
  const hasWindowsExclusiveFonts = fonts.some((f) =>
    ["Segoe UI", "Calibri", "Cambria", "Consolas", "Constantia", "Corbel"].includes(f)
  );
  const hasAppleExclusiveFonts = fonts.some((f) =>
    ["Menlo", "Monaco", "Apple Color Emoji", "Lucida Grande"].includes(f)
  );
  if (osFamily.includes("macOS") && hasWindowsExclusiveFonts && !hasAppleExclusiveFonts) {
    notes.push("Client declares macOS, but detected font inventory matches Microsoft Windows.");
    suspicious = true;
  } else if (osFamily.includes("Windows") && hasAppleExclusiveFonts && !hasWindowsExclusiveFonts) {
    notes.push("Client declares Windows, but detected font inventory matches Apple macOS.");
    suspicious = true;
  }

  // Virtualized software WebGL renderer check
  if (webgl.rendererFamily === "software-renderer") {
    notes.push("WebGL relies on a virtual software renderer (SwiftShader/llvmpipe), common in headless cloud nodes.");
  }

  const osMatchStatus = suspicious ? "suspicious" : notes.length === 0 ? "consistent" : "indeterminate";
  return { osMatchStatus, notes };
}

export async function generateClientFingerprint(options: { stunUrl?: string; highEntropyResearch?: boolean; hardwareTimingProbes?: boolean; latencyLandmarks?: boolean } = {}): Promise<FingerprintData> {
  const nav = navigator as Navigator & {
    deviceMemory?: number;
    connection?: { effectiveType?: string; downlink?: number; rtt?: number };
  };
  const userAgent = navigator.userAgent;
  const parsedBrowser = parseBrowser(userAgent);
  // Brave sends a Chrome user agent but exposes navigator.brave.
  const browser = "brave" in navigator ? { ...parsedBrowser, family: "Brave" } : parsedBrowser;
  const platform = navigator.platform || "Unknown";
  const osFamily = parseOs(userAgent, platform);
  const hardwareConcurrency = navigator.hardwareConcurrency || null;
  const deviceMemory = nav.deviceMemory || null;
  const highEntropy = await getHighEntropyHints();
  const canvas = await getCanvasFingerprint();
  const webgl = await getWebGLFingerprint();
  const fonts = getInstalledFonts();
  const capabilities = getCapabilities();
  const highEntropyResearch = Boolean(options.highEntropyResearch);
  const speechVoices = highEntropyResearch
    ? await getSpeechVoices()
    : { count: 0, sample: [], osVoiceHint: "disabled" };
  const environmentChecks = evaluateEnvironment(osFamily, fonts, speechVoices, webgl);
  const mediaCapabilities = getMediaCapabilities();
  const display = getDisplayProfile();
  const storage = getStorageProfile();
  const audio = await getAudioFingerprint(highEntropyResearch);
  const ndss2017 = highEntropyResearch ? await collectNdss2017Suite() : undefined;
  const hardwareTimingProbes = Boolean(options.hardwareTimingProbes);
  // Landmarks run before the GPU probes so heavy work does not inflate timings.
  const landmarks = await collectLandmarkLatency(Boolean(options.latencyLandmarks));
  const modern = await collectModernSignals({ highEntropyResearch, hardwareTimingProbes });
  const webrtcSupported = "RTCPeerConnection" in window;
  let webrtcStatus: FingerprintData["webrtcStatus"] = options.stunUrl ? "configured" : "not-configured";
  let webrtcCandidates: WebRTCCandidate[] = [];
  if (!webrtcSupported) {
    webrtcStatus = "unsupported";
  } else if (options.stunUrl) {
    try {
      webrtcCandidates = await getWebRTCCandidates(options.stunUrl);
    } catch {
      webrtcStatus = "failed";
    }
  }
  const timezone = {
    name: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
    offsetMinutes: -new Date().getTimezoneOffset(),
  };
  const screen = {
    width: window.screen.width,
    height: window.screen.height,
    maxDimensionBucket: roundTo(Math.max(window.screen.width, window.screen.height), 100),
    minDimensionBucket: roundTo(Math.min(window.screen.width, window.screen.height), 100),
    pixelRatioBucket: Math.round(window.devicePixelRatio * 4) / 4,
  };

  const base = {
    schemaVersion: FINGERPRINT_SCHEMA_VERSION,
    collectedAt: new Date().toISOString(),
    browserFamily: browser.family,
    browserMajor: browser.major,
    userAgent,
    languages: Array.from(navigator.languages || [navigator.language]),
    platform,
    osFamily,
    architecture: highEntropy.architecture,
    bitness: highEntropy.bitness,
    hardwareConcurrency,
    hardwareBucket: numberBucket(hardwareConcurrency, [2, 4, 8, 16]),
    deviceMemory,
    memoryBucket: numberBucket(deviceMemory, [2, 4, 8, 16]),
    touchPoints: navigator.maxTouchPoints || 0,
    colorDepth: window.screen.colorDepth,
    screen,
    timezone,
    canvas,
    webgl,
    fonts,
    capabilities,
    mediaCapabilities,
    display,
    storage,
    audio,
    speechVoices,
    environmentChecks,
    connection: nav.connection ? {
      effectiveType: nav.connection.effectiveType || "unknown",
      downlink: nav.connection.downlink ?? null,
      rtt: nav.connection.rtt ?? null,
    } : null,
    webrtcCandidates,
    webrtcStatus,
    geoIp: null,
    collectionContext: {
      highEntropyResearch,
      hardwareTimingProbes,
      collectorVersion: FINGERPRINT_SCHEMA_VERSION,
    },
    ndss2017,
    modern,
    landmarks,
  };

  const browserSignatureInput = {
    schema: base.schemaVersion,
    browser: `${base.browserFamily}:${base.browserMajor}`,
    os: base.osFamily,
    platform: base.platform,
    hardware: base.hardwareBucket,
    memory: base.memoryBucket,
    screen: base.screen,
    touch: base.touchPoints,
    colorDepth: base.colorDepth,
    canvas: base.canvas.hash,
    webgl: base.webgl.parameterHash,
    fonts: base.fonts,
    capabilities: base.capabilities,
    mediaCapabilities: base.mediaCapabilities,
    display: base.display,
    audio: base.audio.status === "collected" ? base.audio.hash : base.audio.status,
    ndss2017: base.ndss2017?.signature || "disabled",
  };
  const deviceSignatureInput = {
    schema: base.schemaVersion,
    os: base.osFamily,
    architecture: base.architecture,
    bitness: base.bitness,
    hardware: base.hardwareBucket,
    memory: base.memoryBucket,
    screen: base.screen,
    touch: base.touchPoints > 0,
    colorDepth: base.colorDepth,
    gpuFamily: base.webgl.rendererFamily,
    display: {
      colorGamut: base.display.colorGamut,
      dynamicRange: base.display.dynamicRange,
      pointer: base.display.pointer,
    },
    ndss2017: base.ndss2017 ? {
      screenRatio: base.ndss2017.screen.widthHeightRatio,
      taskIds: base.ndss2017.crossBrowserTaskIds,
    } : "disabled",
  };

  return {
    ...base,
    signatures: {
      browser: await sha256(stableStringify(browserSignatureInput)),
      coarseDevice: await sha256(stableStringify(deviceSignatureInput)),
    },
  };
}
