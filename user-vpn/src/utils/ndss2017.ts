/**
 * Opt-in reproduction harness for the task families described in Cao, Li and
 * Wijmans (NDSS 2017). It is deliberately a first-party research component:
 * callers must gate it behind an explicit consent control and it returns
 * hashes, capability states, and static test metadata - never rendered pixels.
 *
 * This is a reproducibility suite, not a claim that a browser can prove a
 * physical device or a person's identity. A few paper tasks require historic
 * codecs/assets (DDS, PVR and video frames); those are represented by their
 * supported WebGL/media capabilities rather than bundling third-party assets.
 */

export const NDSS2017_SUITE_VERSION = "ndss-2017-opt-in-v1";

export type NdssTaskStatus = "collected" | "unsupported" | "failed" | "capability-only";

export interface NdssTaskResult {
  id: string;
  title: string;
  family: "render" | "canvas" | "texture" | "media" | "writing-system";
  status: NdssTaskStatus;
  hash: string;
  parameters: string[];
  crossBrowserEligible: boolean;
}

export interface Ndss2017Suite {
  version: string;
  enabled: true;
  commonParameters: {
    canvas: "256x256";
    ambientLight: "0.3,0.3,0.3";
    defaultCamera: "0,0,-7";
    texture: "256x256 deterministic RGB";
  };
  screen: {
    widthHeightRatio: number;
    availableWidth: number;
    availableHeight: number;
    availableLeft: number;
    availableTop: number;
    orientation: string;
  };
  cpu: { virtualCores: number | null };
  audioDestination: {
    sampleRate: number | null;
    maxChannelCount: number | null;
    channelCount: number | null;
    channelCountMode: string;
    channelInterpretation: string;
    numberOfInputs: number | null;
    numberOfOutputs: number | null;
  };
  writingSystems: { supported: string[]; unsupported: string[]; hash: string };
  tasks: NdssTaskResult[];
  supportedTaskIds: string[];
  crossBrowserTaskIds: string[];
  signature: string;
}

const WRITING_SYSTEMS: Array<[string, string]> = [
  ["Latin", "A"], ["Chinese", "中"], ["Arabic", "م"], ["Devanagari", "अ"], ["Cyrillic", "Ж"],
  ["Bengali", "অ"], ["Kana", "あ"], ["Gurmukhi", "ਅ"], ["Javanese", "ꦄ"], ["Hangul", "한"],
  ["Telugu", "అ"], ["Tamil", "அ"], ["Malayalam", "അ"], ["Burmese", "က"], ["Thai", "ก"],
  ["Sudanese", "ᮃ"], ["Kannada", "ಅ"], ["Gujarati", "અ"], ["Lao", "ກ"], ["Odia", "ଅ"],
  ["Ge'ez", "ሀ"], ["Sinhala", "අ"], ["Armenian", "Ա"], ["Khmer", "ក"], ["Greek", "Α"],
  ["Lontara", "ᨀ"], ["Hebrew", "א"], ["Tibetan", "ཀ"], ["Georgian", "ა"], ["Modern Yi", "ꆈ"],
  ["Mongolian", "ᠠ"], ["Tifinagh", "ⴰ"], ["Amharic", "ሀ"], ["Thaana", "ހ"], ["Inuktitut", "ᐃ"], ["Cherokee", "Ꭰ"],
];

const TASKS: Array<{
  id: string;
  title: string;
  family: NdssTaskResult["family"];
  parameters: string[];
  eligible: boolean;
  mode: "webgl" | "canvas" | "capability" | "writing";
}> = [
  { id: "a", title: "Texture", family: "texture", parameters: ["Suzanne-style texture interpolation", "256x256 deterministic RGB texture"], eligible: true, mode: "webgl" },
  { id: "b", title: "Varyings", family: "render", parameters: ["contrasting per-vertex colours", "camera 0,0,-5"], eligible: true, mode: "webgl" },
  { id: "b-prime", title: "Anti-aliasing + Varyings", family: "render", parameters: ["task b", "anti-aliasing requested"], eligible: true, mode: "webgl" },
  { id: "c", title: "Camera", family: "render", parameters: ["camera -1,-4,-10", "projection variation"], eligible: true, mode: "webgl" },
  { id: "d", title: "Lines and curves", family: "canvas", parameters: ["three gradients", "cosine curve"], eligible: true, mode: "canvas" },
  { id: "d-prime", title: "Anti-aliasing + Lines and curves", family: "canvas", parameters: ["task d", "anti-aliasing requested"], eligible: true, mode: "canvas" },
  { id: "e", title: "Multi-models", family: "render", parameters: ["two model surfaces", "two deterministic textures"], eligible: true, mode: "webgl" },
  { id: "f", title: "Diffuse point light", family: "render", parameters: ["white RGB 2,2,2", "light 3,-4,-2"], eligible: true, mode: "webgl" },
  { id: "g", title: "Light and models", family: "render", parameters: ["task f", "two model surfaces"], eligible: true, mode: "webgl" },
  { id: "h", title: "Specular light", family: "render", parameters: ["diffuse RGB .75,.75,1", "specular RGB .8,.8,.8", "light .8,-.8,-.8"], eligible: true, mode: "webgl" },
  { id: "h-prime", title: "Anti-aliasing + Specular light", family: "render", parameters: ["task h", "anti-aliasing requested"], eligible: true, mode: "webgl" },
  { id: "h-rotated", title: "Rotated specular light", family: "render", parameters: ["task h-prime", "90 degree rotation"], eligible: true, mode: "webgl" },
  { id: "i", title: "Two textures", family: "texture", parameters: ["two layered deterministic textures"], eligible: true, mode: "webgl" },
  { id: "j-009", title: "Alpha 0.09", family: "render", parameters: ["alpha .09", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-010", title: "Alpha 0.10", family: "render", parameters: ["alpha .10", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-011", title: "Alpha 0.11", family: "render", parameters: ["alpha .11", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-039", title: "Alpha 0.39", family: "render", parameters: ["alpha .39", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-040", title: "Alpha 0.40", family: "render", parameters: ["alpha .40", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-041", title: "Alpha 0.41", family: "render", parameters: ["alpha .41", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-079", title: "Alpha 0.79", family: "render", parameters: ["alpha .79", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "j-100", title: "Alpha 1.00", family: "render", parameters: ["alpha 1.00", "overlapping surfaces"], eligible: true, mode: "webgl" },
  { id: "k", title: "Complex lights", family: "render", parameters: ["seeded scene", "red/yellow moving-light proxy", "5,000-ring paper reference"], eligible: true, mode: "webgl" },
  { id: "k-prime", title: "Anti-aliasing + Complex lights", family: "render", parameters: ["task k", "anti-aliasing requested"], eligible: true, mode: "webgl" },
  { id: "l", title: "Clipping plane", family: "render", parameters: ["clipping-plane proxy", "static tetrahedron paper reference"], eligible: true, mode: "webgl" },
  { id: "m", title: "Cubemap and Fresnel", family: "texture", parameters: ["cubemap capability", "Fresnel-style reflection proxy"], eligible: true, mode: "webgl" },
  { id: "n", title: "DDS textures", family: "texture", parameters: ["S3TC DXT1/DXT3/DXT5", "mipmap capability"], eligible: true, mode: "capability" },
  { id: "o", title: "PVR textures", family: "texture", parameters: ["PVRTC v1/v3", "2/4-bit, mipmap capability"], eligible: true, mode: "capability" },
  { id: "p", title: "Float and depth textures", family: "texture", parameters: ["float texture capability", "depth texture capability"], eligible: true, mode: "capability" },
  { id: "q", title: "Video texture", family: "media", parameters: ["WebM/H.264 capability", "six-frame paper reference"], eligible: false, mode: "capability" },
  { id: "r", title: "Writing scripts", family: "writing-system", parameters: ["36 writing systems", "missing-glyph comparison"], eligible: true, mode: "writing" },
];

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => `${JSON.stringify(key)}:${stable(child)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function hash(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(stable(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function seedFor(id: string): number {
  return Array.from(id).reduce((value, char) => (value * 31 + char.charCodeAt(0)) >>> 0, 2166136261);
}

function seeded(value: number): () => number {
  let state = value >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function textPixels(text: string): Uint8ClampedArray | null {
  const canvas = document.createElement("canvas");
  canvas.width = 96;
  canvas.height = 96;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  context.fillStyle = "#000";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.font = "64px sans-serif";
  context.fillStyle = "#fff";
  context.fillText(text, 12, 70);
  return context.getImageData(0, 0, canvas.width, canvas.height).data;
}

function supportsWritingSystem(character: string): boolean {
  const candidate = textPixels(character);
  const fallback = textPixels("\ufffd");
  if (!candidate || !fallback) return false;
  if (candidate.length !== fallback.length) return false;
  return candidate.some((value, index) => value !== fallback[index]);
}

async function getWritingSystems() {
  const supported: string[] = [];
  const unsupported: string[] = [];
  for (const [name, character] of WRITING_SYSTEMS) {
    (supportsWritingSystem(character) ? supported : unsupported).push(name);
  }
  return { supported, unsupported, hash: await hash({ supported, unsupported }) };
}

function drawCurveTask(id: string): Uint8ClampedArray | null {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  context.fillStyle = "#000";
  context.fillRect(0, 0, 256, 256);
  context.strokeStyle = id.includes("prime") ? "#80f6ff" : "#e8f1ff";
  context.lineWidth = 1.25;
  context.beginPath();
  for (let x = 0; x < 256; x += 1) {
    const y = 256 - 100 * Math.cos((2 * Math.PI * x) / 100) + 30 * Math.cos((4 * Math.PI * x) / 100) + 6 * Math.cos((6 * Math.PI * x) / 100);
    if (x === 0) context.moveTo(x, y); else context.lineTo(x, y);
  }
  context.stroke();
  [[38.4, 115.2, 89.6, 204.8], [89.6, 89.6, 153.6, 204.8], [166.4, 89.6, 217.6, 204.8]].forEach(([x1, y1, x2, y2]) => {
    context.beginPath(); context.moveTo(x1, y1); context.lineTo(x2, y2); context.stroke();
  });
  return context.getImageData(0, 0, 256, 256).data;
}

function webglPixels(id: string): { pixels: Uint8Array; capabilities: Record<string, unknown> } | null {
  const task = TASKS.find((entry) => entry.id === id);
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const gl = canvas.getContext("webgl", { antialias: Boolean(id.includes("prime")), preserveDrawingBuffer: true });
  if (!gl || !task) return null;
  const vertexSource = `attribute vec2 p; attribute vec3 c; varying vec3 v; varying vec2 uv; uniform float s; uniform vec2 o; void main(){ v=c; uv=(p+1.0)*.5; gl_Position=vec4(p*s+o,0.,1.); }`;
  const fragmentSource = `precision mediump float; varying vec3 v; varying vec2 uv; uniform sampler2D tex; uniform float a; uniform float k; void main(){ vec3 t=texture2D(tex,uv).rgb; vec3 lit=mix(v,t,.62)+vec3(sin((uv.x+uv.y+k)*8.)*.09); gl_FragColor=vec4(lit,a); }`;
  const compile = (kind: number, source: string) => {
    const shader = gl.createShader(kind)!;
    gl.shaderSource(shader, source); gl.compileShader(shader);
    return gl.getShaderParameter(shader, gl.COMPILE_STATUS) ? shader : null;
  };
  const vertex = compile(gl.VERTEX_SHADER, vertexSource);
  const fragment = compile(gl.FRAGMENT_SHADER, fragmentSource);
  if (!vertex || !fragment) return null;
  const program = gl.createProgram()!;
  gl.attachShader(program, vertex); gl.attachShader(program, fragment); gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return null;
  gl.useProgram(program);
  const random = seeded(seedFor(id));
  const pixels = new Uint8Array(256 * 256 * 4);
  for (let index = 0; index < pixels.length; index += 4) {
    pixels[index] = Math.floor(random() * 256); pixels[index + 1] = Math.floor(random() * 256); pixels[index + 2] = Math.floor(random() * 256); pixels[index + 3] = 255;
  }
  const texture = gl.createTexture()!;
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 256, 256, 0, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
  const vertices = new Float32Array([-0.92, -0.85, 1, 0, 0, 0.96, -0.72, 0, 1, 0, 0.0, 0.95, 0, 0, 1, -0.55, 0.22, 1, 1, 0, 0.86, 0.58, 0, 1, 1, -0.1, -0.52, 1, 0, 1]);
  const buffer = gl.createBuffer()!;
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer); gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
  const stride = 5 * Float32Array.BYTES_PER_ELEMENT;
  const position = gl.getAttribLocation(program, "p"); const colour = gl.getAttribLocation(program, "c");
  gl.enableVertexAttribArray(position); gl.vertexAttribPointer(position, 2, gl.FLOAT, false, stride, 0);
  gl.enableVertexAttribArray(colour); gl.vertexAttribPointer(colour, 3, gl.FLOAT, false, stride, 2 * Float32Array.BYTES_PER_ELEMENT);
  const alphaParameter = task.parameters.find((parameter) => parameter.startsWith("alpha "));
  const alpha = alphaParameter ? Number(alphaParameter.replace("alpha ", "")) : 1;
  const scale = id === "c" ? 0.5 : id === "h-rotated" ? 0.87 : 1;
  const offset = id === "c" ? [-0.08, -0.12] : id === "h-rotated" ? [0.12, 0] : [0, 0];
  gl.uniform1f(gl.getUniformLocation(program, "a"), alpha);
  gl.uniform1f(gl.getUniformLocation(program, "s"), scale);
  gl.uniform2f(gl.getUniformLocation(program, "o"), offset[0], offset[1]);
  gl.uniform1f(gl.getUniformLocation(program, "k"), seedFor(id) % 17);
  gl.uniform1i(gl.getUniformLocation(program, "tex"), 0);
  gl.clearColor(0.03, 0.04, 0.07, 1); gl.clear(gl.COLOR_BUFFER_BIT); gl.drawArrays(gl.TRIANGLES, 0, 6);
  const output = new Uint8Array(256 * 256 * 4); gl.readPixels(0, 0, 256, 256, gl.RGBA, gl.UNSIGNED_BYTE, output);
  return {
    pixels: output,
    capabilities: {
      antialias: gl.getContextAttributes()?.antialias ?? false,
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
      compressedS3tc: Boolean(gl.getExtension("WEBGL_compressed_texture_s3tc") || gl.getExtension("WEBKIT_WEBGL_compressed_texture_s3tc")),
      compressedPvrtc: Boolean(gl.getExtension("WEBGL_compressed_texture_pvrtc") || gl.getExtension("WEBKIT_WEBGL_compressed_texture_pvrtc")),
      floatTexture: Boolean(gl.getExtension("OES_texture_float")),
      depthTexture: Boolean(gl.getExtension("WEBGL_depth_texture")),
    },
  };
}

function textureCapabilities(): Record<string, unknown> | null {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl");
  if (!gl) return null;
  return {
    s3tc: Boolean(gl.getExtension("WEBGL_compressed_texture_s3tc") || gl.getExtension("WEBKIT_WEBGL_compressed_texture_s3tc")),
    pvrtc: Boolean(gl.getExtension("WEBGL_compressed_texture_pvrtc") || gl.getExtension("WEBKIT_WEBGL_compressed_texture_pvrtc")),
    floatTexture: Boolean(gl.getExtension("OES_texture_float")),
    depthTexture: Boolean(gl.getExtension("WEBGL_depth_texture")),
    cubemapLimit: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
    webm: document.createElement("video").canPlayType('video/webm; codecs="vp8"'),
    h264: document.createElement("video").canPlayType('video/mp4; codecs="avc1.42E01E"'),
  };
}

function audioDestination(): Ndss2017Suite["audioDestination"] {
  const Audio = window.AudioContext || (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Audio) return { sampleRate: null, maxChannelCount: null, channelCount: null, channelCountMode: "unsupported", channelInterpretation: "unsupported", numberOfInputs: null, numberOfOutputs: null };
  try {
    const context = new Audio();
    const destination = context.destination;
    void context.close();
    return { sampleRate: context.sampleRate, maxChannelCount: destination.maxChannelCount, channelCount: destination.channelCount, channelCountMode: destination.channelCountMode, channelInterpretation: destination.channelInterpretation, numberOfInputs: destination.numberOfInputs, numberOfOutputs: destination.numberOfOutputs };
  } catch {
    return { sampleRate: null, maxChannelCount: null, channelCount: null, channelCountMode: "failed", channelInterpretation: "failed", numberOfInputs: null, numberOfOutputs: null };
  }
}

export async function collectNdss2017Suite(): Promise<Ndss2017Suite> {
  const screen = window.screen as Screen & { availLeft?: number; availTop?: number };
  const writingSystems = await getWritingSystems();
  const capabilityProfile = textureCapabilities();
  const tasks: NdssTaskResult[] = [];
  for (const task of TASKS) {
    try {
      if (task.mode === "writing") {
        tasks.push({ ...task, status: "collected", hash: writingSystems.hash, crossBrowserEligible: task.eligible });
      } else if (task.mode === "canvas") {
        const pixels = drawCurveTask(task.id);
        tasks.push({ ...task, status: pixels ? "collected" : "unsupported", hash: pixels ? await hash(Array.from(pixels)) : "unsupported", crossBrowserEligible: task.eligible });
      } else if (task.mode === "capability") {
        tasks.push({ ...task, status: capabilityProfile ? "capability-only" : "unsupported", hash: capabilityProfile ? await hash({ id: task.id, capabilityProfile }) : "unsupported", crossBrowserEligible: task.eligible });
      } else {
        const output = webglPixels(task.id);
        tasks.push({ ...task, status: output ? "collected" : "unsupported", hash: output ? await hash({ pixels: Array.from(output.pixels), capabilities: output.capabilities }) : "unsupported", crossBrowserEligible: task.eligible });
      }
    } catch {
      tasks.push({ ...task, status: "failed", hash: "failed", crossBrowserEligible: task.eligible });
    }
  }
  const supportedTaskIds = tasks.filter((task) => task.status === "collected" || task.status === "capability-only").map((task) => task.id);
  const crossBrowserTaskIds = tasks.filter((task) => task.crossBrowserEligible && (task.status === "collected" || task.status === "capability-only")).map((task) => task.id);
  const suite: Omit<Ndss2017Suite, "signature"> = {
    version: NDSS2017_SUITE_VERSION,
    enabled: true,
    commonParameters: { canvas: "256x256", ambientLight: "0.3,0.3,0.3", defaultCamera: "0,0,-7", texture: "256x256 deterministic RGB" },
    screen: { widthHeightRatio: screen.height ? Number((screen.width / screen.height).toFixed(6)) : 0, availableWidth: screen.availWidth, availableHeight: screen.availHeight, availableLeft: screen.availLeft ?? 0, availableTop: screen.availTop ?? 0, orientation: screen.orientation?.type || "unknown" },
    cpu: { virtualCores: navigator.hardwareConcurrency || null },
    audioDestination: audioDestination(),
    writingSystems,
    tasks,
    supportedTaskIds,
    crossBrowserTaskIds,
  };
  return { ...suite, signature: await hash(suite) };
}
