import "server-only";

import { createHmac } from "node:crypto";
import type { FingerprintData } from "./fingerprint";

export function protectFingerprintComponents(fingerprint: FingerprintData): Record<string, string> {
  const secret = process.env.FINGERPRINT_HMAC_SECRET;
  if (!secret) return { status: "unconfigured" };
  const schema = fingerprint.schemaVersion;
  const components: Record<string, unknown> = {
    browserSignature: fingerprint.signatures.browser,
    coarseDeviceSignature: fingerprint.signatures.coarseDevice,
    canvas: fingerprint.canvas.hash,
    webglParameters: fingerprint.webgl.parameterHash,
    webglRender: fingerprint.webgl.renderHash,
    fonts: [...fingerprint.fonts].sort(),
    capabilities: [...fingerprint.capabilities].sort(),
    mediaCapabilities: [...(fingerprint.mediaCapabilities || [])].sort(),
    audio: fingerprint.audio?.status === "collected" ? fingerprint.audio.hash : fingerprint.audio?.status,
  };
  return Object.fromEntries(Object.entries(components).map(([name, value]) => [name, hmac(secret, `${schema}:${name}:${stableStringify(value)}`)]));
}

function hmac(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
