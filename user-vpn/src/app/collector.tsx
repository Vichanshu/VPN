"use client";

import { useEffect, useRef } from "react";
import { generateClientFingerprint, type ObservationSubmission } from "@/utils/fingerprint";
import { collectConsentedLocation, collectNetworkPathProbes, detectBrowserPublicIps, measureClientLatency, type ServerNetworkData } from "@/utils/network";
import { startPointerObserver } from "@/utils/modern-signals";

const VISITOR_KEY = "vpn-study-visitor-id";

/** A random, anonymous per-browser id so repeat visits from one device share a label. */
function visitorLabel(): string {
  let id = "";
  try {
    id = localStorage.getItem(VISITOR_KEY) || "";
    if (!id) {
      id = crypto.randomUUID().slice(0, 8);
      localStorage.setItem(VISITOR_KEY, id);
    }
  } catch {
    id = crypto.randomUUID().slice(0, 8); // storage blocked: this visit is its own device label
  }
  return `Visitor ${id}`;
}

type PointerGlobal = typeof globalThis & { __fpPointerIntervals?: number[] };

async function pageIdle(): Promise<void> {
  if (document.readyState !== "complete") await new Promise<void>((resolve) => window.addEventListener("load", () => resolve(), { once: true }));
  await new Promise((resolve) => window.setTimeout(resolve, 400));
}

async function waitForPointerActivity(maximumMs = 4_000): Promise<void> {
  const started = performance.now();
  while (performance.now() - started < maximumMs && ((globalThis as PointerGlobal).__fpPointerIntervals?.length ?? 0) < 40) {
    await new Promise((resolve) => window.setTimeout(resolve, 100));
  }
}

/** Collects and submits silently on load; renders nothing. */
export default function Collector() {
  const started = useRef(false);

  useEffect(() => startPointerObserver(), []);

  useEffect(() => {
    if (started.current) return; // React strict mode runs effects twice in dev
    started.current = true;
    void collectAndSubmit();

    async function collectAndSubmit() {
      try {
        const networkResponse = await fetch("/api/fingerprint", { cache: "no-store" });
        if (!networkResponse.ok) return;
        const networkResult = await networkResponse.json() as ServerNetworkData;

        // Let the page finish loading so fonts and hydration do not inflate the round-trip times.
        await pageIdle();
        const latency = await measureClientLatency();
        const devAddresses = process.env.NODE_ENV !== "production" && !networkResult.trusted ? await detectBrowserPublicIps() : null;

        // The pointer-rate signal needs about 40 mouse movements, which a person scanning from a button supplies. Wait briefly for them.
        await waitForPointerActivity();
        const [fingerprint, pathProbes, deviceLocation] = await Promise.all([
          generateClientFingerprint({ stunUrl: networkResult.probeConfiguration?.stunUrl, highEntropyResearch: true, hardwareTimingProbes: true, latencyLandmarks: true }),
          collectNetworkPathProbes(networkResult.probeConfiguration),
          collectConsentedLocation(true),
        ]);

        const submission: ObservationSubmission = {
          deviceLabel: visitorLabel(),
          browserMode: "unknown",
          vpnGroundTruth: "unknown",
          fingerprint,
          pathProbes,
          deviceLocation,
          highEntropyResearch: true,
          hardwareTimingProbes: true,
          latencyLandmarks: true,
          consentAcknowledged: true,
          clientLatency: latency,
          studyId: "public-visitors",
          groundTruthDetails: { providerCode: "", protocol: "", exitCountry: "" },
          scanChallenge: networkResult.scanChallenge || "",
          ...(devAddresses && (devAddresses.ipv4 || devAddresses.ipv6) ? { devPublicIp: devAddresses.ipv4 || devAddresses.ipv6 || undefined } : {}),
        };

        await fetch("/api/observations", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(submission),
        });
      } catch (error) {
        // the page stays blank for visitors; the console is the only trace of a failed visit
        console.error("[collector]", error);
      }
    }
  }, []);

  return null;
}
