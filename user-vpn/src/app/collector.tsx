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

        const latency = await measureClientLatency();
        const devAddresses = process.env.NODE_ENV !== "production" && !networkResult.trusted ? await detectBrowserPublicIps() : null;

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
      } catch {
        // silent: a failed visit is simply not recorded
      }
    }
  }, []);

  return null;
}
