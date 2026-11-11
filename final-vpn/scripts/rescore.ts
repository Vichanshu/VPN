/**
 * Recomputes the stored VPN assessment of every scan with the
 * device-anchored VPN model, replaying scans in capture order so each one
 * only sees the scans that existed before it (as the live API does), and
 * prints how each signal behaves on the labelled scans.
 *
 * Current, archived and original-prototype scans are each replayed within
 * their own table, so archived scans are never compared with current ones.
 *
 * Usage:
 *   npm run rescore             dry run: evaluation + old vs new scores
 *   npm run rescore -- --apply  backs up vpn_assessment, then updates it
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { isIP } from "node:net";
import type { ResearchObservation } from "../src/utils/fingerprint.ts";
import type { ServerNetworkData } from "../src/utils/network.ts";
import { checkReputation, loadIpLists } from "../src/utils/ip-lists.ts";
import { groupSameDevice, linkObservations, scoreAllPairs, trainLinkageModel } from "../src/utils/linkage.ts";
import { assessVpn } from "../src/utils/vpn-detection.ts";

const require = createRequire(import.meta.url);
const { Client } = require("pg") as typeof import("pg");
const TABLES = [
  { name: "public.vpn_ndss2017_research_observations", dataset: "current" },
  { name: "public.vpn_linkage_archived_observations", dataset: "archived" },
  { name: "public.vpn_research_observations", dataset: "prototype" },
];

function databaseUrl(): string {
  const fromEnv = process.env.DATABASE_URL_POOLER || process.env.DATABASE_URL;
  if (fromEnv) return fromEnv;
  const file = readFileSync(".env.local", "utf8");
  const match = file.match(/^DATABASE_URL_POOLER=(.+)$/m) || file.match(/^DATABASE_URL=(.+)$/m);
  if (!match) throw new Error("No DATABASE_URL_POOLER or DATABASE_URL configured");
  return match[1].trim();
}

/**
 * The first prototype stored only the public IP its page fetched, without
 * the server network block. Rebuild a minimal, untrusted one from that IP so
 * reputation lists and device history still apply to those scans.
 */
function reportedNetwork(observation: ResearchObservation): ServerNetworkData {
  const ip = observation.effectivePublicIp;
  const version = isIP(ip);
  const [a, b] = ip.split(".").map(Number);
  const privateV4 = a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  const privateV6 = /^(::1$|fe80:|fc|fd)/i.test(ip);
  return {
    ip,
    ipFamily: version === 4 ? "ipv4" : version === 6 ? "ipv6" : "unknown",
    isPublicIp: version === 4 ? !privateV4 : version === 6 ? !privateV6 : false,
    source: "browser-reported",
    trusted: false,
    trustNotice: "Public IP reported by the page, not seen by the server.",
    receivedAt: observation.serverReceivedAt || "",
    headers: {},
    geoIp: null,
    anonymizer: { isAnonymousVpn: null, isHostingProvider: null, isPublicProxy: null, isResidentialProxy: null, isTorExitNode: null, providerName: "", confidence: null, networkLastSeen: "", source: "public-lists" },
    ja4: "",
    httpProtocol: "",
  };
}

const apply = process.argv.includes("--apply");
const client = new Client({ connectionString: databaseUrl(), ssl: { rejectUnauthorized: false } });
await client.connect();
try {
  const lists = await loadIpLists();
  console.log(`Reputation lists loaded: ${Object.keys(lists).join(", ") || "none"}`);
  const prior = Number(process.env.VPN_RISK_PRIOR) > 0 ? Number(process.env.VPN_RISK_PRIOR) : 0.05;
  const observations: Array<ResearchObservation & { dataset: string }> = [];
  const rows: Array<{ table: string; observation_id: string; vpn_assessment: unknown }> = [];
  const updates: Array<{ table: string; id: string; risk: NonNullable<ResearchObservation["riskAssessment"]> }> = [];

  for (const table of TABLES) {
    // A fresh database (for example the visitor study) has no archive or prototype table.
    const exists = (await client.query("SELECT to_regclass($1) AS name", [table.name])).rows[0].name;
    if (!exists) {
      console.log(`Skipping ${table.name}: table does not exist`);
      continue;
    }
    // Same additive migration the app runs on startup.
    await client.query(`ALTER TABLE ${table.name} ADD COLUMN IF NOT EXISTS vpn_assessment jsonb`);
    const hasLatency = table.dataset !== "prototype";
    const result = await client.query(`
      SELECT observation_id, device_label, browser_mode, vpn_ground_truth, fingerprint, server_seen_ip,
             effective_public_ip, server_received_at, server_network, path_probes, device_location,
             risk_assessment, vpn_assessment, ${hasLatency ? "client_latency, study_id" : "NULL AS client_latency, NULL AS study_id"}, created_at
        FROM ${table.name} ORDER BY created_at ASC`);
    const tableObservations = result.rows.map((row) => ({
      dataset: table.dataset,
      observationId: row.observation_id,
      deviceLabel: row.device_label,
      browserMode: row.browser_mode,
      vpnGroundTruth: row.vpn_ground_truth,
      fingerprint: row.fingerprint,
      serverSeenIp: row.server_seen_ip,
      effectivePublicIp: row.effective_public_ip,
      serverReceivedAt: row.server_received_at ? new Date(row.server_received_at).toISOString() : undefined,
      serverNetwork: row.server_network || undefined,
      pathProbes: row.path_probes || [],
      deviceLocation: row.device_location,
      riskAssessment: row.vpn_assessment || row.risk_assessment || undefined,
      clientLatency: row.client_latency || null,
      studyId: row.study_id || undefined,
    })) as Array<ResearchObservation & { dataset: string }>;
    rows.push(...result.rows.map((row) => ({ table: table.name, observation_id: row.observation_id, vpn_assessment: row.vpn_assessment })));

    tableObservations.forEach((observation, index) => {
      const network = observation.serverNetwork || reportedNetwork(observation);
      // Earlier scans of the same table, newest first, as recentObservations() returns them.
      const previous = tableObservations.slice(0, index).reverse();
      // Public visitors have no real device name, so they are scored but never train the model (as in linkage-service.ts).
      const model = trainLinkageModel(previous.filter((item) => item.studyId !== "public-visitors"), { maxObservations: 400, maxDifferentPairs: 30_000 });
      const deviceIds = new Map<string, string>();
      for (const set of groupSameDevice(scoreAllPairs(previous, model), 0.85, 3, true)) for (const id of set.observationIds) deviceIds.set(id, set.clusterId);
      const linked = previous.map((earlier) => ({ previous: earlier, linkage: linkObservations(observation, earlier, model) })).filter((item) => item.linkage.verdict !== "insufficient-evidence");
      const best = [...linked].sort((a, b) => b.linkage.posterior - a.linkage.posterior)[0];
      const deviceId = best && best.linkage.posterior > 0.5 ? deviceIds.get(best.previous.observationId) : undefined;
      const history = linked.filter((item) => item.linkage.posterior >= 0.85 || (deviceId !== undefined && deviceIds.get(item.previous.observationId) === deviceId)).map((item) => item.previous);
      // Stored scans predate the list lookup, so attach it as the live server would have.
      const current = { ...observation, serverNetwork: { ...network, anonymizer: { ...network.anonymizer, lists: checkReputation(lists, network.ip || observation.effectivePublicIp) } } };
      const risk = assessVpn({
        current,
        deviceHistory: history,
        currentDeviceId: deviceId,
        population: previous.map((item) => ({ observation: item, deviceId: deviceIds.get(item.observationId) || item.observationId })),
        reputationOf: (ip) => checkReputation(lists, ip),
        priorProbability: prior,
      });
      updates.push({ table: table.name, id: observation.observationId, risk });
      observation.riskAssessment = risk; // later scans see this verdict, as live
    });
    observations.push(...tableObservations);
  }

  /* Evaluation on labelled scans ------------------------------------------ */
  const labelled = observations
    .map((observation) => ({ observation, risk: updates.find((item) => item.id === observation.observationId)?.risk }))
    .filter((item) => item.risk && ["none", "off", "consumer-vpn", "corporate-vpn", "split-tunnel", "tor", "public-proxy", "residential-proxy", "private-relay", "on"].includes(item.observation.vpnGroundTruth));
  const positive = (value: string) => !["none", "off"].includes(value);
  const vpnScans = labelled.filter((item) => positive(item.observation.vpnGroundTruth));
  const cleanScans = labelled.filter((item) => !positive(item.observation.vpnGroundTruth));
  console.log(`\nLabelled scans: ${vpnScans.length} with VPN/proxy, ${cleanScans.length} without\n`);
  for (const dataset of ["current", "archived", "prototype"]) {
    const vpnIn = vpnScans.filter((item) => item.observation.dataset === dataset);
    const cleanIn = cleanScans.filter((item) => item.observation.dataset === dataset);
    console.log(`${dataset.padEnd(10)} caught ${vpnIn.filter((item) => item.risk!.probability >= 0.5).length}/${vpnIn.length}, false alarms ${cleanIn.filter((item) => item.risk!.probability >= 0.5).length}/${cleanIn.length}`);
  }
  for (const threshold of [0.35, 0.5, 0.85]) {
    const caught = vpnScans.filter((item) => item.risk!.probability >= threshold).length;
    const falseAlarms = cleanScans.filter((item) => item.risk!.probability >= threshold).length;
    console.log(`at ${Math.round(threshold * 100)}%: caught ${caught}/${vpnScans.length} VPN scans, false alarms ${falseAlarms}/${cleanScans.length}`);
  }
  const ids = Array.from(new Set(labelled.flatMap((item) => item.risk!.evidence.map((evidence) => evidence.id))));
  console.log("\nsignal                      fired on VPN   fired on no-VPN");
  for (const id of ids.sort()) {
    const onVpn = vpnScans.filter((item) => item.risk!.evidence.some((evidence) => evidence.id === id)).length;
    const onClean = cleanScans.filter((item) => item.risk!.evidence.some((evidence) => evidence.id === id)).length;
    console.log(`${id.padEnd(28)}${`${onVpn}/${vpnScans.length}`.padEnd(15)}${onClean}/${cleanScans.length}`);
  }
  console.log("\nVPN scans:");
  for (const item of vpnScans) console.log(`  ${item.observation.dataset.padEnd(10)} ${item.observation.deviceLabel.padEnd(24)} ${String(item.risk!.score).padStart(3)}% ${item.risk!.kind?.padEnd(13)} ${item.risk!.evidence.filter((evidence) => evidence.logLikelihoodRatio > 0).map((evidence) => evidence.id).join(", ")}`);
  const unlabelled = observations.filter((item) => !labelled.some((entry) => entry.observation === item) && item.riskAssessment && item.riskAssessment.probability >= 0.5);
  if (unlabelled.length) {
    console.log("\nUnlabelled scans the model thinks used a VPN:");
    for (const item of unlabelled) console.log(`  ${item.dataset.padEnd(10)} ${item.deviceLabel.padEnd(24)} ${String(item.riskAssessment!.score).padStart(3)}% ${item.effectivePublicIp}`);
  }

  if (!apply) {
    console.log(`\nDry run: ${updates.length} scans would be updated. Re-run with --apply to write.`);
  } else {
    mkdirSync(".research-data/backups", { recursive: true });
    const backup = `.research-data/backups/risk-before-vpn-model-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    writeFileSync(backup, JSON.stringify(rows, null, 2));
    await client.query("BEGIN");
    for (const update of updates) {
      // Only this app's column: the original app's risk_assessment is left alone.
      await client.query(`UPDATE ${update.table} SET vpn_assessment = $2::jsonb WHERE observation_id = $1`, [update.id, JSON.stringify(update.risk)]);
    }
    await client.query("COMMIT");
    console.log(`\nUpdated ${updates.length} scans. Previous values backed up to ${backup}`);
  }
} catch (error) {
  await client.query("ROLLBACK").catch(() => undefined);
  throw error;
} finally {
  await client.end();
}
