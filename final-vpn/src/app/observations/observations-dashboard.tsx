"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Archive, ArrowLeft, BarChart3, GitCompare, Layers, Loader2, Lock, RefreshCw, Search, Table2 } from "lucide-react";
import type { ResearchObservation } from "@/utils/fingerprint";
import { evaluateStoredModel } from "@/utils/evaluation";
import type { ArchivedObservation } from "@/utils/research-store";
import { browserOf, groupSameDevice, linkObservations, scoreAllPairs, type LinkageModel, type LinkageResult, type PairPosteriors } from "@/utils/linkage";
import { Card, Disclosure, DivergingBar, Empty, Pill, Row, inputClass, toneText, type Tone } from "@/components/ui";

type Dataset = "current" | "archived" | "prototype";
type Scope = "all" | Dataset;

/** A scan is listed as "similar to" another when the model is at least this sure they are the same device. */
const SIMILAR_MIN = 0.5;
interface SimilarScan { item: ResearchObservation; posterior: number }

const SCOPES: Array<{ id: Scope; label: string }> = [
  { id: "all", label: "All saved data" },
  { id: "current", label: "Current set" },
  { id: "archived", label: "Archived" },
  { id: "prototype", label: "Original prototype" },
];

export default function ObservationsDashboard({ initialObservations, legacyObservations, linkageModel, archivedObservations, archiveEnabled }: {
  initialObservations: ResearchObservation[];
  legacyObservations: ResearchObservation[];
  linkageModel: LinkageModel;
  archivedObservations: ArchivedObservation[];
  archiveEnabled: boolean;
}) {
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<Scope>("all");
  // Earlier scans are shown and evaluated for VPN detection, but device
  // linking below only ever compares scans of the current set.
  const datasetOf = useMemo(() => {
    const map = new Map<string, Dataset>();
    for (const item of legacyObservations) map.set(item.observationId, "prototype");
    for (const item of archivedObservations) map.set(item.observationId, "archived");
    for (const item of initialObservations) map.set(item.observationId, "current");
    return map;
  }, [initialObservations, archivedObservations, legacyObservations]);
  const everything = useMemo(() => [...initialObservations, ...archivedObservations, ...legacyObservations], [initialObservations, archivedObservations, legacyObservations]);
  const scoped = useMemo(() => scope === "all" ? everything : everything.filter((item) => datasetOf.get(item.observationId) === scope), [everything, datasetOf, scope]);
  const [firstId, setFirstId] = useState(initialObservations[0]?.observationId || "");
  const [secondId, setSecondId] = useState(initialObservations[1]?.observationId || initialObservations[0]?.observationId || "");

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return scoped;
    return scoped.filter((item) => [
      item.deviceLabel, item.fingerprint.browserFamily, item.fingerprint.osFamily, item.effectivePublicIp,
      item.serverNetwork?.geoIp?.country, item.serverNetwork?.geoIp?.org, item.vpnGroundTruth,
    ].some((value) => String(value || "").toLowerCase().includes(term)));
  }, [scoped, search]);

  const labels = new Set(scoped.map((item) => item.deviceLabel)).size;
  const browsers = new Set(scoped.map((item) => item.fingerprint.browserFamily)).size;
  const ips = new Set(scoped.map((item) => item.effectivePublicIp).filter((value) => value && value !== "Unknown")).size;
  const first = initialObservations.find((item) => item.observationId === firstId) || null;
  const second = initialObservations.find((item) => item.observationId === secondId) || null;
  const comparison = first && second && first !== second ? linkObservations(first, second, linkageModel) : null;
  // Every pair of current scans is scored once; the sets, and each scan's "similar to" list, share it.
  const pairs = useMemo(() => scoreAllPairs(initialObservations, linkageModel), [initialObservations, linkageModel]);
  const similarTo = useMemo(() => {
    const map = new Map<string, SimilarScan[]>();
    const size = pairs.observations.length;
    pairs.observations.forEach((item, row) => {
      const others: SimilarScan[] = [];
      for (let column = 0; column < size; column += 1) {
        const posterior = pairs.posteriors[row * size + column];
        if (column !== row && posterior >= SIMILAR_MIN) others.push({ item: pairs.observations[column], posterior });
      }
      map.set(item.observationId, others.sort((a, b) => b.posterior - a.posterior).slice(0, 5));
    });
    return map;
  }, [pairs]);

  return (
    <main className="min-h-screen bg-canvas">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <Link href="/" className="font-serif text-lg text-ink">VPN Detection Lab</Link>
          <div className="flex items-center gap-1 text-sm">
            <Link href="/" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium text-ink hover:bg-surface-2"><ArrowLeft className="h-3.5 w-3.5" /> Scanner</Link>
            <button type="button" onClick={() => window.location.reload()} className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium text-ink hover:bg-surface-2"><RefreshCw className="h-3.5 w-3.5" /> Refresh</button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-5xl space-y-4 px-4 pb-16 pt-10 sm:px-6">
        <section className="mb-4">
          <h1 className="font-serif text-4xl text-ink">Saved data</h1>
          <p className="mt-2 text-muted">How well VPNs are detected, how scans link to devices, and every scan.</p>
        </section>

        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Which scans to show">
          {SCOPES.map((option) => {
            const count = option.id === "all" ? everything.length : everything.filter((item) => datasetOf.get(item.observationId) === option.id).length;
            return (
              <button key={option.id} type="button" onClick={() => setScope(option.id)} aria-pressed={scope === option.id}
                className={`rounded-lg border px-3 py-1.5 text-sm transition ${scope === option.id ? "border-accent bg-accent-soft text-ink" : "border-line text-ink-2 hover:bg-surface-2"}`}>
                {option.label} <span className="text-muted">{count}</span>
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Scans" value={scoped.length} />
          <Stat label="Named devices" value={labels} />
          <Stat label="Browsers" value={browsers} />
          <Stat label="Public IPs" value={ips} />
        </div>

        <VpnDetectionPanel observations={scoped} datasetOf={datasetOf} />

        <SameDeviceSets observations={initialObservations} pairs={pairs} />

        <Disclosure title="Compare two scans" hint="Pick any pair to see the reasoning" icon={<GitCompare className="h-4 w-4" />}>
          <div className="grid gap-3 sm:grid-cols-2">
            <ScanSelect value={firstId} onChange={setFirstId} observations={initialObservations} />
            <ScanSelect value={secondId} onChange={setSecondId} observations={initialObservations} />
          </div>
          {comparison && first && second ? <ComparisonView result={comparison} sameName={first.deviceLabel === second.deviceLabel} /> : <Empty>Choose two different scans.</Empty>}
        </Disclosure>

        <Disclosure title="All scans" hint={`${scoped.length} rows · ${SCOPES.find((option) => option.id === scope)!.label.toLowerCase()}`} icon={<Table2 className="h-4 w-4" />}>
          <label className="relative mb-3 block">
            <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted" />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, browser, IP, country…" className={`${inputClass} pl-9`} />
          </label>
          {filtered.length === 0 ? <Empty>Nothing matches.</Empty> : (
            <div className="divide-y divide-line">
              {filtered.map((item) => <ScanRow key={item.observationId} item={item} dataset={datasetOf.get(item.observationId)} similar={similarTo.get(item.observationId)} />)}
            </div>
          )}
        </Disclosure>


        <ArchivedBatches rows={archivedObservations} />

        <FreshStart enabled={archiveEnabled} activeCount={initialObservations.length} />


      </div>
    </main>
  );
}

function ScanRow({ item, dataset, similar }: { item: ResearchObservation; dataset?: Dataset; similar?: SimilarScan[] }) {
  const risk = item.riskAssessment;
  return (
    <details className="group py-2.5">
      <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2">
        <span className="text-sm text-ink"><span className="font-medium">{item.deviceLabel}</span> <span className="text-muted">· {item.fingerprint.browserFamily}{item.browserMode === "private" ? " (private)" : ""} · {formatTimestamp(item.serverReceivedAt || item.fingerprint.collectedAt)}</span></span>
        <span className="flex gap-1.5">
          {similar !== undefined && <Pill tone={similar.length ? "accent" : "neutral"}>{similar.length ? `similar to ${similar.length}` : "unique"}</Pill>}
          {dataset && dataset !== "current" && <Pill>{dataset === "archived" ? "archived" : "prototype"}</Pill>}
          {item.vpnGroundTruth !== "unknown" && <Pill tone={["none", "off"].includes(item.vpnGroundTruth) ? "neutral" : "accent"}>{item.vpnGroundTruth}</Pill>}
          {risk && (risk.band === "unknown"
            ? <Pill>VPN: not enough data</Pill>
            : <Pill tone={risk.band === "high" ? "bad" : risk.band === "elevated" ? "warn" : "neutral"}>VPN {risk.score}%</Pill>)}
        </span>
      </summary>
      <div className="mt-2 grid gap-x-8 rounded-xl bg-surface-2/50 px-4 py-2 sm:grid-cols-2">
        <Row label="VPN likelihood" value={risk ? (risk.band === "unknown" ? "not enough data" : `${risk.score}% · ${risk.headline}`) : "not scored"} />
        <Row label="Similar devices" value={similar === undefined ? "only current-set scans are compared" : similar.length ? `${similar.length} found` : "none, looks unique"} />
        {similar?.map(({ item: other, posterior }) => (
          <Row key={other.observationId} label={`${other.deviceLabel} · ${browserOf(other.fingerprint)}`} value={`${formatShare(posterior)} same device${other.riskAssessment && other.riskAssessment.band !== "unknown" ? ` · VPN ${other.riskAssessment.score}%` : ""}`} />
        ))}
        <Row label="System" value={`${item.fingerprint.osFamily} · ${item.fingerprint.browserFamily} ${item.fingerprint.browserMajor}`} />
        <Row label="IP" value={item.effectivePublicIp} mono />
        <Row label="Location" value={item.serverNetwork?.geoIp ? `${item.serverNetwork.geoIp.city}, ${item.serverNetwork.geoIp.country}` : "unavailable"} />
        <Row label="Network" value={item.serverNetwork?.geoIp?.org || "unavailable"} />
        <Row label="Screen / GPU" value={`${item.fingerprint.screen.width}×${item.fingerprint.screen.height} · ${item.fingerprint.modern?.gpu.rendererTokens.join(" ") || item.fingerprint.webgl.rendererFamily}`} />
        <Row label="Schema" value={item.fingerprint.schemaVersion} />
      </div>
    </details>
  );
}

function ArchivedBatches({ rows }: { rows: ArchivedObservation[] }) {
  const batches = useMemo(() => {
    const groups = new Map<string, ArchivedObservation[]>();
    for (const row of rows) groups.set(row.archiveBatchId, [...(groups.get(row.archiveBatchId) || []), row]);
    return Array.from(groups.entries()).map(([id, items]) => ({ id, archivedAt: items[0].archivedAt, items }));
  }, [rows]);
  return (
    <Disclosure title="Archived scans" hint={rows.length ? `${rows.length} scans in ${batches.length} archived set${batches.length === 1 ? "" : "s"} · view only, never compared` : "Nothing archived yet"} icon={<Archive className="h-4 w-4" />}>
      {batches.length === 0 ? <Empty>When you start a fresh comparison set, earlier scans appear here.</Empty> : (
        <div className="space-y-3">
          {batches.map((batch) => (
            <details key={batch.id} className="rounded-xl border border-line px-4 py-2">
              <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2 py-1 text-sm">
                <span className="text-ink">Archived {formatTimestamp(batch.archivedAt)}</span>
                <Pill>{batch.items.length} scans · {new Set(batch.items.map((item) => item.deviceLabel)).size} devices</Pill>
              </summary>
              <div className="divide-y divide-line">{batch.items.map((item) => <ScanRow key={item.observationId} item={item} />)}</div>
            </details>
          ))}
        </div>
      )}
    </Disclosure>
  );
}

function FreshStart({ enabled, activeCount }: { enabled: boolean; activeCount: number }) {
  const [password, setPassword] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: Tone; text: string } | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!password || !confirmed) return;
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/archive", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password, confirm: true }),
      });
      const body = await response.json().catch(() => ({})) as { error?: string; archived?: number; retryAfterSeconds?: number };
      if (response.ok) {
        setMessage({ tone: "good", text: `Archived ${body.archived ?? 0} scans. New scans now start a fresh comparison set.` });
        setPassword("");
        window.setTimeout(() => window.location.reload(), 1_500);
      } else if (response.status === 429) {
        setMessage({ tone: "bad", text: `Too many attempts. Try again in about ${formatWait(body.retryAfterSeconds ?? 900)}.` });
      } else {
        setMessage({ tone: "bad", text: body.error || "Request refused." });
      }
    } catch {
      setMessage({ tone: "bad", text: "Could not reach the server." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Disclosure title="Start a fresh comparison set" hint="Password protected · moves current scans to the archive" icon={<Lock className="h-4 w-4" />}>
      {!enabled ? <Empty>Disabled: set ARCHIVE_PASSWORD_HASH in the server environment (run npm run hash-password).</Empty> : (
        <form onSubmit={submit} className="space-y-4">
          <p className="text-sm leading-6 text-ink-2">
            All {activeCount} current scans move to <span className="text-ink">Archived scans</span>. They stay visible there, but new scans will no longer be compared with them.
            Nothing is deleted.
          </p>
          <label className="block space-y-1.5">
            <span className="block text-sm font-medium text-ink">Admin password</span>
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" maxLength={200} className={inputClass} />
          </label>
          <label className="flex cursor-pointer items-start gap-3 text-sm">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-0.5 h-4 w-4 accent-[var(--accent)]" />
            <span className="text-ink-2">I understand that current scans will stop being used for matching.</span>
          </label>
          <button type="submit" disabled={busy || !password || !confirmed} className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-medium text-white transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-50">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Archive className="h-4 w-4" />} Archive and start fresh
          </button>
          {message && <p className={`rounded-xl px-4 py-3 text-sm ${message.tone === "good" ? "bg-good-soft text-good" : "bg-bad-soft text-bad"}`}>{message.text}</p>}
          <p className="text-xs leading-5 text-muted">Five wrong passwords lock this action for 15 minutes, doubling each time up to 24 hours.</p>
        </form>
      )}
    </Disclosure>
  );
}

function formatWait(seconds: number): string {
  if (seconds < 90) return `${seconds} seconds`;
  if (seconds < 5_400) return `${Math.ceil(seconds / 60)} minutes`;
  return `${Math.ceil(seconds / 3_600)} hours`;
}

const THRESHOLDS = [0.7, 0.8, 0.85, 0.9, 0.95, 0.99];

const POSITIVE_LABELS = new Set(["consumer-vpn", "corporate-vpn", "split-tunnel", "tor", "public-proxy", "residential-proxy", "private-relay", "on"]);
const NEGATIVE_LABELS = new Set(["none", "off"]);

/** How the VPN model and each of its signals behave on labelled scans. */
function VpnDetectionPanel({ observations, datasetOf }: { observations: ResearchObservation[]; datasetOf: Map<string, Dataset> }) {
  const withLabel = observations.filter((item) => item.riskAssessment && (POSITIVE_LABELS.has(item.vpnGroundTruth) || NEGATIVE_LABELS.has(item.vpnGroundTruth)));
  // Scans the model abstained on (e.g. saved without any IP address) are reported, not scored as misses.
  const labelled = withLabel.filter((item) => item.riskAssessment!.band !== "unknown");
  const unscored = withLabel.length - labelled.length;
  const withoutIp = withLabel.filter((item) => item.riskAssessment!.band === "unknown" && !/[.:]/.test(item.effectivePublicIp || "")).length;
  const evaluation = evaluateStoredModel(labelled);
  const missed = labelled.filter((item) => POSITIVE_LABELS.has(item.vpnGroundTruth) && item.riskAssessment!.probability < 0.5);
  const vpn = labelled.filter((item) => POSITIVE_LABELS.has(item.vpnGroundTruth));
  const clean = labelled.filter((item) => NEGATIVE_LABELS.has(item.vpnGroundTruth));
  const caught = vpn.filter((item) => item.riskAssessment!.probability >= 0.5).length;
  const falseAlarms = clean.filter((item) => item.riskAssessment!.probability >= 0.5).length;
  const signals = new Map<string, { label: string; onVpn: number; onClean: number; weight: number }>();
  for (const item of labelled) {
    for (const evidence of item.riskAssessment!.evidence) {
      const entry = signals.get(evidence.id) || { label: evidence.label, onVpn: 0, onClean: 0, weight: evidence.logLikelihoodRatio };
      if (POSITIVE_LABELS.has(item.vpnGroundTruth)) entry.onVpn += 1;
      else entry.onClean += 1;
      signals.set(evidence.id, entry);
    }
  }
  const flaggedUnlabelled = observations.filter((item) => item.vpnGroundTruth === "unknown" && (item.riskAssessment?.probability ?? 0) >= 0.5);
  return (
    <>
      <Card className="p-5">
        <p className="text-sm text-muted">How well does VPN detection work on your labelled scans?</p>
        {vpn.length && clean.length ? (
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            <Headline value={`${caught}/${vpn.length}`} label="VPN scans caught (≥ 50%)" tone={caught === vpn.length ? "good" : caught / vpn.length >= 0.7 ? "warn" : "bad"} />
            <Headline value={`${falseAlarms}/${clean.length}`} label="False alarms on no-VPN scans" tone={falseAlarms === 0 ? "good" : falseAlarms / clean.length <= 0.05 ? "warn" : "bad"} />
            <Headline value={formatRate(evaluation.prAuc)} label="PR-AUC (ranking quality)" tone={toneFor(evaluation.prAuc, 0.9, 0.7)} />
          </div>
        ) : <p className="mt-2 text-sm text-ink-2">Label some scans as “No VPN” and some with a VPN type to measure detection.</p>}
        {unscored > 0 && (
          <p className="mt-3 text-xs text-muted">
            {unscored} labelled scan{unscored === 1 ? " has" : "s have"} too little data for a verdict and {unscored === 1 ? "is" : "are"} left out
            {withoutIp > 0 ? ` (${withoutIp} saved without any IP address; the rest are old scans with only an IP and no history)` : ""}.
          </p>
        )}
      </Card>
      <Disclosure title="VPN signals" hint="Which signals fired on VPN and no-VPN scans" icon={<BarChart3 className="h-4 w-4" />}>
        {signals.size === 0 ? <Empty>No labelled scans yet.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-xs text-muted"><tr className="border-b border-line"><th className="py-2 pr-3 font-medium">Signal</th><th className="px-3 py-2 font-medium">Weight</th><th className="px-3 py-2 font-medium">On VPN scans</th><th className="px-3 py-2 font-medium">On no-VPN scans</th></tr></thead>
              <tbody>
                {Array.from(signals.entries()).sort((a, b) => b[1].weight - a[1].weight).map(([id, entry]) => (
                  <tr key={id} className="border-b border-line last:border-0">
                    <td className="py-2 pr-3 text-ink">{entry.label}</td>
                    <td className={`px-3 py-2 font-mono text-xs ${entry.weight >= 0 ? "text-bad" : "text-good"}`}>{entry.weight >= 0 ? "+" : ""}{entry.weight.toFixed(1)}</td>
                    <td className="px-3 py-2 font-mono text-xs">{entry.onVpn}/{vpn.length}</td>
                    <td className="px-3 py-2 font-mono text-xs">{entry.onClean}/{clean.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-4 space-y-1">
          <Row label="Precision at 50%" value={formatRate(evaluation.precision)} />
          <Row label="Recall at 50%" value={formatRate(evaluation.recall)} />
          <Row label="Brier score (lower is better)" value={evaluation.brierScore === null ? "n/a" : evaluation.brierScore.toFixed(3)} />
        </div>
        {missed.length > 0 && (
          <div className="mt-4">
            <p className="mb-1 text-sm font-medium text-ink">VPN scans the model missed</p>
            {missed.map((item) => <Row key={item.observationId} label={`${item.deviceLabel} · ${item.fingerprint.browserFamily}${datasetOf.get(item.observationId) === "current" ? "" : ` · ${datasetOf.get(item.observationId)}`}`} value={`${item.riskAssessment!.score}% · ${item.effectivePublicIp}`} />)}
          </div>
        )}
        {flaggedUnlabelled.length > 0 && (
          <div className="mt-4">
            <p className="mb-1 text-sm font-medium text-ink">Unlabelled scans the model thinks used a VPN</p>
            {flaggedUnlabelled.map((item) => <Row key={item.observationId} label={`${item.deviceLabel} · ${item.fingerprint.browserFamily}${datasetOf.get(item.observationId) === "current" ? "" : ` · ${datasetOf.get(item.observationId)}`}`} value={`${item.riskAssessment!.score}% · ${item.effectivePublicIp}`} />)}
          </div>
        )}
        <p className="mt-3 text-xs leading-5 text-muted">Weights are log-likelihood ratios from the research literature (red raises VPN likelihood, green lowers it). Scans from before latency landmarks, IP geolocation and WebRTC were collected can only show the network, reputation and device-history signals. Archived and prototype scans are scored only against earlier scans of their own set; original-prototype scans use the public IP their page reported.</p>
      </Disclosure>
    </>
  );
}

/**
 * Distinct physical devices at a chosen confidence: scans whose same-device
 * likelihood clears the threshold are grouped into one set.
 */
function SameDeviceSets({ observations, pairs }: { observations: ResearchObservation[]; pairs: PairPosteriors }) {
  const [threshold, setThreshold] = useState(0.85);
  const [joinClosest, setJoinClosest] = useState(true);
  const sets = useMemo(() => groupSameDevice(pairs, threshold, 3, joinClosest), [pairs, threshold, joinClosest]);
  const byId = useMemo(() => new Map(pairs.observations.map((item) => [item.observationId, item])), [pairs]);
  const multi = sets.filter((set) => set.observationIds.length > 1);
  const singles = sets.length - multi.length;
  const names = new Set(observations.map((item) => item.deviceLabel)).size;

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted"><Layers className="h-4 w-4 text-accent" /> Same-device sets</p>
          <p className="mt-2 font-serif text-3xl text-ink">{sets.length} distinct device{sets.length === 1 ? "" : "s"}</p>
          <p className="mt-1 text-sm text-muted">
            from {pairs.observations.length} scans · {multi.length} seen more than once · {singles} seen once · you named {names}
          </p>
        </div>
        <div className="space-y-2 text-sm">
          <label className="block">
            <span className="mb-1 block text-muted">Same device if at least</span>
            <select value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} className={`${inputClass} w-32`}>
              {THRESHOLDS.map((value) => <option key={value} value={value}>{Math.round(value * 100)}% sure</option>)}
            </select>
          </label>
          <label className="flex cursor-pointer items-center gap-2 text-ink-2">
            <input type="checkbox" checked={joinClosest} onChange={(event) => setJoinClosest(event.target.checked)} className="h-4 w-4 accent-[var(--accent)]" />
            Also join mutual closest matches
          </label>
        </div>
      </div>

      {sets.length === 0 ? <Empty>No scans yet.</Empty> : (
        <div className="mt-4 divide-y divide-line border-t border-line">
          {sets.map((set, index) => {
            const items = set.observationIds.map((id) => byId.get(id)!).filter(Boolean);
            return (
              <details key={set.clusterId} className="group py-3">
                <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 text-sm">
                    <span className="font-medium text-ink">Set {index + 1}</span>
                    <span className="text-muted"> · {items.length} scan{items.length === 1 ? "" : "s"} · {set.labels.join(", ")}</span>
                  </span>
                  <span className="flex flex-wrap gap-1.5">
                    {set.weakestLink !== null && <Pill tone={set.weakestLink >= threshold ? "good" : "accent"}>linked ≥ {formatShare(set.weakestLink)}</Pill>}
                    {set.labels.length > 1 && <Pill tone="warn">{set.labels.length} names</Pill>}
                  </span>
                </summary>
                <div className="mt-2 rounded-xl bg-surface-2/50 px-4 py-1">
                  {items.map((item) => (
                    <div key={item.observationId} className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line py-2 text-sm last:border-0">
                      <span className="text-ink">{item.deviceLabel} <span className="text-muted">· {browserOf(item.fingerprint)}{item.browserMode === "private" ? " (private)" : ""} · {item.fingerprint.osFamily}</span></span>
                      <span className="font-mono text-xs text-muted">{item.effectivePublicIp} · {formatTimestamp(item.serverReceivedAt || item.fingerprint.collectedAt)}</span>
                    </div>
                  ))}
                  <p className="py-2 text-xs text-muted">{set.browsers.join(", ")} · {set.networks.length} network{set.networks.length === 1 ? "" : "s"}</p>
                </div>
              </details>
            );
          })}
        </div>
      )}
      <p className="mt-3 text-xs leading-5 text-muted">
        A scan joins a set when the model is at least {Math.round(threshold * 100)}% sure it is the same device as one of its closest matches.
        {joinClosest && " With “mutual closest matches” on, two scans that are each other's best match and more than 50% likely also join; those sets show their lower link in orange."}
        {" "}“Names” shows when one set holds scans you named differently.
      </p>
    </Card>
  );
}

function formatShare(value: number): string {
  return value >= 0.999 ? ">99.9%" : `${(Math.floor(value * 1000) / 10).toFixed(1)}%`;
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Card className="px-4 py-3">
      <p className="font-serif text-3xl text-ink">{value}</p>
      <p className="text-sm text-muted">{label}</p>
    </Card>
  );
}

function Headline({ value, label, tone }: { value: string; label: string; tone: Tone }) {
  return (
    <div>
      <p className={`font-serif text-3xl ${toneText[tone]}`}>{value}</p>
      <p className="mt-1 text-sm text-muted">{label}</p>
    </div>
  );
}

function ScanSelect({ value, onChange, observations }: { value: string; onChange: (value: string) => void; observations: ResearchObservation[] }) {
  return (
    <select value={value} onChange={(event) => onChange(event.target.value)} className={inputClass}>
      {observations.map((item) => <option key={item.observationId} value={item.observationId}>{item.deviceLabel} · {item.fingerprint.browserFamily} · {formatTimestamp(item.serverReceivedAt || item.fingerprint.collectedAt)}</option>)}
    </select>
  );
}

function ComparisonView({ result, sameName }: { result: LinkageResult; sameName: boolean }) {
  const used = result.features.filter((item) => item.status === "used").sort((a, b) => Math.abs(b.logLikelihoodRatio) - Math.abs(a.logLikelihoodRatio));
  const max = Math.max(1, ...result.families.map((item) => Math.abs(item.capped)));
  const tone: Tone = result.verdict === "same-device" ? "good" : result.verdict === "probably-same" ? "accent" : result.verdict === "different-device" ? "neutral" : "warn";
  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <p className={`font-serif text-3xl ${toneText[tone]}`}>{formatProbability(result.posterior)}</p>
        <p className="text-sm text-muted">same-device likelihood · {result.context.replace("-", " ")} · you named them {sameName ? "the same" : "differently"}</p>
      </div>
      <div className="space-y-2">
        {result.families.map((item) => (
          <div key={item.family} className="grid grid-cols-[minmax(120px,180px)_1fr_48px] items-center gap-3 text-sm">
            <span className="truncate text-ink-2">{item.label}</span>
            <DivergingBar value={item.capped} max={max} />
            <span className={`text-right font-mono text-xs ${item.capped >= 0 ? "text-good" : "text-bad"}`}>{item.capped >= 0 ? "+" : ""}{item.capped.toFixed(1)}</span>
          </div>
        ))}
      </div>
      <details>
        <summary className="cursor-pointer text-sm font-medium text-accent-strong">Show the {used.length} signals compared</summary>
        <div className="mt-2 max-h-80 overflow-y-auto rounded-xl border border-line">
          {used.map((item) => (
            <div key={item.id} className="grid grid-cols-[1fr_auto] gap-3 border-b border-line px-3 py-2 text-xs last:border-0">
              <div className="min-w-0"><p className="text-ink">{item.label} <span className="text-muted">· {item.bin}</span></p><p className="truncate font-mono text-[11px] text-muted">{item.current} ↔ {item.previous}</p></div>
              <span className={`font-mono ${item.logLikelihoodRatio >= 0 ? "text-good" : "text-bad"}`}>{item.logLikelihoodRatio >= 0 ? "+" : ""}{item.logLikelihoodRatio.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

function toneFor(value: number | null, good: number, ok: number): Tone {
  if (value === null) return "neutral";
  return value >= good ? "good" : value >= ok ? "warn" : "bad";
}

function formatRate(value: number | null): string { return value === null ? "n/a" : `${(value * 100).toFixed(1)}%`; }
function formatProbability(value: number): string { return value >= 0.999 ? ">99.9%" : value < 0.001 ? "<0.1%" : `${(value * 100).toFixed(1)}%`; }
// Fixed locale and time zone so server-rendered HTML matches the browser.
const TIMESTAMP_FORMAT = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
function formatTimestamp(value: string): string {
  return `${TIMESTAMP_FORMAT.format(new Date(value))} UTC`;
}
