"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Database, Globe2, ListChecks, Loader2, Radar, Search, ShieldCheck } from "lucide-react";
import type { IpIntel, IpVerdict } from "@/utils/ip-intel";
import { detectBrowserPublicIps } from "@/utils/network";
import { Card, DivergingBar, Empty, Pill, Row, inputClass, toneText, type Tone } from "@/components/ui";

interface CheckResponse {
  intel: IpIntel;
  verdict: IpVerdict;
  integrations?: { ipinfo: boolean; atlas: boolean; atlasDailyLimit: number };
}

const BAND_TONE: Record<IpVerdict["band"], Tone> = { low: "good", elevated: "warn", high: "bad", unknown: "neutral" };
const POLL_MS = 5_000;

export default function IpCheckPage() {
  const [input, setInput] = useState("");
  const [data, setData] = useState<CheckResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [atlasNote, setAtlasNote] = useState<string | null>(null);
  const [mine, setMine] = useState<{ ipv4: string | null; ipv6: string | null } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stopPolling = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  }, []);
  useEffect(() => stopPolling, [stopPolling]);

  // Named so the callback can reschedule itself without referencing `poll` before it is declared.
  const poll = useCallback(function schedule(ip: string) {
    stopPolling();
    timer.current = setTimeout(async () => {
      try {
        const response = await fetch(`/api/ip-check/atlas?ip=${encodeURIComponent(ip)}`, { cache: "no-store" });
        const body = (await response.json()) as CheckResponse & { error?: string };
        if (!response.ok) return;
        setData((current) => ({ ...body, integrations: current?.integrations }));
        if (body.intel.atlas.status === "running") schedule(ip);
      } catch {
        schedule(ip);
      }
    }, POLL_MS);
  }, [stopPolling]);

  async function check(target: string) {
    stopPolling();
    setLoading(true);
    setError(null);
    setAtlasNote(null);
    try {
      const response = await fetch(`/api/ip-check?ip=${encodeURIComponent(target)}`, { cache: "no-store" });
      const body = (await response.json()) as CheckResponse & { error?: string };
      if (!response.ok) throw new Error(body.error || "Lookup failed.");
      setData(body);
      setInput(body.intel.ip);
      if (body.intel.atlas.status === "running") poll(body.intel.ip);
    } catch (problem) {
      setData(null);
      setError(problem instanceof Error ? problem.message : "Lookup failed.");
    } finally {
      setLoading(false);
    }
  }

  /** The browser reports its own addresses, so a VPN that covers only the browser is seen correctly. */
  async function checkMine() {
    setLoading(true);
    setError(null);
    const found = await detectBrowserPublicIps();
    setMine(found);
    setLoading(false);
    const first = found.ipv4 || found.ipv6;
    if (first) void check(first);
    else void check("me");
  }

  async function startAtlas(force: boolean) {
    if (!data) return;
    setAtlasNote(null);
    try {
      const response = await fetch("/api/ip-check/atlas", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ip: data.intel.ip, force }) });
      const body = (await response.json()) as { started?: boolean; reason?: string; error?: string };
      if (!body.started) {
        setAtlasNote(body.reason || body.error || "Could not start the check.");
        return;
      }
      const refreshed = await fetch(`/api/ip-check/atlas?ip=${encodeURIComponent(data.intel.ip)}`, { cache: "no-store" });
      const next = (await refreshed.json()) as CheckResponse;
      setData({ ...next, integrations: data.integrations });
      poll(data.intel.ip);
    } catch {
      setAtlasNote("Could not reach the server.");
    }
  }

  const intel = data?.intel;
  const verdict = data?.verdict;
  const info = intel?.ipinfo.status === "ok" ? intel.ipinfo.result : null;
  const maxLr = Math.max(1, ...(verdict?.evidence.map((item) => Math.abs(item.logLikelihoodRatio)) || [1]));

  return (
    <main className="min-h-screen bg-canvas">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent-soft text-accent"><ShieldCheck className="h-5 w-5" aria-hidden /></span>
            <div>
              <h1 className="font-serif text-xl text-ink">IP VPN check</h1>
              <p className="text-xs text-muted">Local lists, IPinfo and RIPE Atlas probes</p>
            </div>
          </div>
          <Link href="/" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-ink transition hover:bg-surface-2"><ArrowLeft className="h-3.5 w-3.5" /> Scanner</Link>
        </div>
      </header>

      <div className="mx-auto max-w-4xl space-y-5 px-6 py-8">
        <Card className="p-5">
          <form className="flex flex-col gap-3 sm:flex-row" onSubmit={(event) => { event.preventDefault(); void check(input.trim()); }}>
            <input value={input} onChange={(event) => setInput(event.target.value)} placeholder="IPv4 or IPv6 address, e.g. 193.0.6.139" className={inputClass} aria-label="IP address" spellCheck={false} />
            <div className="flex gap-2">
              <button type="submit" disabled={loading || !input.trim()} className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-medium text-white transition hover:bg-accent-strong disabled:opacity-50">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Check
              </button>
              <button type="button" disabled={loading} onClick={() => void checkMine()} className="rounded-xl border border-line-strong px-4 py-2.5 text-sm font-medium text-ink transition hover:bg-surface-2 disabled:opacity-50">Use my IP</button>
            </div>
          </form>
          {mine && (mine.ipv4 || mine.ipv6) && (
            <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted">
              Your browser&apos;s addresses:
              {(["ipv4", "ipv6"] as const).map((family) => (
                mine[family]
                  ? <button key={family} type="button" onClick={() => void check(mine[family]!)} className="rounded-full border border-line-strong px-2.5 py-0.5 font-mono text-ink transition hover:bg-surface-2">{family === "ipv4" ? "IPv4" : "IPv6"} {mine[family]}</button>
                  : <span key={family} className="rounded-full bg-surface-2 px-2.5 py-0.5">{family === "ipv4" ? "IPv4" : "IPv6"}: none (not detected)</span>
              ))}
            </p>
          )}
          {error && <p role="alert" className="mt-3 text-sm text-bad">{error}</p>}
        </Card>

        {intel && verdict && (
          <>
            <Card className="p-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-sm text-muted">{intel.ip}</p>
                  <h2 className={`mt-1 font-serif text-2xl ${toneText[BAND_TONE[verdict.band]]}`}>{verdict.headline}</h2>
                </div>
                <div className="text-right">
                  <p className={`text-3xl font-semibold ${toneText[BAND_TONE[verdict.band]]}`}>{verdict.score}%</p>
                  <p className="text-xs text-muted">VPN likelihood (uncalibrated)</p>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <Pill tone={BAND_TONE[verdict.band]}>{verdict.band === "unknown" ? "Undecided" : `${verdict.band} risk`}</Pill>
                <Pill tone="accent">{verdict.kind === "none" ? "ordinary network" : verdict.kind}</Pill>
              </div>
            </Card>

            <div className="grid gap-5 md:grid-cols-2">
              <Card className="p-5">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-medium text-ink"><Database className="h-4 w-4 text-accent" /> 1 · Cache</h3>
                <Row label="Source" value={intel.fromCache ? "Stored result (under 7 days old)" : "Fresh lookup, now stored"} />
                <Row label="Checked" value={new Date(intel.checkedAt).toLocaleString()} />
              </Card>

              <Card className="p-5">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-medium text-ink"><ListChecks className="h-4 w-4 text-accent" /> 2 · Public lists</h3>
                {intel.lists ? (
                  <>
                    <Row label="Known VPN netblock" value={<Flag on={intel.lists.vpn} />} />
                    <Row label="Datacenter / hosting" value={<Flag on={intel.lists.datacenter} />} />
                    <Row label="Tor exit" value={<Flag on={intel.lists.tor} />} />
                    <Row label="iCloud Private Relay" value={<Flag on={intel.lists.privateRelay} />} />
                    {intel.lists.checked.length < 4 && <p className="mt-2 text-xs text-muted">Lists not loaded: {["vpn", "datacenter", "private-relay", "tor"].filter((name) => !intel.lists!.checked.includes(name as never)).join(", ")}.</p>}
                  </>
                ) : <Empty>Lists were not checked for this address.</Empty>}
              </Card>
            </div>

            <Card className="p-5">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-medium text-ink"><Globe2 className="h-4 w-4 text-accent" /> 3 · IPinfo</h3>
              {info ? (
                <div className="grid gap-x-8 md:grid-cols-2">
                  <div>
                    <Row label="Claimed location" value={[info.city, info.region, info.country].filter(Boolean).join(", ") || "Unknown"} />
                    <Row label="Coordinates" value={info.latitude !== null ? `${info.latitude}, ${info.longitude}` : "Unknown"} mono />
                    <Row label="Timezone" value={info.timezone || "Not in this plan"} />
                  </div>
                  <div>
                    <Row label="Network owner" value={info.org || "Unknown"} />
                    <Row label="Anycast" value={info.anycast ? "Yes (location not meaningful)" : "No"} />
                    <Row label="Privacy flags" value={info.privacy ? ([info.privacy.vpn && "VPN", info.privacy.proxy && "proxy", info.privacy.tor && "Tor", info.privacy.relay && "relay", info.privacy.hosting && "hosting"].filter(Boolean).join(", ") || "none") : "Not in this IPinfo plan"} />
                  </div>
                </div>
              ) : <Empty>{intel.ipinfo.status === "unavailable" ? intel.ipinfo.message : "No data."}</Empty>}
            </Card>

            <Card className="p-5">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
                <h3 className="flex items-center gap-2 text-sm font-medium text-ink"><Radar className="h-4 w-4 text-accent" /> 4 · RIPE Atlas location check</h3>
                {intel.atlas.status !== "running" && (
                  <button type="button" onClick={() => void startAtlas(intel.atlas.status === "done")} disabled={!data?.integrations?.atlas || !info} className="rounded-lg border border-line-strong px-3 py-1.5 text-xs font-medium text-ink transition hover:bg-surface-2 disabled:opacity-50">
                    {intel.atlas.status === "done" ? "Run again" : "Run deep check"}
                  </button>
                )}
              </div>
              <p className="mb-3 text-xs leading-5 text-muted">Pings the address from RIPE Atlas probes near its claimed location and on other continents. Light in fibre sets a hard distance limit per probe; a claimed location outside any probe&apos;s limit is impossible. Each run costs RIPE Atlas credits.</p>
              {atlasNote && <p role="status" className="mb-3 text-sm text-warn">{atlasNote}</p>}
              {intel.atlas.status === "not-run" && <Empty>Not run. {intel.atlas.message}</Empty>}
              {intel.atlas.status === "failed" && <p className="text-sm text-bad">{intel.atlas.message}</p>}
              {intel.atlas.status === "running" && (
                <p className="flex items-center gap-2 text-sm text-ink-2"><Loader2 className="h-4 w-4 animate-spin" /> {intel.atlas.message}</p>
              )}
              {intel.atlas.status === "done" && (
                <>
                  <p className={`mb-3 text-sm ${intel.atlas.geo.verdict === "inconsistent" ? "text-bad" : intel.atlas.geo.verdict === "consistent" ? "text-good" : "text-ink-2"}`}>
                    <strong className="font-medium capitalize">{intel.atlas.geo.verdict}.</strong> {intel.atlas.geo.reason}
                  </p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="text-muted"><tr><th className="py-1 pr-4 font-medium">Probe</th><th className="pr-4 font-medium">Country</th><th className="pr-4 font-medium">Role</th><th className="pr-4 font-medium">Min RTT</th><th className="font-medium">Target within</th></tr></thead>
                      <tbody>
                        {intel.atlas.samples.map((sample) => (
                          <tr key={sample.id} className="border-t border-line text-ink-2">
                            <td className="py-1 pr-4 font-mono">{sample.id}</td><td className="pr-4">{sample.country}</td><td className="pr-4">{sample.role}</td>
                            <td className="pr-4">{sample.minRttMs === null ? "no reply" : `${sample.minRttMs.toFixed(1)} ms`}</td>
                            <td>{sample.minRttMs === null ? "" : `${Math.round(sample.minRttMs * 100)} km`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </Card>

            <Card className="p-5">
              <h3 className="mb-3 text-sm font-medium text-ink">Evidence behind the verdict</h3>
              {verdict.evidence.length === 0 ? <Empty>No evidence for or against a VPN was found.</Empty> : (
                <ul className="space-y-4">
                  {verdict.evidence.map((item) => (
                    <li key={item.id}>
                      <div className="flex items-baseline justify-between gap-4">
                        <span className="text-sm font-medium text-ink">{item.label}</span>
                        <span className={`font-mono text-xs ${item.logLikelihoodRatio >= 0 ? "text-bad" : "text-good"}`}>{item.logLikelihoodRatio > 0 ? "+" : ""}{item.logLikelihoodRatio.toFixed(1)}</span>
                      </div>
                      <div className="my-1.5"><DivergingBar value={item.logLikelihoodRatio} max={maxLr} /></div>
                      <p className="text-xs leading-5 text-muted">{item.detail} <span className="opacity-70">({item.source})</span></p>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </>
        )}
      </div>
    </main>
  );
}

function Flag({ on }: { on: boolean }) {
  return on ? <Pill tone="bad">listed</Pill> : <Pill tone="good">not listed</Pill>;
}
