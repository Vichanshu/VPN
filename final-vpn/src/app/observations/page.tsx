import Link from "next/link";
import ObservationsDashboard from "./observations-dashboard";
import { archivedObservations, recentLegacyObservations, recentObservations } from "@/utils/research-store";
import { cachedLinkageModel } from "@/utils/linkage-service";

export const dynamic = "force-dynamic";

export default async function ObservationsPage() {
  let observations;
  let legacyObservations;
  let archived;
  try {
    [observations, legacyObservations, archived] = await Promise.all([recentObservations(1000), recentLegacyObservations(1000), archivedObservations(2000)]);
  } catch {
    return (
      <main className="flex min-h-screen items-center justify-center bg-canvas px-6">
        <div className="max-w-lg rounded-2xl border border-line bg-surface p-8 text-center">
          <h1 className="font-serif text-2xl text-ink">Saved data is unavailable</h1>
          <p className="mt-3 text-sm leading-6 text-muted">Check the server-side DATABASE_URL and network access to the database, then reload this page.</p>
          <Link href="/" className="mt-6 inline-flex rounded-xl bg-accent px-5 py-3 text-sm font-medium text-white hover:bg-accent-strong">Back to scanner</Link>
        </div>
      </main>
    );
  }

  const linkageModel = cachedLinkageModel(observations);
  return (
    <ObservationsDashboard
      initialObservations={observations}
      legacyObservations={legacyObservations}
      linkageModel={linkageModel}
      archivedObservations={archived}
      archiveEnabled={Boolean(process.env.ARCHIVE_PASSWORD_HASH)}
    />
  );
}
