import "server-only";

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import type { ResearchObservation } from "./fingerprint";
import { emptyState, lockedFor, registerAttempt, type ThrottleLimits, type ThrottleState } from "./throttle-policy";

const NDSS_TABLE = "public.vpn_ndss2017_research_observations";
const LEGACY_TABLE = "public.vpn_research_observations";
const ARCHIVE_TABLE = "public.vpn_linkage_archived_observations";
const THROTTLE_TABLE = "public.vpn_linkage_auth_throttle";
const COLUMNS = `observation_id, device_label, browser_mode, vpn_ground_truth,
  fingerprint, server_seen_ip, effective_public_ip, study_id,
  consent_version, server_received_at, server_network, path_probes,
  device_location, ground_truth_details, risk_assessment, protected_components`;

type DatabaseGlobal = typeof globalThis & {
  __vpnResearchPool?: Pool;
  __vpnResearchSchemaReady?: Promise<void>;
  __vpnResearchFileQueue?: Promise<unknown>;
  __vpnAuthThrottle?: Map<string, ThrottleState>;
};

/** A scan that was moved out of the active comparison set. */
export interface ArchivedObservation extends ResearchObservation {
  archiveBatchId: string;
  archivedAt: string;
}

export type StorageBackend = "postgresql" | "local-file";

interface ObservationRow {
  observation_id: string;
  device_label: string;
  browser_mode: ResearchObservation["browserMode"];
  vpn_ground_truth: ResearchObservation["vpnGroundTruth"];
  fingerprint: ResearchObservation["fingerprint"];
  server_seen_ip: string;
  effective_public_ip: string;
  study_id: string | null;
  consent_version: string | null;
  server_received_at: string | null;
  server_network: ResearchObservation["serverNetwork"] | null;
  path_probes: ResearchObservation["pathProbes"] | null;
  device_location: ResearchObservation["deviceLocation"] | null;
  ground_truth_details: ResearchObservation["groundTruthDetails"] | null;
  risk_assessment: ResearchObservation["riskAssessment"] | null;
  protected_components: ResearchObservation["protectedComponents"] | null;
  client_latency?: ResearchObservation["clientLatency"] | null;
  vpn_assessment?: ResearchObservation["riskAssessment"] | null;
  archive_batch_id?: string;
  archived_at?: string;
}

/**
 * PostgreSQL is used whenever a connection string is configured. Without one
 * (local development, offline demos) observations go to a JSON file under
 * .research-data/, which is git-ignored and never mixed with the database.
 */
export function storageBackend(): StorageBackend {
  return process.env.DATABASE_URL_POOLER || process.env.DATABASE_URL ? "postgresql" : "local-file";
}

function databasePool(): Pool {
  // Supabase's pooler is useful when a direct Postgres port is restricted by a
  // corporate network or VPN. Prefer it when explicitly configured.
  const connectionString = process.env.DATABASE_URL_POOLER || process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL or DATABASE_URL_POOLER is not configured");

  const shared = globalThis as DatabaseGlobal;
  shared.__vpnResearchPool ??= new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30_000,
    // VPN DNS/TLS handshakes to a managed pooler can exceed the usual local
    // direct-Postgres timeout. Bound the wait, but allow a cold connection.
    connectionTimeoutMillis: 30_000,
  });
  return shared.__vpnResearchPool;
}

async function ensureSchema(): Promise<void> {
  const shared = globalThis as DatabaseGlobal;
  shared.__vpnResearchSchemaReady ??= databasePool().query(`
    CREATE TABLE IF NOT EXISTS ${NDSS_TABLE} (
      observation_id uuid PRIMARY KEY,
      device_label varchar(60) NOT NULL,
      browser_mode varchar(16) NOT NULL,
      vpn_ground_truth varchar(16) NOT NULL,
      fingerprint jsonb NOT NULL,
      server_seen_ip text NOT NULL,
      effective_public_ip text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE ${NDSS_TABLE}
      ALTER COLUMN vpn_ground_truth TYPE varchar(32),
      ADD COLUMN IF NOT EXISTS study_id varchar(60),
      ADD COLUMN IF NOT EXISTS consent_version varchar(40),
      ADD COLUMN IF NOT EXISTS server_received_at timestamptz,
      ADD COLUMN IF NOT EXISTS server_network jsonb,
      ADD COLUMN IF NOT EXISTS path_probes jsonb,
      ADD COLUMN IF NOT EXISTS device_location jsonb,
      ADD COLUMN IF NOT EXISTS ground_truth_details jsonb,
      ADD COLUMN IF NOT EXISTS risk_assessment jsonb,
      ADD COLUMN IF NOT EXISTS protected_components jsonb,
      ADD COLUMN IF NOT EXISTS client_latency jsonb,
      -- Device-anchored VPN verdict of the final-vpn app, kept apart from
      -- risk_assessment so the two apps never overwrite each other.
      ADD COLUMN IF NOT EXISTS vpn_assessment jsonb;

    CREATE INDEX IF NOT EXISTS vpn_ndss2017_research_observations_created_at_idx
      ON ${NDSS_TABLE} (created_at DESC);

    CREATE INDEX IF NOT EXISTS vpn_ndss2017_research_observations_device_label_idx
      ON ${NDSS_TABLE} (device_label);

    CREATE TABLE IF NOT EXISTS ${ARCHIVE_TABLE} (
      observation_id uuid PRIMARY KEY,
      device_label varchar(60) NOT NULL,
      browser_mode varchar(16) NOT NULL,
      vpn_ground_truth varchar(32) NOT NULL,
      fingerprint jsonb NOT NULL,
      server_seen_ip text NOT NULL,
      effective_public_ip text NOT NULL,
      created_at timestamptz NOT NULL,
      study_id varchar(60),
      consent_version varchar(40),
      server_received_at timestamptz,
      server_network jsonb,
      path_probes jsonb,
      device_location jsonb,
      ground_truth_details jsonb,
      risk_assessment jsonb,
      protected_components jsonb,
      client_latency jsonb,
      archive_batch_id uuid NOT NULL,
      archived_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE ${ARCHIVE_TABLE} ADD COLUMN IF NOT EXISTS vpn_assessment jsonb;

    -- The prototype table only gains this app's verdict column; its rows stay as they are.
    DO $$ BEGIN
      IF to_regclass('${LEGACY_TABLE}') IS NOT NULL THEN
        ALTER TABLE ${LEGACY_TABLE} ADD COLUMN IF NOT EXISTS vpn_assessment jsonb;
      END IF;
    END $$;

    CREATE INDEX IF NOT EXISTS vpn_linkage_archived_observations_batch_idx
      ON ${ARCHIVE_TABLE} (archived_at DESC, archive_batch_id);

    CREATE TABLE IF NOT EXISTS ${THROTTLE_TABLE} (
      throttle_key text PRIMARY KEY,
      attempts integer NOT NULL DEFAULT 0,
      window_started timestamptz NOT NULL DEFAULT now(),
      locked_until timestamptz,
      lock_count integer NOT NULL DEFAULT 0
    );
  `).then(() => undefined).catch((error) => {
    shared.__vpnResearchSchemaReady = undefined;
    throw error;
  });
  await shared.__vpnResearchSchemaReady;
}

function fromRow(row: ObservationRow): ResearchObservation {
  return {
    observationId: row.observation_id,
    deviceLabel: row.device_label,
    browserMode: row.browser_mode,
    vpnGroundTruth: row.vpn_ground_truth,
    fingerprint: row.fingerprint,
    serverSeenIp: row.server_seen_ip,
    effectivePublicIp: row.effective_public_ip,
    studyId: row.study_id || undefined,
    consentVersion: row.consent_version || undefined,
    serverReceivedAt: row.server_received_at ? new Date(row.server_received_at).toISOString() : undefined,
    serverNetwork: row.server_network || undefined,
    pathProbes: row.path_probes || undefined,
    deviceLocation: row.device_location,
    groundTruthDetails: row.ground_truth_details || undefined,
    // This app's verdict lives in vpn_assessment; older rows fall back to the
    // original risk_assessment until `npm run rescore -- --apply` fills it.
    riskAssessment: row.vpn_assessment || row.risk_assessment || undefined,
    protectedComponents: row.protected_components || undefined,
    clientLatency: row.client_latency || null,
  };
}

export async function observationCount(): Promise<number> {
  if (storageBackend() === "local-file") return (await readFileStore()).length;
  await ensureSchema();
  const result = await databasePool().query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${NDSS_TABLE}`,
  );
  return Number(result.rows[0]?.count || 0);
}

/** The original prototype table is read-only from the NDSS final app. */
export async function legacyObservationCount(): Promise<number> {
  if (storageBackend() === "local-file") return 0;
  await ensureSchema();
  try {
    const result = await databasePool().query<{ count: string }>(`SELECT count(*)::text AS count FROM ${LEGACY_TABLE}`);
    return Number(result.rows[0]?.count || 0);
  } catch (error) {
    if (isMissingTable(error)) return 0;
    throw error;
  }
}

export async function recentObservations(limit = 200): Promise<ResearchObservation[]> {
  const safeLimit = Math.max(1, Math.min(1000, Math.floor(limit)));
  if (storageBackend() === "local-file") return (await readFileStore()).slice(0, safeLimit);
  await ensureSchema();
  const result = await databasePool().query<ObservationRow>(`
    SELECT ${COLUMNS}, client_latency, vpn_assessment
      FROM ${NDSS_TABLE}
     ORDER BY created_at DESC
     LIMIT $1
  `, [safeLimit]);
  return result.rows.map(fromRow);
}

export async function recentLegacyObservations(limit = 200): Promise<ResearchObservation[]> {
  if (storageBackend() === "local-file") return [];
  await ensureSchema();
  const safeLimit = Math.max(1, Math.min(1000, Math.floor(limit)));
  try {
    const result = await databasePool().query<ObservationRow>(`
      SELECT ${COLUMNS}, vpn_assessment
        FROM ${LEGACY_TABLE}
       ORDER BY created_at DESC
       LIMIT $1
    `, [safeLimit]);
    return result.rows.map(fromRow);
  } catch (error) {
    if (isMissingTable(error)) return [];
    throw error;
  }
}

export async function saveObservation(observation: ResearchObservation): Promise<void> {
  if (storageBackend() === "local-file") {
    await mutateFileStore((rows) => [observation, ...rows]);
    return;
  }
  await ensureSchema();
  await databasePool().query(`
    INSERT INTO ${NDSS_TABLE} (${COLUMNS}, client_latency, vpn_assessment)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb, $15::jsonb, $16::jsonb, $17::jsonb, $15::jsonb)
  `, [
    observation.observationId,
    observation.deviceLabel,
    observation.browserMode,
    observation.vpnGroundTruth,
    JSON.stringify(observation.fingerprint),
    observation.serverSeenIp,
    observation.effectivePublicIp,
    observation.studyId || null,
    observation.consentVersion || null,
    observation.serverReceivedAt || null,
    JSON.stringify(observation.serverNetwork || null),
    JSON.stringify(observation.pathProbes || []),
    JSON.stringify(observation.deviceLocation || null),
    JSON.stringify(observation.groundTruthDetails || null),
    JSON.stringify(observation.riskAssessment || null),
    JSON.stringify(observation.protectedComponents || null),
    JSON.stringify(observation.clientLatency || null),
  ]);
}

export async function deleteObservationsOlderThan(days: number): Promise<number> {
  const safeDays = Math.max(1, Math.min(3650, Math.floor(days)));
  if (storageBackend() === "local-file") {
    const cutoff = Date.now() - safeDays * 24 * 60 * 60_000;
    let removed = 0;
    await mutateFileStore((rows) => {
      const kept = rows.filter((row) => Date.parse(row.serverReceivedAt || row.fingerprint.collectedAt) >= cutoff);
      removed = rows.length - kept.length;
      return kept;
    });
    return removed;
  }
  await ensureSchema();
  const result = await databasePool().query(
    `DELETE FROM ${NDSS_TABLE} WHERE created_at < now() - ($1::text || ' days')::interval`,
    [safeDays],
  );
  return result.rowCount || 0;
}

/* Archive -------------------------------------------------------------- */

/**
 * Moves every active scan into the archive in one statement, so a scan saved
 * concurrently is either archived or stays active, never lost. New scans are
 * then compared only with scans captured after this point.
 */
export async function archiveActiveObservations(): Promise<{ batchId: string; archived: number }> {
  const batchId = crypto.randomUUID();
  if (storageBackend() === "local-file") {
    let moved: ResearchObservation[] = [];
    await mutateFileStore((rows) => { moved = rows; return []; });
    const archivedAt = new Date().toISOString();
    await mutateArchiveFile((rows) => [...moved.map((row) => ({ ...row, archiveBatchId: batchId, archivedAt })), ...rows]);
    return { batchId, archived: moved.length };
  }
  await ensureSchema();
  const result = await databasePool().query(`
    WITH moved AS (DELETE FROM ${NDSS_TABLE} RETURNING *)
    INSERT INTO ${ARCHIVE_TABLE} (${COLUMNS}, client_latency, vpn_assessment, created_at, archive_batch_id, archived_at)
    SELECT ${COLUMNS}, client_latency, vpn_assessment, created_at, $1::uuid, now() FROM moved
  `, [batchId]);
  return { batchId, archived: result.rowCount || 0 };
}

export async function archivedObservations(limit = 2_000): Promise<ArchivedObservation[]> {
  const safeLimit = Math.max(1, Math.min(5_000, Math.floor(limit)));
  if (storageBackend() === "local-file") return (await readArchiveFile()).slice(0, safeLimit);
  await ensureSchema();
  const result = await databasePool().query<ObservationRow>(`
    SELECT ${COLUMNS}, client_latency, vpn_assessment, archive_batch_id, archived_at
      FROM ${ARCHIVE_TABLE}
     ORDER BY archived_at DESC, created_at DESC
     LIMIT $1
  `, [safeLimit]);
  return result.rows.map((row) => ({
    ...fromRow(row),
    archiveBatchId: String(row.archive_batch_id),
    archivedAt: new Date(row.archived_at || 0).toISOString(),
  }));
}

/* Brute-force throttle ----------------------------------------------------- */

export interface ThrottleCheck {
  allowed: boolean;
  retryAfterMs: number;
}

/**
 * Atomically registers one attempt against every key unless any key is
 * locked. Rows are locked FOR UPDATE, so concurrent requests serialise and
 * cannot each see "attempts remaining".
 */
export async function registerAuthAttempt(keys: Array<{ key: string; limits: ThrottleLimits }>): Promise<ThrottleCheck> {
  const now = Date.now();
  if (storageBackend() === "local-file") {
    const shared = globalThis as DatabaseGlobal;
    shared.__vpnAuthThrottle ??= new Map();
    const states = keys.map(({ key }) => shared.__vpnAuthThrottle!.get(key) || null);
    const retryAfterMs = Math.max(0, ...states.map((state) => lockedFor(state, now)));
    if (retryAfterMs > 0) return { allowed: false, retryAfterMs };
    keys.forEach(({ key, limits }, index) => shared.__vpnAuthThrottle!.set(key, registerAttempt(states[index], now, limits)));
    return { allowed: true, retryAfterMs: 0 };
  }
  await ensureSchema();
  const client = await databasePool().connect();
  try {
    await client.query("BEGIN");
    const ordered = [...keys].sort((a, b) => a.key.localeCompare(b.key));
    const states: ThrottleState[] = [];
    for (const { key } of ordered) {
      await client.query(`INSERT INTO ${THROTTLE_TABLE} (throttle_key) VALUES ($1) ON CONFLICT (throttle_key) DO NOTHING`, [key]);
      const row = (await client.query<{ attempts: number; window_started: string; locked_until: string | null; lock_count: number }>(
        `SELECT attempts, window_started, locked_until, lock_count FROM ${THROTTLE_TABLE} WHERE throttle_key = $1 FOR UPDATE`, [key],
      )).rows[0];
      states.push(row ? {
        attempts: row.attempts,
        windowStarted: Date.parse(row.window_started),
        lockedUntil: row.locked_until ? Date.parse(row.locked_until) : 0,
        lockCount: row.lock_count,
      } : emptyState(now));
    }
    const retryAfterMs = Math.max(0, ...states.map((state) => lockedFor(state, now)));
    if (retryAfterMs > 0) {
      await client.query("COMMIT");
      return { allowed: false, retryAfterMs };
    }
    for (let index = 0; index < ordered.length; index += 1) {
      const next = registerAttempt(states[index], now, ordered[index].limits);
      await client.query(
        `UPDATE ${THROTTLE_TABLE}
            SET attempts = $2::integer,
                window_started = to_timestamp($3::double precision / 1000),
                locked_until = CASE WHEN $4::double precision > 0 THEN to_timestamp($4::double precision / 1000) ELSE NULL END,
                lock_count = $5::integer
          WHERE throttle_key = $1`,
        [ordered[index].key, next.attempts, next.windowStarted, next.lockedUntil, next.lockCount],
      );
    }
    await client.query("COMMIT");
    return { allowed: true, retryAfterMs: 0 };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/** Clears a key after a correct password (the global counter is kept). */
export async function resetAuthThrottle(key: string): Promise<void> {
  if (storageBackend() === "local-file") {
    (globalThis as DatabaseGlobal).__vpnAuthThrottle?.delete(key);
    return;
  }
  await ensureSchema();
  await databasePool().query(`DELETE FROM ${THROTTLE_TABLE} WHERE throttle_key = $1`, [key]);
}

function isMissingTable(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "42P01");
}

/* Local JSON file backend ------------------------------------------------- */

function fileStorePath(): string {
  return process.env.RESEARCH_FILE_STORE || path.join(process.cwd(), ".research-data", "observations.json");
}

async function readFileStore(): Promise<ResearchObservation[]> {
  return readJsonRows<ResearchObservation>(fileStorePath());
}

function archiveFilePath(): string {
  return path.join(path.dirname(fileStorePath()), "archive.json");
}

async function readJsonRows<T>(file: string): Promise<T[]> {
  try {
    const rows = JSON.parse(await readFile(/*turbopackIgnore: true*/ file, "utf8")) as T[];
    return Array.isArray(rows) ? rows : [];
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
}

async function readArchiveFile(): Promise<ArchivedObservation[]> {
  return readJsonRows<ArchivedObservation>(archiveFilePath());
}

/** Serialises writes (shared queue for both files) and replaces files atomically. */
function queueFileWrite<T>(file: string, change: (rows: T[]) => T[], limit: number): Promise<void> {
  const shared = globalThis as DatabaseGlobal;
  const run = (shared.__vpnResearchFileQueue || Promise.resolve()).catch(() => undefined).then(async () => {
    await mkdir(path.dirname(file), { recursive: true });
    const next = change(await readJsonRows<T>(file)).slice(0, limit);
    const temporary = `${file}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(next), "utf8");
    await rename(temporary, file);
  });
  shared.__vpnResearchFileQueue = run;
  return run;
}

/** Newest rows first. */
function mutateFileStore(change: (rows: ResearchObservation[]) => ResearchObservation[]): Promise<void> {
  return queueFileWrite(fileStorePath(), change, 5_000);
}

function mutateArchiveFile(change: (rows: ArchivedObservation[]) => ArchivedObservation[]): Promise<void> {
  return queueFileWrite(archiveFilePath(), change, 20_000);
}
