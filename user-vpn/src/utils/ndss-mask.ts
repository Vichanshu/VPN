import type { FingerprintData } from "./fingerprint";

export interface MaskObservation {
  deviceLabel: string;
  fingerprint: FingerprintData;
}

export interface NdssCrossBrowserMask {
  browserPair: string;
  taskIds: string[];
  trainingPairs: number;
  stability: number;
  uniqueness: number;
  trained: boolean;
}

function pairName(first: string, second: string): string {
  return [first, second].sort((a, b) => a.localeCompare(b)).join(" ↔ ");
}

function taskHash(fingerprint: FingerprintData, taskId: string): string | null {
  const task = fingerprint.ndss2017?.tasks.find((candidate) => candidate.id === taskId);
  if (!task || !task.crossBrowserEligible || (task.status !== "collected" && task.status !== "capability-only")) return null;
  return task.hash;
}

function signature(fingerprint: FingerprintData, taskIds: string[]): string | null {
  const values = taskIds.map((id) => taskHash(fingerprint, id));
  return values.some((value) => value === null) ? null : values.join("|");
}

function combinations(taskIds: string[]): string[][] {
  const output: string[][] = [];
  for (let bitset = 1; bitset < 1 << taskIds.length; bitset += 1) {
    const selected = taskIds.filter((_, index) => Boolean(bitset & (1 << index)));
    output.push(selected);
  }
  return output;
}

/**
 * A bounded implementation of the paper's mask search. It first keeps the
 * twelve most stable/discriminative eligible tasks, then exhaustively scores
 * every non-empty mask. The cap prevents an exponential search from affecting
 * a production request path while preserving the original methodology.
 */
export function trainNdssCrossBrowserMask(
  observations: MaskObservation[],
  firstBrowser: string,
  secondBrowser: string,
): NdssCrossBrowserMask {
  const pair = pairName(firstBrowser, secondBrowser);
  const relevant = observations.filter(({ fingerprint }) =>
    fingerprint.browserFamily === firstBrowser || fingerprint.browserFamily === secondBrowser,
  );
  const sameDevicePairs: Array<[MaskObservation, MaskObservation]> = [];
  for (let left = 0; left < relevant.length; left += 1) {
    for (let right = left + 1; right < relevant.length; right += 1) {
      const first = relevant[left];
      const second = relevant[right];
      if (first.deviceLabel !== second.deviceLabel || first.fingerprint.browserFamily === second.fingerprint.browserFamily) continue;
      sameDevicePairs.push([first, second]);
    }
  }
  if (sameDevicePairs.length < 2) {
    return { browserPair: pair, taskIds: [], trainingPairs: sameDevicePairs.length, stability: 0, uniqueness: 0, trained: false };
  }

  const possibleTaskIds = Array.from(new Set(relevant.flatMap(({ fingerprint }) => fingerprint.ndss2017?.crossBrowserTaskIds || [])));
  const ranked = possibleTaskIds.map((taskId) => {
    const comparable = sameDevicePairs.filter(([a, b]) => taskHash(a.fingerprint, taskId) && taskHash(b.fingerprint, taskId));
    const stable = comparable.length ? comparable.filter(([a, b]) => taskHash(a.fingerprint, taskId) === taskHash(b.fingerprint, taskId)).length / comparable.length : 0;
    const values = new Map<string, Set<string>>();
    for (const observation of relevant) {
      const value = taskHash(observation.fingerprint, taskId);
      if (!value) continue;
      values.set(value, (values.get(value) || new Set()).add(observation.deviceLabel));
    }
    const labelled = Array.from(values.values());
    const uniqueness = labelled.length ? labelled.filter((labels) => labels.size === 1).length / labelled.length : 0;
    return { taskId, stable, uniqueness, value: stable * uniqueness };
  }).filter((candidate) => candidate.stable >= 0.5 && candidate.uniqueness > 0).sort((a, b) => b.value - a.value).slice(0, 12);

  if (!ranked.length) return { browserPair: pair, taskIds: [], trainingPairs: sameDevicePairs.length, stability: 0, uniqueness: 0, trained: false };
  let best = { taskIds: [] as string[], stability: 0, uniqueness: 0, score: -1 };
  for (const taskIds of combinations(ranked.map((candidate) => candidate.taskId))) {
    const matchingPairs = sameDevicePairs.filter(([a, b]) => {
      const first = signature(a.fingerprint, taskIds);
      return first !== null && first === signature(b.fingerprint, taskIds);
    });
    const stability = matchingPairs.length / sameDevicePairs.length;
    if (stability === 0) continue;
    const signatures = new Map<string, Set<string>>();
    for (const observation of relevant) {
      const value = signature(observation.fingerprint, taskIds);
      if (!value) continue;
      signatures.set(value, (signatures.get(value) || new Set()).add(observation.deviceLabel));
    }
    const uniqueValues = Array.from(signatures.values()).filter((labels) => labels.size === 1).length;
    const uniqueness = signatures.size ? uniqueValues / signatures.size : 0;
    const score = stability * uniqueness;
    if (score > best.score) best = { taskIds, stability, uniqueness, score };
  }
  return { browserPair: pair, taskIds: best.taskIds, trainingPairs: sameDevicePairs.length, stability: best.stability, uniqueness: best.uniqueness, trained: best.taskIds.length > 0 };
}
