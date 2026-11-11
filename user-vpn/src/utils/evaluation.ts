import type { ResearchObservation } from "./fingerprint";

export interface ModelEvaluation {
  labelled: number;
  positives: number;
  negatives: number;
  threshold: number;
  precision: number | null;
  recall: number | null;
  specificity: number | null;
  falsePositiveRate: number | null;
  brierScore: number | null;
  prAuc: number | null;
}

export function evaluateStoredModel(observations: ResearchObservation[], threshold = 0.5): ModelEvaluation {
  const rows = observations.flatMap((observation) => {
    const label = binaryLabel(observation.vpnGroundTruth);
    const probability = observation.riskAssessment?.probability;
    return label === null || probability === undefined ? [] : [{ label, probability }];
  });
  let truePositive = 0;
  let falsePositive = 0;
  let trueNegative = 0;
  let falseNegative = 0;
  for (const row of rows) {
    const predicted = row.probability >= threshold ? 1 : 0;
    if (predicted && row.label) truePositive += 1;
    else if (predicted) falsePositive += 1;
    else if (row.label) falseNegative += 1;
    else trueNegative += 1;
  }
  const positives = rows.filter((row) => row.label === 1).length;
  const negatives = rows.length - positives;
  return {
    labelled: rows.length,
    positives,
    negatives,
    threshold,
    precision: divide(truePositive, truePositive + falsePositive),
    recall: divide(truePositive, truePositive + falseNegative),
    specificity: divide(trueNegative, trueNegative + falsePositive),
    falsePositiveRate: divide(falsePositive, falsePositive + trueNegative),
    brierScore: rows.length ? rows.reduce((sum, row) => sum + (row.probability - row.label) ** 2, 0) / rows.length : null,
    prAuc: precisionRecallAuc(rows),
  };
}

function binaryLabel(value: ResearchObservation["vpnGroundTruth"]): 0 | 1 | null {
  if (value === "none" || value === "off") return 0;
  if (value === "unknown") return null;
  return 1;
}

function divide(numerator: number, denominator: number): number | null {
  return denominator ? numerator / denominator : null;
}

function precisionRecallAuc(rows: Array<{ label: 0 | 1; probability: number }>): number | null {
  const positives = rows.filter((row) => row.label === 1).length;
  if (!positives) return null;
  const sorted = [...rows].sort((a, b) => b.probability - a.probability);
  let truePositive = 0;
  let falsePositive = 0;
  let previousRecall = 0;
  let area = 0;
  for (const row of sorted) {
    if (row.label) truePositive += 1;
    else falsePositive += 1;
    const recall = truePositive / positives;
    const precision = truePositive / (truePositive + falsePositive);
    area += (recall - previousRecall) * precision;
    previousRecall = recall;
  }
  return area;
}
