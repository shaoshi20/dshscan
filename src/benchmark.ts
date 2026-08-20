import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { scanLocalPath } from "./scanner.js";
import { VERSION } from "./version.js";

export interface BenchmarkExpected {
  description?: string;
  shouldFind?: string[];
}

export interface BenchmarkCaseResult {
  name: string;
  description: string;
  expected: string[];
  actual: string[];
  truePositives: string[];
  falsePositives: string[];
  falseNegatives: string[];
  pass: boolean;
}

export interface RuleMetric {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface BenchmarkResult {
  tool: string;
  version: string;
  generatedAt: string;
  casesDir: string;
  cases: BenchmarkCaseResult[];
  summary: {
    totalCases: number;
    passedCases: number;
    tp: number;
    fp: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
  };
  byRule: Record<string, RuleMetric>;
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

export function runBenchmark(casesDir: string): BenchmarkResult {
  if (!existsSync(casesDir)) {
    throw new Error(`benchmark cases dir not found: ${casesDir}`);
  }

  const entries = readdirSync(casesDir, { withFileTypes: true }).filter((e) => e.isDirectory());
  const cases: BenchmarkCaseResult[] = [];
  const ruleStats: Record<string, { tp: number; fp: number; fn: number }> = {};

  const touch = (id: string) => {
    ruleStats[id] ??= { tp: 0, fp: 0, fn: 0 };
  };

  for (const entry of entries) {
    const caseDir = join(casesDir, entry.name);
    const expectedPath = join(caseDir, "expected.json");
    if (!existsSync(expectedPath)) continue;

    const expectedRaw = JSON.parse(readFileSync(expectedPath, "utf-8")) as BenchmarkExpected;
    const expected = uniqueSorted(expectedRaw.shouldFind ?? []);

    // Benchmark focuses on detection rules (R*), not metadata/dependency/limitation noise.
    const raw = scanLocalPath(caseDir);
    const actual = uniqueSorted(
      raw.findings
        .map((f) => f.id)
        .filter((id) => /^R\d+$/.test(id)),
    );

    const expectedSet = new Set(expected);
    const actualSet = new Set(actual);
    const truePositives = expected.filter((id) => actualSet.has(id));
    const falsePositives = actual.filter((id) => !expectedSet.has(id));
    const falseNegatives = expected.filter((id) => !actualSet.has(id));

    for (const id of [...expected, ...actual]) {
      touch(id);
      if (expectedSet.has(id) && actualSet.has(id)) ruleStats[id]!.tp++;
      if (!expectedSet.has(id) && actualSet.has(id)) ruleStats[id]!.fp++;
      if (expectedSet.has(id) && !actualSet.has(id)) ruleStats[id]!.fn++;
    }

    cases.push({
      name: entry.name,
      description: expectedRaw.description ?? "",
      expected,
      actual,
      truePositives,
      falsePositives,
      falseNegatives,
      pass: falsePositives.length === 0 && falseNegatives.length === 0,
    });
  }

  const totalTp = cases.reduce((sum, c) => sum + c.truePositives.length, 0);
  const totalFp = cases.reduce((sum, c) => sum + c.falsePositives.length, 0);
  const totalFn = cases.reduce((sum, c) => sum + c.falseNegatives.length, 0);

  const precision = totalTp + totalFp > 0 ? totalTp / (totalTp + totalFp) : 0;
  const recall = totalTp + totalFn > 0 ? totalTp / (totalTp + totalFn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const byRule: Record<string, RuleMetric> = {};
  for (const [id, s] of Object.entries(ruleStats)) {
    const p = s.tp + s.fp > 0 ? s.tp / (s.tp + s.fp) : 0;
    const r = s.tp + s.fn > 0 ? s.tp / (s.tp + s.fn) : 0;
    const f = p + r > 0 ? (2 * p * r) / (p + r) : 0;
    byRule[id] = {
      tp: s.tp,
      fp: s.fp,
      fn: s.fn,
      precision: round(p),
      recall: round(r),
      f1: round(f),
    };
  }

  return {
    tool: "DShScan",
    version: VERSION,
    generatedAt: new Date().toISOString(),
    casesDir,
    cases,
    summary: {
      totalCases: cases.length,
      passedCases: cases.filter((c) => c.pass).length,
      tp: totalTp,
      fp: totalFp,
      fn: totalFn,
      precision: round(precision),
      recall: round(recall),
      f1: round(f1),
    },
    byRule,
  };
}
