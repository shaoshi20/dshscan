import type { Finding, Rule, Severity } from "./types.js";
export declare const SEVERITY_WEIGHTS: Record<Severity, number>;
export declare const RULES: Rule[];
export declare function buildFinding(rule: Rule, evidence: string, source?: "static" | "semantic" | "metadata"): Finding;
