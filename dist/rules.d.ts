import type { Finding, Rule, Severity } from "./types.js";
export declare const SEVERITY_WEIGHTS: Record<Severity, number>;
export declare const RULES: Rule[];
export declare function buildFinding(rule: Rule, evidence: string, source?: "static" | "semantic" | "metadata"): Finding;
export interface DshRuleSpec {
    id: string;
    severity: Severity;
    category: string;
    title: string;
    recommendation: string;
}
export declare const DSH_SPECIFIC_RULES: DshRuleSpec[];
export declare function buildDshFinding(spec: DshRuleSpec, evidence: string, source?: "static" | "semantic" | "metadata"): Finding;
