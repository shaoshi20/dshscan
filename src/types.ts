export type Severity = "low" | "medium" | "high" | "critical";
export type ScanMode = "static" | "static+semantic";
export type FindingSource = "static" | "semantic" | "metadata";

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  evidence: string;
  recommendation: string;
  source: FindingSource;
  rule?: string;
  scope?: string;
}

export interface PluginMeta {
  name: string;
  slug?: string;
  owner?: string;
  category?: string;
  stars?: number;
  trust?: string;
  verified?: boolean;
  npm?: boolean;
  cmd?: string;
  ucs?: string[];
  updated?: string;
  url?: string;
  search?: string;
}

export type TargetKind = "plugin" | "remote" | "dir" | "zip" | "md" | "file";

export interface TargetInfo {
  kind: TargetKind;
  raw: string;
  displayName: string;
  repoUrl?: string;
  localPath?: string;
  metadata: PluginMeta | null;
}

export interface ScanReport {
  tool: string;
  version: string;
  target: TargetInfo;
  risk_score: number;
  severity: Severity;
  safe_to_install: boolean;
  recommendation: string;
  findings: Finding[];
  findings_truncated: boolean;
  llm_used: boolean;
  scan_mode: ScanMode;
  scan_note: string;
  metadata: PluginMeta | null;
}

export interface Rule {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  pattern: RegExp;
  recommendation: string;
  scope?: string;
  enabled?: boolean;
}

export interface Policy {
  ignoreRules?: string[];
  severityOverrides?: Record<string, Severity>;
  includeScopes?: string[];
  excludeScopes?: string[];
  maxRiskScore?: number;
  auditLog?: string;
}

export interface SemanticResult {
  used: boolean;
  riskScore?: number;
  findings?: Finding[];
  error?: string;
}
