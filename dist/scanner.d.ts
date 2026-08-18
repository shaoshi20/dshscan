import type { Finding, PluginMeta, ScanReport, Severity, TargetInfo } from "./types.js";
export interface ScanOptions {
    indexPath?: string;
    offline?: boolean;
    semantic?: boolean;
    llmModel?: string;
    llmBaseUrl?: string;
    llmApiKey?: string;
}
export interface RawScanResult {
    findings: Finding[];
    readmeText: string;
    codeExcerpts: string[];
    sourceLabel: string;
}
export declare function loadIndex(indexPath?: string): PluginMeta[];
export declare function findPlugin(name: string, plugins: PluginMeta[]): PluginMeta | null;
export declare function parseCmdToRepo(cmd?: string): string | null;
export declare function normalizeRemote(raw: string): string;
export declare function cloneRepo(url: string, dest: string): void;
export declare function collectTextFiles(root: string): string[];
export declare function readTextFile(file: string): string;
export declare function scanText(text: string, fileLabel: string, source?: "static"): Finding[];
export declare function scanLocalPath(localPath: string): RawScanResult;
export declare function metadataFindings(meta: PluginMeta): Finding[];
export declare function computeScore(findings: Finding[], meta: PluginMeta | null): number;
export declare function severityFromScore(score: number): Severity;
export declare function recommendationFromFindings(findings: Finding[], score: number, severity: Severity): string;
export declare function resolveTarget(raw: string, plugins: PluginMeta[], offline: boolean): TargetInfo;
export declare function scanTarget(target: TargetInfo, opts?: ScanOptions): Promise<ScanReport>;
