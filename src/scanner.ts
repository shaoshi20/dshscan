import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import AdmZip from "adm-zip";
import { runSemantic } from "./semantic.js";
import { buildFinding, RULES, SEVERITY_WEIGHTS } from "./rules.js";
import type {
  Finding,
  PluginMeta,
  ScanReport,
  Severity,
  TargetInfo,
  TargetKind,
} from "./types.js";

const DEFAULT_INDEX =
  process.env.DSCAN_INDEX ?? "E:/workspace/deepseek/work/dshbase-plugin-directory/dshbase-directory.json";
const TOOL_NAME = "DShScan";
const TOOL_VERSION = "0.1.0";

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".venv",
  "venv",
  "dist",
  "build",
  "out",
  "__pycache__",
  ".cache",
  ".next",
  ".tox",
  "coverage",
  ".turbo",
  // CI 定义文件：cron/sudo/chmod/curl 都是正常写法，规则在 CI 上下文里基本是噪音。
  ".github",
  ".circleci",
  ".gitlab",
  "azure-pipelines",
  // 第三方 vendored 依赖：扫描结果基本是库内部方法的噪音，且不可控。
  "third_party",
  "thirdparty",
  "vendor",
  "vendored",
]);

const TEXT_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".zsh",
  ".ps1", ".cmd", ".bat", ".rb", ".php", ".pl", ".lua", ".go", ".rs", ".java",
  ".c", ".h", ".cpp", ".hpp", ".cs", ".swift", ".kt", ".json", ".yaml", ".yml",
  ".toml", ".ini", ".cfg", ".conf", ".md", ".markdown", ".txt", ".html", ".htm",
  ".xml", ".sql", ".env", ".service", ".desktop", ".lock",
]);

const SPECIAL_FILES = new Set([
  "Dockerfile", "Makefile", "Rakefile", "Gemfile", "Procfile", "Vagrantfile",
  "package.json", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "requirements.txt",
  "Pipfile", "pyproject.toml", "Cargo.toml", "go.mod", "setup.py", "install.sh",
]);

// 常见语言的注释行前缀；注释里出现 http://、token、curl 等不应触发网络/凭据类规则。
const COMMENT_RE = /^\s*(?:\/\/|#|;|\*|<!--|--|%|\/\*)/;

// 文档与测试代码的命中降一级严重级（文档是描述性的、测试是夹具数据，
// 同类信号在可执行安装脚本里的权重应当更高）。R008 针对文档内容，
// 在文档里保持原级，但测试文件里的 R008 仍降级。
const DOC_RE = /\.(?:md|markdown|txt|rst)$/i;
const TEST_RE = /(^|\/)(?:test|tests|__tests__)(\/|$)|(?:\.test|\.spec)\.|(?:_test|_spec)\.|(^|\/)test_/i;
const DOCKER_RE = /(^|\/)(?:Dockerfile(?:[^/]*)?|docker-compose(?:[^/]*)\.ya?ml)$/i;

function downgradeSeverity(severity: Severity): Severity {
  switch (severity) {
    case "critical": return "high";
    case "high": return "medium";
    case "medium": return "low";
    default: return "low";
  }
}

// 报告最多展示的 finding 条数（计分仍用全量）。
const MAX_REPORT_FINDINGS = 100;
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

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

export function loadIndex(indexPath: string = DEFAULT_INDEX): PluginMeta[] {
  const raw = readFileSync(indexPath, "utf-8");
  const data = JSON.parse(raw) as { plugins?: PluginMeta[] };
  return data.plugins ?? [];
}

export function findPlugin(name: string, plugins: PluginMeta[]): PluginMeta | null {
  const q = name.trim().toLowerCase();
  if (!q) return null;
  const exact = plugins.find(
    (p) => p.name.toLowerCase() === q || (p.slug ?? "").toLowerCase() === q,
  );
  if (exact) return exact;
  const fuzzy = plugins
    .filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.slug ?? "").toLowerCase().includes(q) ||
        (p.search ?? "").toLowerCase().includes(q),
    )
    .sort((a, b) => (b.stars ?? 0) - (a.stars ?? 0));
  return fuzzy[0] ?? null;
}

export function parseCmdToRepo(cmd?: string): string | null {
  if (!cmd) return null;
  const m = cmd.match(/github:([^\s]+)/);
  if (m) return `https://github.com/${m[1]}.git`;
  const m2 = cmd.match(/git\+https?:\/\/[^\s]+/);
  if (m2) return m2[0];
  const m3 = cmd.match(/https?:\/\/github\.com\/[^\s]+/);
  if (m3) return m3[0];
  return null;
}

export function normalizeRemote(raw: string): string {
  const s = raw.trim();
  if (s.startsWith("github:")) return `https://github.com/${s.slice("github:".length)}.git`;
  if (/^[\w.-]+\/[\w.-]+$/.test(s) && !s.includes(":")) return `https://github.com/${s}.git`;
  return s;
}

export function cloneRepo(url: string, dest: string): void {
  execFileSync("git", ["clone", "--depth", "1", url, dest], {
    stdio: "pipe",
    encoding: "utf-8",
  });
}

export function collectTextFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
      } else if (entry.isFile()) {
        const ext = entry.name.includes(".") ? `.${entry.name.split(".").pop()?.toLowerCase()}` : "";
        if (TEXT_EXTS.has(ext) || SPECIAL_FILES.has(entry.name)) out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

export function readTextFile(file: string): string {
  try {
    return readFileSync(file, "utf-8");
  } catch {
    return "";
  }
}

export function scanText(text: string, fileLabel: string, source: "static" = "static"): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      // 注释行不参与除 R008（提示注入，针对文档内容）以外的规则，
      // 否则 "// http://..." 或 "# token = ..." 这类注释会制造误报。
      if (rule.id !== "R008" && COMMENT_RE.test(line)) continue;
      // R002 不命中 eval 的函数定义（def eval / function eval 是 ML 代码里
      // 常见的 evaluate 命名，不是动态执行）。
      if (rule.id === "R002" && /^\s*(?:async\s+)?def\s+eval\b|^\s*(?:export\s+)?(?:async\s+)?function\s+eval\b/.test(line)) continue;
      if (rule.pattern.test(line)) {
        const evidence = `${fileLabel}:${i + 1}: ${line.trim().slice(0, 300)}`;
        const finding = buildFinding(rule, evidence, source);
        // 测试/构建镜像里的命中降一级（夹具数据与官方安装器在上下文里不算高置信）；
        // 文档里除 R008（本身针对文档）外也降一级。
        if (TEST_RE.test(fileLabel) || DOCKER_RE.test(fileLabel) || (DOC_RE.test(fileLabel) && rule.id !== "R008")) {
          finding.severity = downgradeSeverity(finding.severity);
        }
        findings.push(finding);
      }
    }
  }

  // package.json lifecycle scripts
  if (basename(fileLabel) === "package.json" && fileLabel.endsWith("package.json")) {
    try {
      const pkg = JSON.parse(text) as {
        scripts?: Record<string, string>;
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const lifecycle = ["preinstall", "install", "postinstall", "prepare"];
      for (const key of lifecycle) {
        const script = pkg.scripts?.[key];
        if (script && script.trim()) {
          const evidence = `${fileLabel}: scripts.${key} = ${script.slice(0, 300)}`;
          findings.push({
            id: "R009",
            severity: script.match(/curl|wget|eval|exec|base64|http:\/\//i) ? "high" : "medium",
            category: "package-install-script",
            title: "Package lifecycle script present",
            evidence,
            recommendation:
              "Review lifecycle scripts carefully; they run automatically during install. Prefer zero-install packages or pinned, reviewed scripts.",
            source,
            rule: "R009",
          });
        }
      }
    } catch {
      // ignore malformed package.json; other rules may still flag it
    }
  }

  return findings;
}

export function scanLocalPath(localPath: string): RawScanResult {
  const resolved = resolve(localPath);
  const findings: Finding[] = [];
  const readmeParts: string[] = [];
  const codeExcerpts: string[] = [];
  let sourceLabel = resolved;

  if (statSync(resolved).isDirectory()) {
    sourceLabel = resolved;
    const files = collectTextFiles(resolved);
    for (const file of files) {
      const rel = relative(resolved, file).replace(/\\/g, "/");
      const text = readTextFile(file);
      if (!text) continue;
      const fileFindings = scanText(text, rel);
      findings.push(...fileFindings);
      const lower = basename(file).toLowerCase();
      if (lower.startsWith("readme")) readmeParts.push(text.slice(0, 12000));
      if (fileFindings.some((f) => f.severity === "high" || f.severity === "critical")) {
        codeExcerpts.push(`--- ${rel} ---\n${text.slice(0, 4000)}`);
      }
    }
  } else if (resolved.toLowerCase().endsWith(".zip")) {
    sourceLabel = resolved;
    const tmp = mkdtempSync(join(tmpdir(), "dshscan-zip-"));
    try {
      const zip = new AdmZip(resolved);
      zip.extractAllTo(tmp, true);
      const files = collectTextFiles(tmp);
      for (const file of files) {
        const rel = relative(tmp, file).replace(/\\/g, "/");
        const text = readTextFile(file);
        if (!text) continue;
        const fileFindings = scanText(text, `${basename(resolved)}/${rel}`);
        findings.push(...fileFindings);
        if (basename(file).toLowerCase().startsWith("readme")) readmeParts.push(text.slice(0, 12000));
        if (fileFindings.some((f) => f.severity === "high" || f.severity === "critical")) {
          codeExcerpts.push(`--- ${rel} ---\n${text.slice(0, 4000)}`);
        }
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  } else {
    sourceLabel = resolved;
    const text = readTextFile(resolved);
    findings.push(...scanText(text, basename(resolved)));
    if (basename(resolved).toLowerCase().startsWith("readme")) readmeParts.push(text.slice(0, 12000));
  }

  return {
    findings,
    readmeText: readmeParts.join("\n\n---\n\n").slice(0, 16000),
    codeExcerpts: codeExcerpts.slice(0, 8),
    sourceLabel,
  };
}

export function metadataFindings(meta: PluginMeta): Finding[] {
  const findings: Finding[] = [];
  const source = "metadata" as const;

  if (!meta.verified) {
    findings.push({
      id: "M001",
      severity: "medium",
      category: "metadata-risk",
      title: "Plugin is not marked verified by dshbase CI",
      evidence: `${meta.name}: verified=${String(meta.verified)}`,
      recommendation:
        "verified=false only means dshbase CI did not confirm installability, not that it is malicious. Treat as higher uncertainty and review source before installing.",
      source,
      rule: "M001",
    });
  }

  const stars = meta.stars ?? 0;
  if (stars < 10) {
    findings.push({
      id: "M002",
      severity: "medium",
      category: "metadata-risk",
      title: "Very low GitHub stars / community adoption",
      evidence: `${meta.name}: stars=${stars}`,
      recommendation:
        "Low adoption increases supply-chain risk. Prefer well-known maintainers and inspect the repository directly.",
      source,
      rule: "M002",
    });
  } else if (stars < 100) {
    findings.push({
      id: "M003",
      severity: "low",
      category: "metadata-risk",
      title: "Low GitHub stars / community adoption",
      evidence: `${meta.name}: stars=${stars}`,
      recommendation: "Review the maintainer history and source before installing.",
      source,
      rule: "M003",
    });
  }

  const trust = meta.trust ?? "";
  if (trust !== "gold" && trust !== "silver") {
    findings.push({
      id: "M004",
      severity: "low",
      category: "metadata-risk",
      title: "Unknown trust tier",
      evidence: `${meta.name}: trust=${trust || "unknown"}`,
      recommendation:
        "Unknown trust tier means no strong community/vendor signal. Inspect repository owner and recent activity.",
      source,
      rule: "M004",
    });
  }

  return findings;
}

export function computeScore(findings: Finding[], meta: PluginMeta | null): number {
  // 每个类别只取最高严重级的权重：同一类别的重复命中（如 install.sh 里 40 处 chmod）
  // 不再叠加计分，避免噪音把分数顶满。类别间仍可叠加，总量封顶 100。
  const byCategory = new Map<string, number>();
  for (const f of findings) {
    if (f.source === "semantic") continue;
    const w = SEVERITY_WEIGHTS[f.severity] ?? 0;
    byCategory.set(f.category, Math.max(byCategory.get(f.category) ?? 0, w));
  }
  let score = 0;
  for (const w of byCategory.values()) score += w;

  if (meta) {
    const trust = meta.trust ?? "";
    if (trust === "gold") score -= 5;
    else if (trust === "silver") score -= 2;
    else score += 3;

    if (meta.verified) score -= 3;
    else score += 5;

    const stars = meta.stars ?? 0;
    if (stars < 10) score += 5;
    else if (stars < 100) score += 3;
    else if (stars >= 1000) score -= 2;
  }

  return Math.max(0, Math.min(100, score));
}

export function severityFromScore(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function recommendationFromFindings(findings: Finding[], score: number, severity: Severity): string {
  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  if (hasCritical) {
    return `不建议安装：发现 ${findings.filter((f) => f.severity === "critical").length} 条严重风险，可能包含远程代码执行、凭据窃取或提示注入。请先在隔离环境审查并联系维护者确认。`;
  }
  if (hasHigh) {
    return `建议暂不安装或仅在隔离环境安装：存在 ${findings.filter((f) => f.severity === "high").length} 条高风险发现，需人工审计后决定。`;
  }
  if (severity === "medium" || score >= 30) {
    return "可以在隔离环境试用，但安装前请人工复核相关发现；不要在生产/主 profile 直接使用。";
  }
  return "风险较低，可以安装；仍建议保持插件更新并定期复查。";
}

export function resolveTarget(raw: string, plugins: PluginMeta[], offline: boolean): TargetInfo {
  const trimmed = raw.trim();
  const localExists = existsSync(trimmed);

  if (localExists) {
    const st = statSync(trimmed);
    const kind: TargetKind = st.isDirectory()
      ? "dir"
      : trimmed.toLowerCase().endsWith(".zip")
        ? "zip"
        : trimmed.toLowerCase().endsWith(".md") || trimmed.toLowerCase().endsWith(".markdown")
          ? "md"
          : "file";
    return {
      kind,
      raw: trimmed,
      displayName: basename(trimmed),
      localPath: resolve(trimmed),
      metadata: null,
    };
  }

  const plugin = findPlugin(trimmed, plugins);
  if (plugin) {
    const repoUrl = parseCmdToRepo(plugin.cmd);
    const info: TargetInfo = {
      kind: "plugin",
      raw: trimmed,
      displayName: plugin.name,
      metadata: plugin,
      repoUrl: repoUrl ?? undefined,
    };
    return info;
  }

  if (
    trimmed.startsWith("github:") ||
    trimmed.startsWith("git+") ||
    trimmed.startsWith("http://") ||
    trimmed.startsWith("https://") ||
    trimmed.startsWith("git@") ||
    /^[\w.-]+\/[\w.-]+$/.test(trimmed)
  ) {
    return {
      kind: "remote",
      raw: trimmed,
      displayName: trimmed,
      repoUrl: normalizeRemote(trimmed),
      metadata: null,
    };
  }

  // Treat as unknown plugin name.
  return {
    kind: "plugin",
    raw: trimmed,
    displayName: trimmed,
    metadata: null,
  };
}

export async function scanTarget(target: TargetInfo, opts: ScanOptions = {}): Promise<ScanReport> {
  const findings: Finding[] = [];
  let readmeText = "";
  let codeExcerpts: string[] = [];
  let sourceAvailable = true;

  if (target.metadata) {
    findings.push(...metadataFindings(target.metadata));
  }

  if (target.kind === "dir" || target.kind === "zip" || target.kind === "md" || target.kind === "file") {
    if (!target.localPath || !existsSync(target.localPath)) {
      findings.push({
        id: "E001",
        severity: "high",
        category: "input-error",
        title: "Local scan target not found",
        evidence: target.localPath ?? target.raw,
        recommendation: "Provide an existing directory, zip, or Markdown file.",
        source: "static",
        rule: "E001",
      });
      sourceAvailable = false;
    } else {
      const raw = scanLocalPath(target.localPath);
      findings.push(...raw.findings);
      readmeText = raw.readmeText;
      codeExcerpts = raw.codeExcerpts;
    }
  } else if ((target.kind === "remote" || target.kind === "plugin") && target.repoUrl) {
    // remote 与带 repoUrl 的 plugin 走同一逻辑：克隆到临时目录后静态扫描。
    if (opts.offline) {
      findings.push({
        id: "E002",
        severity: "medium",
        category: "scan-limitation",
        title: "Remote source not scanned (offline mode)",
        evidence: target.repoUrl,
        recommendation:
          "Re-run without --offline to clone and statically scan the repository, or provide a local directory.",
        source: "static",
        rule: "E002",
      });
      sourceAvailable = false;
    } else {
      const tmp = mkdtempSync(join(tmpdir(), "dshscan-git-"));
      try {
        try {
          cloneRepo(target.repoUrl, tmp);
          const raw = scanLocalPath(tmp);
          findings.push(...raw.findings);
          readmeText = raw.readmeText;
          codeExcerpts = raw.codeExcerpts;
        } catch (err) {
          findings.push({
            id: "E003",
            severity: "high",
            category: "scan-limitation",
            title: "Failed to clone repository",
            evidence: `${target.repoUrl}: ${err instanceof Error ? err.message : String(err)}`,
            recommendation:
              "Check network access or clone manually into a local directory and scan that directory.",
            source: "static",
            rule: "E003",
          });
          sourceAvailable = false;
        }
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
    }
  } else if (target.kind === "plugin" && target.metadata?.npm) {
    findings.push({
      id: "E004",
      severity: "medium",
      category: "scan-limitation",
      title: "npm package source not downloaded",
      evidence: `${target.metadata.name} (npm=true, cmd=${target.metadata.cmd ?? ""})`,
      recommendation:
        "Install the package in a sandbox and scan its unpacked contents, or provide a local directory of the package.",
      source: "static",
      rule: "E004",
    });
    sourceAvailable = false;
  } else {
    findings.push({
      id: "E005",
      severity: "medium",
      category: "scan-limitation",
      title: "No downloadable source identified",
      evidence: target.raw,
      recommendation:
        "Provide a GitHub repo URL, local directory/zip, or a plugin name that exists in the dshbase index.",
      source: "static",
      rule: "E005",
    });
    sourceAvailable = false;
  }

  // Deduplicate identical static findings (same rule + evidence) to keep report readable.
  const deduped = dedupeFindings(findings);

  const staticScore = computeScore(deduped, target.metadata);
  let finalScore = staticScore;
  let llmUsed = false;
  let semanticFindings: Finding[] = [];
  let semanticNote = "";

  if (opts.semantic && sourceAvailable && (readmeText || codeExcerpts.length > 0)) {
    const sem = await runSemantic({
      displayName: target.displayName,
      readme: readmeText,
      codeExcerpts,
      model: opts.llmModel,
      baseUrl: opts.llmBaseUrl,
      apiKey: opts.llmApiKey,
    });
    if (sem.used && sem.riskScore !== undefined) {
      llmUsed = true;
      semanticFindings = sem.findings ?? [];
      finalScore = Math.round(staticScore * 0.7 + sem.riskScore * 0.3);
      semanticNote = "已完成静态+LLM语义双通道扫描。";
    } else {
      semanticNote = `语义扫描未执行：${sem.error ?? "未知原因"}。当前仅为静态扫描，非完整扫描。`;
    }
  } else {
    semanticNote = "仅静态扫描，非完整扫描。";
  }

  const allFindings = dedupeFindings([...deduped, ...semanticFindings]);
  const severity = severityFromScore(finalScore);
  const safeToInstall =
    !allFindings.some((f) => f.severity === "high" || f.severity === "critical") &&
    finalScore < 40;

  // 报告只展示按严重级排序的前 N 条；计分与安装建议仍基于全量。
  const reportFindings = [...allFindings]
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, MAX_REPORT_FINDINGS);
  const findingsTruncated = allFindings.length > MAX_REPORT_FINDINGS;

  const report: ScanReport = {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    target,
    risk_score: finalScore,
    severity,
    safe_to_install: safeToInstall,
    recommendation: recommendationFromFindings(allFindings, finalScore, severity),
    findings: reportFindings,
    findings_truncated: findingsTruncated,
    llm_used: llmUsed,
    scan_mode: llmUsed ? "static+semantic" : "static",
    scan_note: semanticNote,
    metadata: target.metadata,
  };

  return report;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.id}|${f.evidence}|${f.source}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(f);
    }
  }
  return out;
}


