import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import AdmZip from "adm-zip";
import { parse as parseYaml } from "yaml";
import { runSemantic } from "./semantic.js";
import { buildDshFinding, buildFinding, DSH_SPECIFIC_RULES, RULES, SEVERITY_WEIGHTS } from "./rules.js";
import { VERSION } from "./version.js";
import type {
  Finding,
  PluginMeta,
  ScanReport,
  Severity,
  TargetInfo,
  TargetKind,
} from "./types.js";

function defaultIndexPath(): string {
  if (process.env.DSCAN_INDEX) return process.env.DSCAN_INDEX;
  const homeCandidate = join(homedir(), ".dsh", "dshbase-directory.json");
  if (existsSync(homeCandidate)) return homeCandidate;
  const localCandidate = join(process.cwd(), "dshbase-directory.json");
  if (existsSync(localCandidate)) return localCandidate;
  return homeCandidate;
}

const DEFAULT_INDEX = defaultIndexPath();
const TOOL_NAME = "DShScan";

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
  ".xml", ".sql", ".env", ".service", ".desktop",
]);

// 单文件扫描上限：超大文件/压缩产物不逐行跑正则，避免 O(n²) 和内存问题。
const MAX_FILE_SIZE = 2 * 1024 * 1024;

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
  audit?: boolean;
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
    timeout: 60_000,
    maxBuffer: 10 * 1024 * 1024,
  });
}

export function runNpmAudit(dir: string): Finding[] {
  const findings: Finding[] = [];
  const result = spawnSync("npm", ["audit", "--json", "--omit=dev"], {
    cwd: dir,
    encoding: "utf-8",
    timeout: 120_000,
    maxBuffer: 20 * 1024 * 1024,
  });
  const stdout = String(result.stdout || "");
  let data: { vulnerabilities?: Record<string, { severity?: string; range?: string; isDirect?: boolean }> };
  try {
    data = JSON.parse(stdout) as typeof data;
  } catch {
    return findings;
  }
  const vulns = data.vulnerabilities ?? {};
  for (const [name, info] of Object.entries(vulns)) {
    const sev = String(info.severity ?? "medium");
    const severity: Severity =
      sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "moderate" ? "medium" : "low";
    findings.push({
      id: `AUDIT-${name}`,
      severity,
      category: "dependency-vulnerability",
      title: `npm audit: ${name}`,
      evidence: `${name}${info.range ? `@${info.range}` : ""}${info.isDirect ? " (direct)" : " (transitive)"}`,
      recommendation: `Update ${name} to a non-vulnerable version and re-run npm audit.`,
      source: "static",
      rule: "AUDIT",
    });
  }
  return findings;
}

export function scanNpmPackage(packageName: string): RawScanResult | null {
  const tmp = mkdtempSync(join(tmpdir(), "dshscan-npm-"));
  try {
    execFileSync(
      "npm",
      ["pack", packageName, "--pack-destination", tmp, "--ignore-scripts", "--silent"],
      { stdio: "pipe", encoding: "utf-8", timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
    );
    const tgz = readdirSync(tmp).find((f) => f.endsWith(".tgz"));
    if (!tgz) return null;
    const extract = mkdtempSync(join(tmp, "extract-"));
    execFileSync("tar", ["-xzf", join(tmp, tgz), "-C", extract], {
      stdio: "pipe",
      encoding: "utf-8",
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    const raw = scanLocalPath(extract);
    raw.findings.push(...runNpmAudit(extract));
    return raw;
  } catch {
    return null;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export function collectTextFiles(root: string): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        const ext = entry.name.includes(".") ? `.${entry.name.split(".").pop()?.toLowerCase()}` : "";
        if ((TEXT_EXTS.has(ext) || SPECIAL_FILES.has(entry.name)) && statSync(full).size <= MAX_FILE_SIZE) {
          out.push(full);
        }
      }
    }
  }
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

  // R005 cross-line detection: credential access and network sink often span
  // multiple lines in real code. Look for a 5-line window when no line-level hit.
  if (!findings.some((f) => f.id === "R005")) {
    const r005 = RULES.find((r) => r.id === "R005");
    if (r005) {
      for (let i = 0; i < lines.length; i++) {
        const window = lines.slice(i, i + 5).join(" ");
        if (r005.pattern.test(window)) {
          const evidence = `${fileLabel}:${i + 1}-${Math.min(i + 5, lines.length)}: ${window.slice(0, 300)}`;
          const finding = buildFinding(r005, evidence, source);
          if (TEST_RE.test(fileLabel) || DOCKER_RE.test(fileLabel) || (DOC_RE.test(fileLabel) && r005.id !== "R008")) {
            finding.severity = downgradeSeverity(finding.severity);
          }
          findings.push(finding);
          break;
        }
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
      findings.push(...scanPackageDependencies(fileLabel, text, source));
    } catch {
      // ignore malformed package.json; other rules may still flag it
    }
  }

  // DSH-specific attack surface rules (cordis.patch.yml, client.mjs, profile tampering).
  const dshFindings = scanDshSpecific(fileLabel, text, source);
  for (const f of dshFindings) {
    if (TEST_RE.test(fileLabel) || DOCKER_RE.test(fileLabel) || (DOC_RE.test(fileLabel) && f.id !== "R008")) {
      f.severity = downgradeSeverity(f.severity);
    }
    findings.push(f);
  }

  return findings;
}

function scanDshManifest(root: string, source: "static" = "static"): Finding[] {
  const findings: Finding[] = [];
  const pkgPath = join(root, "package.json");
  if (!existsSync(pkgPath)) return findings;

  let pkg: { dsh?: { bundle?: { patch?: unknown } }; name?: string } | null = null;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      dsh?: { bundle?: { patch?: unknown } };
      name?: string;
    };
  } catch {
    return findings;
  }

  const patchPath = join(root, "cordis.patch.yml");
  const isDshCandidate =
    Boolean(pkg?.dsh) || existsSync(patchPath) || /dsh/i.test(String(pkg?.name ?? ""));

  if (!isDshCandidate) return findings;

  const files = readdirSync(root).map((f) => f.toLowerCase());
  const hasLicense = files.some((f) => /^license(?:\..*)?$/.test(f));
  const hasReadme = files.some((f) => /^readme(?:\..*)?$/.test(f));

  if (!pkg?.dsh?.bundle) {
    findings.push({
      id: "M006",
      severity: "medium",
      category: "dsh-manifest",
      title: "Missing dsh.bundle manifest",
      evidence: "package.json: dsh.bundle is missing",
      recommendation:
        "Add dsh.bundle.patch pointing to cordis.patch.yml so DSH can mount this plugin.",
      source,
      rule: "M006",
    });
  }
  if (pkg?.dsh?.bundle && !existsSync(patchPath)) {
    findings.push({
      id: "M007",
      severity: "high",
      category: "dsh-manifest",
      title: "cordis.patch.yml missing",
      evidence: "dsh.bundle.patch references cordis.patch.yml but file is absent",
      recommendation:
        "Create cordis.patch.yml with the plugin loader insertion rows.",
      source,
      rule: "M007",
    });
  }
  if (!hasLicense) {
    findings.push({
      id: "M008",
      severity: "medium",
      category: "dsh-manifest",
      title: "Missing LICENSE file",
      evidence: "LICENSE not found",
      recommendation:
        "Add an open-source license so users know the terms before installing.",
      source,
      rule: "M008",
    });
  }
  if (!hasReadme) {
    findings.push({
      id: "M009",
      severity: "low",
      category: "dsh-manifest",
      title: "Missing README",
      evidence: "README not found",
      recommendation: "Add a README describing what the plugin does and how to configure it.",
      source,
      rule: "M009",
    });
  }

  return findings;
}

function isClientFile(fileLabel: string): boolean {
  const lower = fileLabel.toLowerCase();
  const base = basename(lower);
  return (
    base === "client.mjs" ||
    base === "client.js" ||
    base === "client.ts" ||
    base.endsWith(".client.mjs") ||
    base.endsWith(".client.js") ||
    base.endsWith(".client.ts") ||
    /(^|\/)client\/.*\.(?:mjs|js|ts)$/.test(lower)
  );
}

function isProfileConfigFile(fileLabel: string): boolean {
  const lower = fileLabel.toLowerCase();
  const base = basename(lower);
  return (
    base === "cordis.yml" ||
    base === "cordis.patch.yml" ||
    base === "package.json" ||
    base === "pnpm-workspace.yaml" ||
    base === "pnpm-workspace.yml" ||
    base === ".env" ||
    base.startsWith(".env.")
  );
}

function isCodeFile(fileLabel: string): boolean {
  return /\.(?:js|mjs|cjs|ts|tsx|jsx|py|sh|bash|ps1|cmd|bat|rb|php|pl|go|rs)$/i.test(fileLabel);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const DANGEROUS_LOADER_NAMES = [
  "@deepseek-ai/dsh-mcp-client",
  "@deepseek-ai/cordis-plugin-group",
  "@deepseek-ai/cordis-plugin-include",
  "@deepseek-ai/cordis-plugin-loader",
];

const SECURITY_ROW_IDS = [
  "tool-bash",
  "tool-pwsh",
  "tool-shell",
  "session-telemetry-otel",
  "llm-deepseek",
  "approval",
  "permission",
  "skill-badge",
  "directory-picker",
  "agent-instructions",
];

const SUSPICIOUS_BUNDLE_RE = /(?:evil|malicious|hack|backdoor|exfil|miner|keylog)/i;

const KNOWN_PLUGIN_NAMES = [
  "dsh-browser",
  "dsh-market",
  "dsh-memory-evolve",
  "modlens",
  "openviking",
  "dsh-web-ui",
  "dsh-suite",
  "dsh-plugin-marketplace",
  "dsh-skill-viewer",
  "dsh-vision",
];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp: number[] = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(
        dp[j] + 1,
        dp[j - 1] + 1,
        prev + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      prev = tmp;
    }
  }
  return dp[n];
}

const COMMON_DEPENDENCY_NAMES = [
  "lodash",
  "express",
  "react",
  "axios",
  "request",
  "chalk",
  "commander",
  "typescript",
  "webpack",
  "node-fetch",
  "yaml",
  "adm-zip",
];

function scanPackageDependencies(
  fileLabel: string,
  text: string,
  source: "static" = "static",
): Finding[] {
  const findings: Finding[] = [];
  try {
    const pkg = JSON.parse(text) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    for (const [name, rawVersion] of Object.entries(deps)) {
      const version = String(rawVersion ?? "");
      if (/^(?:\*|latest)$/i.test(version) || /^[>=<^~]/.test(version)) {
        findings.push({
          id: "D001",
          severity: "medium",
          category: "dependency-risk",
          title: "Unpinned dependency version",
          evidence: `${fileLabel}: ${name}@${version}`,
          recommendation:
            "Pin exact versions to reduce supply-chain drift and unexpected updates.",
          source,
          rule: "D001",
        });
      }
      if (/^(?:https?:|git\+|github:)/i.test(version)) {
        findings.push({
          id: "D003",
          severity: "high",
          category: "dependency-risk",
          title: "Remote dependency source",
          evidence: `${fileLabel}: ${name}@${version}`,
          recommendation:
            "Prefer registry dependencies with pinned versions over remote tarballs/Git URLs.",
          source,
          rule: "D003",
        });
      }
      const bare = name.toLowerCase().replace(/^@[^/]+\//, "");
      for (const known of COMMON_DEPENDENCY_NAMES) {
        if (
          bare !== known &&
          bare.length >= 4 &&
          known.length >= 4 &&
          levenshtein(bare, known) <= 2
        ) {
          findings.push({
            id: "D002",
            severity: "high",
            category: "dependency-risk",
            title: "Possible dependency typosquatting",
            evidence: `${fileLabel}: ${name} looks like '${known}'`,
            recommendation:
              "Verify the package owner; typosquatted dependencies are a common supply-chain attack.",
            source,
            rule: "D002",
          });
          break;
        }
      }
    }
  } catch {
    // ignore malformed package.json
  }
  return findings;
}

function tryParseYaml(text: string): { parsed: boolean; data: unknown } {
  try {
    return { parsed: true, data: parseYaml(text) };
  } catch {
    return { parsed: false, data: null };
  }
}

function scanCordisPatchStructure(
  fileLabel: string,
  text: string,
  source: "static" = "static",
): { parsed: boolean; findings: Finding[] } {
  const { parsed, data } = tryParseYaml(text);
  const findings: Finding[] = [];
  if (!parsed) return { parsed: false, findings };

  const walk = (node: unknown, path: string) => {
    if (Array.isArray(node)) {
      node.forEach((value, index) => walk(value, `${path}[${index}]`));
      return;
    }
    if (node && typeof node === "object") {
      const obj = node as Record<string, unknown>;
      const id = typeof obj.id === "string" ? obj.id : "";
      const name = typeof obj.name === "string" ? obj.name : "";

      if (id && SECURITY_ROW_IDS.includes(id) && obj.disabled === true) {
        findings.push(
          buildDshFinding(
            DSH_SPECIFIC_RULES[0],
            `${fileLabel}: disables security row '${id}'`,
            source,
          ),
        );
      }
      if (name && DANGEROUS_LOADER_NAMES.includes(name)) {
        findings.push(
          buildDshFinding(
            DSH_SPECIFIC_RULES[0],
            `${fileLabel}: references dangerous loader '${name}'`,
            source,
          ),
        );
      }

      for (const [key, value] of Object.entries(obj)) {
        walk(value, `${path}.${key}`);
      }
    }
  };

  walk(data, "$");
  return { parsed: true, findings };
}

function scanProfileConfigStructure(
  fileLabel: string,
  text: string,
  source: "static" = "static",
): { parsed: boolean; findings: Finding[] } {
  const base = basename(fileLabel).toLowerCase();
  const findings: Finding[] = [];

  if (base === "package.json") {
    try {
      const pkg = JSON.parse(text) as {
        dsh?: {
          profile?: { bundles?: unknown };
          bundle?: { patch?: unknown };
        };
      };
      const bundles = pkg.dsh?.profile?.bundles;
      if (Array.isArray(bundles)) {
        const suspicious = bundles.filter((b) =>
          SUSPICIOUS_BUNDLE_RE.test(String(b)),
        );
        if (suspicious.length > 0) {
          findings.push(
            buildDshFinding(
              DSH_SPECIFIC_RULES[2],
              `${fileLabel}: suspicious dsh.profile.bundles: ${suspicious.join(", ")}`,
              source,
            ),
          );
        }
      }
      const patch = pkg.dsh?.bundle?.patch;
      if (typeof patch === "string" && /^(?:https?:|git\+|\.\.\/)/i.test(patch)) {
        findings.push(
          buildDshFinding(
            DSH_SPECIFIC_RULES[2],
            `${fileLabel}: dsh.bundle.patch points outside package: ${patch}`,
            source,
          ),
        );
      }
      return { parsed: true, findings };
    } catch {
      return { parsed: false, findings };
    }
  }

  if (/pnpm-workspace\.ya?ml$/i.test(fileLabel)) {
    const { parsed } = tryParseYaml(text);
    return { parsed, findings };
  }

  return { parsed: false, findings };
}

function scanProfileTamperPatterns(
  fileLabel: string,
  text: string,
  source: "static" = "static",
): Finding[] {
  const findings: Finding[] = [];
  const tamperPatterns: Array<{ re: RegExp; desc: string }> = [
    {
      re: /disabled\s*:\s*true[\s\S]{0,150}?(?:tool-bash|tool-pwsh|approval|permission|session-telemetry-otel|llm-deepseek)/i,
      desc: "disables a DSH security row",
    },
    {
      re: /(?:tool-bash|tool-pwsh|approval|permission|session-telemetry-otel|llm-deepseek)[\s\S]{0,150}?disabled\s*:\s*true/i,
      desc: "disables a DSH security row",
    },
    {
      re: /["']bundles["'][\s\S]{0,120}?["'](?:evil|malicious|hack|backdoor|exfil|miner|keylog)[^"']*["']|dsh\.profile\.bundles[\s\S]{0,200}?["'](?:evil|malicious|hack|backdoor|exfil|miner|keylog)[^"']*["']/i,
      desc: "adds a suspicious DSH bundle",
    },
    {
      re: /(?:writeFile|appendFile|copyFile|rename|mkdir|exec|spawn|chmod)[^\n]{0,100}(?:\.dsh|profiles|cordis\.patch\.ya?ml)/i,
      desc: "writes/executes against DSH profile",
    },
    {
      re: /(?:\.dsh|profiles|cordis\.patch\.ya?ml)[^\n]{0,100}(?:writeFile|appendFile|copyFile|rename|mkdir|exec|spawn|chmod)/i,
      desc: "writes/executes against DSH profile",
    },
  ];
  for (const p of tamperPatterns) {
    if (p.re.test(text)) {
      findings.push(
        buildDshFinding(
          DSH_SPECIFIC_RULES[2],
          `${fileLabel}: ${p.desc}`,
          source,
        ),
      );
    }
  }
  return findings;
}

function scanDshSpecific(fileLabel: string, text: string, source: "static" = "static"): Finding[] {
  const findings: Finding[] = [];
  const lowerFile = fileLabel.toLowerCase();

  // R010: cordis.patch.yml plugin tree injection (structure-aware when YAML parses)
  if (/cordis\.patch\.ya?ml$/i.test(lowerFile) || basename(lowerFile) === "cordis.patch.yml") {
    const structured = scanCordisPatchStructure(fileLabel, text, source);
    if (structured.parsed) {
      findings.push(...structured.findings);
    } else {
      // Fallback for malformed YAML: keep the previous regex heuristics.
      const hasInsert = /(?:^|\n)\s*- insert:/m.test(text);
      const dangerousNameHit = DANGEROUS_LOADER_NAMES.find((name) => text.includes(name));
      if (hasInsert && dangerousNameHit) {
        findings.push(
          buildDshFinding(
            DSH_SPECIFIC_RULES[0],
            `${fileLabel}: contains '- insert:' of ${dangerousNameHit}`,
            source,
          ),
        );
      }
      for (const id of SECURITY_ROW_IDS) {
        const disableRe = new RegExp(
          `id:\\s*['"]?${escapeRegExp(id)}['"]?[\\s\\S]{0,200}?disabled:\\s*true`,
          "i",
        );
        const disableRe2 = new RegExp(
          `${escapeRegExp(id)}[\\s\\S]{0,80}?disabled:\\s*true`,
          "i",
        );
        if (disableRe.test(text) || disableRe2.test(text)) {
          findings.push(
            buildDshFinding(
              DSH_SPECIFIC_RULES[0],
              `${fileLabel}: disables security row '${id}'`,
              source,
            ),
          );
        }
      }
    }
  }

  // R011: client.mjs / browser-side malicious code
  if (isClientFile(fileLabel)) {
    const clientPatterns: Array<{ re: RegExp; desc: string }> = [
      { re: /navigator\.sendBeacon\s*\(|sendBeacon\s*\(/, desc: "sendBeacon exfiltration" },
      {
        re: /new\s+WebSocket\s*\(\s*["'](?!wss?:\/\/)(?!ws:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0))/i,
        desc: "WebSocket to non-local endpoint",
      },
      {
        re: /addEventListener\s*\(\s*["'](?:keydown|keypress|input|change|paste)["']/i,
        desc: "input/key logging listener",
      },
      { re: /navigator\.clipboard|clipboardData|readText\s*\(/, desc: "clipboard read" },
      {
        re: /document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(/,
        desc: "DOM injection",
      },
      { re: /postMessage\s*\(\s*[^,]+,\s*["']\*["']/, desc: "postMessage to *" },
      {
        re: /atob\s*\(|String\.fromCharCode|eval\s*\(|new\s+Function\s*\(/,
        desc: "obfuscated/eval client code",
      },
      {
        re: /fetch\s*\(\s*["']https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|(?:[a-z0-9-]+\.)*(?:local|example)(?:\/|:|\s|["']|$))/i,
        desc: "external fetch from client code",
      },
    ];
    for (const p of clientPatterns) {
      const m = p.re.exec(text);
      if (m) {
        findings.push(
          buildDshFinding(
            DSH_SPECIFIC_RULES[1],
            `${fileLabel}: ${p.desc} (${m[0].slice(0, 120)})`,
            source,
          ),
        );
      }
    }
  }

  // R012: profile configuration tampering
  if (isProfileConfigFile(fileLabel) || (isCodeFile(fileLabel) && /(?:\.dsh|profiles|cordis\.patch\.ya?ml)/i.test(text))) {
    if (isProfileConfigFile(fileLabel)) {
      const structured = scanProfileConfigStructure(fileLabel, text, source);
      if (structured.parsed) {
        findings.push(...structured.findings);
      } else {
        findings.push(...scanProfileTamperPatterns(fileLabel, text, source));
      }
    } else {
      findings.push(...scanProfileTamperPatterns(fileLabel, text, source));
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
    findings.push(...scanDshManifest(resolved));
  } else if (resolved.toLowerCase().endsWith(".zip")) {
    sourceLabel = resolved;
    const tmp = mkdtempSync(join(tmpdir(), "dshscan-zip-"));
    try {
      const zip = new AdmZip(resolved);
      const entries = zip.getEntries();
      const unsafeEntry = entries.find((entry) => {
        const name = entry.entryName.replace(/\\/g, "/");
        return name.startsWith("/") || name.split("/").includes("..");
      });
      if (unsafeEntry) {
        findings.push({
          id: "E006",
          severity: "high",
          category: "zip-slip",
          title: "Unsafe zip entry path (zip-slip)",
          evidence: `${basename(resolved)}: ${unsafeEntry.entryName}`,
          recommendation:
            "Reject this zip: it contains paths that could escape the extraction directory.",
          source: "static",
          rule: "E006",
        });
      } else {
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

  const bareName = meta.name.toLowerCase().replace(/^@[^/]+\//, "");
  for (const known of KNOWN_PLUGIN_NAMES) {
    if (
      bareName !== known &&
      bareName.length >= 4 &&
      known.length >= 4 &&
      levenshtein(bareName, known) <= 2
    ) {
      findings.push({
        id: "M005",
        severity: "high",
        category: "metadata-risk",
        title: "Possible typosquatting / name confusion",
        evidence: `${meta.name} is visually similar to known plugin '${known}'`,
        recommendation:
          "Verify the maintainer and repository carefully. Typosquatting is a common supply-chain attack vector.",
        source,
        rule: "M005",
      });
      break;
    }
  }

  return findings;
}

export function computeScore(findings: Finding[], _meta: PluginMeta | null): number {
  // 元数据风险已通过 M001-M004 findings 进入计分，这里不再做二次加减，
  // 避免同一信号被重复计分。
  const byCategory = new Map<string, number>();
  for (const f of findings) {
    if (f.source === "semantic") continue;
    const w = SEVERITY_WEIGHTS[f.severity] ?? 0;
    byCategory.set(f.category, Math.max(byCategory.get(f.category) ?? 0, w));
  }
  let score = 0;
  for (const w of byCategory.values()) score += w;

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
      if (opts.audit) findings.push(...runNpmAudit(target.localPath));
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
          if (opts.audit) findings.push(...runNpmAudit(tmp));
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
    if (opts.offline) {
      findings.push({
        id: "E004",
        severity: "medium",
        category: "scan-limitation",
        title: "npm package source not downloaded (offline mode)",
        evidence: `${target.metadata.name} (npm=true, cmd=${target.metadata.cmd ?? ""})`,
        recommendation:
          "Re-run without --offline to download and scan the npm package, or provide a local directory of the package.",
        source: "static",
        rule: "E004",
      });
      sourceAvailable = false;
    } else {
      const raw = scanNpmPackage(target.metadata.name);
      if (raw) {
        findings.push(...raw.findings);
        readmeText = raw.readmeText;
        codeExcerpts = raw.codeExcerpts;
      } else {
        findings.push({
          id: "E004",
          severity: "high",
          category: "scan-limitation",
          title: "Failed to download npm package source",
          evidence: `${target.metadata.name} (npm=true)`,
          recommendation:
            "Check npm registry access or install the package in a sandbox and scan its unpacked contents.",
          source: "static",
          rule: "E004",
        });
        sourceAvailable = false;
      }
    }
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
    version: VERSION,
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


