import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { loadIndex, resolveTarget, scanTarget, type ScanOptions } from "./scanner.js";
import type { PluginMeta, ScanReport } from "./types.js";
import { VERSION } from "./version.js";

const USAGE = `DShScan - DSH plugin security scanner (SkillSpector-style)

Usage:
  dshscan <plugin-name|repo-url|local-directory|zip|md-file> [options]

Options:
  -i, --index <path>       Path to dshbase-directory.json (default: local index)
      --offline            Do not clone remote Git repositories; metadata-only scan
  -s, --semantic           Enable LLM semantic scan (requires DSCAN_LLM_API_KEY/OPENAI_API_KEY)
      --llm-model <model>  Override LLM model (default: DSCAN_LLM_MODEL or gpt-4o-mini)
      --llm-base-url <url> Override OpenAI-compatible base URL (default: DSCAN_LLM_BASE_URL or https://api.openai.com/v1)
      --llm-api-key <key>  Override LLM API key (default: DSCAN_LLM_API_KEY or OPENAI_API_KEY)
  -o, --output <file>      Write JSON report to file instead of stdout
  -p, --pretty             Pretty-print JSON output
      --summary            Print a human-readable summary instead of JSON
      --batch              Batch scan dshbase plugins (default offline)
      --limit <number>     Max plugins to scan in batch mode (default 50)
      --all                Scan all plugins in batch mode
      --online             Allow cloning remote repos in batch mode
  -h, --help               Show this help
      --version            Show version
`;

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let values: {
    index?: string;
    offline?: boolean;
    semantic?: boolean;
    "llm-model"?: string;
    "llm-base-url"?: string;
    "llm-api-key"?: string;
    output?: string;
    pretty?: boolean;
    summary?: boolean;
    batch?: boolean;
    limit?: string;
    all?: boolean;
    online?: boolean;
    help?: boolean;
    version?: boolean;
  };
  let positionals: string[];

  try {
    const parsed = parseArgs({
      options: {
        index: { type: "string", short: "i" },
        offline: { type: "boolean" },
        semantic: { type: "boolean", short: "s" },
        "llm-model": { type: "string" },
        "llm-base-url": { type: "string" },
        "llm-api-key": { type: "string" },
        output: { type: "string", short: "o" },
        pretty: { type: "boolean", short: "p" },
        summary: { type: "boolean" },
        batch: { type: "boolean" },
        limit: { type: "string" },
        all: { type: "boolean" },
        online: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean" },
      },
      allowPositionals: true,
    });
    values = parsed.values as typeof values;
    positionals = parsed.positionals;
  } catch (err) {
    console.error(`dshscan: ${err instanceof Error ? err.message : String(err)}`);
    console.error(USAGE);
    return 2;
  }

  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (values.version) {
    console.log(`DShScan ${VERSION}`);
    return 0;
  }
  if (!values.batch && positionals.length === 0) {
    console.error(USAGE);
    return 2;
  }

  const targetRaw = positionals[0] ?? "";
  // 索引缺失/损坏不应让整个扫描崩溃：降级为无元数据通道并提示。
  let plugins: PluginMeta[] = [];
  try {
    plugins = loadIndex(values.index);
  } catch (err) {
    console.error(
      `dshscan: warning: cannot read plugin index (${err instanceof Error ? err.message : String(err)}); metadata channel disabled`,
    );
  }

  if (values.batch) {
    const limit = values.all
      ? plugins.length
      : Math.max(1, Math.min(Number(values.limit ?? 50) || 50, plugins.length));
    const selected = values.all
      ? plugins
      : [...plugins].sort((a, b) => (b.stars ?? 0) - (a.stars ?? 0)).slice(0, limit);
    const offline = !(values.online ?? false);
    const results: Array<Record<string, unknown>> = [];

    for (const meta of selected) {
      try {
        const t = resolveTarget(meta.name, plugins, offline);
        const r = await scanTarget(t, {
          indexPath: values.index,
          offline,
          semantic: values.semantic ?? false,
          llmModel: values["llm-model"],
          llmBaseUrl: values["llm-base-url"],
          llmApiKey: values["llm-api-key"],
        });
        results.push({
          name: meta.name,
          stars: meta.stars ?? 0,
          trust: meta.trust ?? "",
          verified: meta.verified ?? false,
          risk_score: r.risk_score,
          severity: r.severity,
          safe_to_install: r.safe_to_install,
          findings: r.findings.length,
          scan_mode: r.scan_mode,
        });
      } catch (err) {
        results.push({
          name: meta.name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const batchReport = {
      tool: "DShScan",
      version: VERSION,
      mode: "batch",
      generatedAt: new Date().toISOString(),
      offline,
      scanned: results.length,
      results,
    };
    if (values.summary) {
      const lines = [
        `DShScan ${VERSION} — batch scan`,
        `Scanned: ${results.length}`,
        `Offline: ${offline}`,
        "",
        ...results.map((r) => {
          const rec = r as Record<string, unknown>;
          if (rec.error) return `${rec.name}: ERROR ${rec.error}`;
          return `${rec.name}: risk=${rec.risk_score} severity=${rec.severity} safe=${rec.safe_to_install} findings=${rec.findings} (${rec.scan_mode})`;
        }),
      ];
      if (values.output) {
        writeFileSync(values.output, lines.join("\n"), "utf-8");
        console.error(`Batch summary written to ${values.output}`);
      } else {
        console.log(lines.join("\n"));
      }
    } else {
      const json = JSON.stringify(batchReport, null, values.pretty ? 2 : 0);
      if (values.output) {
        writeFileSync(values.output, json, "utf-8");
        console.error(`Batch report written to ${values.output}`);
      } else {
        console.log(json);
      }
    }
    return 0;
  }

  const target = resolveTarget(targetRaw, plugins, values.offline ?? false);

  const opts: ScanOptions = {
    indexPath: values.index,
    offline: values.offline ?? false,
    semantic: values.semantic ?? false,
    llmModel: values["llm-model"],
    llmBaseUrl: values["llm-base-url"],
    llmApiKey: values["llm-api-key"],
  };

  let report: ScanReport;
  try {
    report = await scanTarget(target, opts);
  } catch (err) {
    console.error(`dshscan: scan failed: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }

  if (values.summary) {
    const lines = [
      `DShScan ${VERSION}`,
      `Target: ${report.target.displayName}`,
      `Risk score: ${report.risk_score}`,
      `Severity: ${report.severity}`,
      `Safe to install: ${report.safe_to_install}`,
      `Scan mode: ${report.scan_mode}`,
      `Findings: ${report.findings.length}`,
      "",
      ...report.findings.slice(0, 20).map(
        (f) => `- [${f.severity}] ${f.id} ${f.title}\n  ${f.evidence}`,
      ),
      "",
      `Recommendation: ${report.recommendation}`,
    ];
    if (values.output) {
      writeFileSync(values.output, lines.join("\n"), "utf-8");
      console.error(`Summary written to ${values.output}`);
    } else {
      console.log(lines.join("\n"));
    }
  } else {
    const json = JSON.stringify(report, null, values.pretty ? 2 : 0);
    if (values.output) {
      writeFileSync(values.output, json, "utf-8");
      console.error(`Report written to ${values.output}`);
      console.error(
        `Summary: risk_score=${report.risk_score} severity=${report.severity} safe_to_install=${report.safe_to_install} findings=${report.findings.length}`,
      );
    } else {
      console.log(json);
    }
  }

  return 0;
}
