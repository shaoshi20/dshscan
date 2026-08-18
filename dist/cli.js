import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { loadIndex, resolveTarget, scanTarget } from "./scanner.js";
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
  -h, --help               Show this help
      --version            Show version
`;
export async function main(argv = process.argv.slice(2)) {
    let values;
    let positionals;
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
                help: { type: "boolean", short: "h" },
                version: { type: "boolean" },
            },
            allowPositionals: true,
        });
        values = parsed.values;
        positionals = parsed.positionals;
    }
    catch (err) {
        console.error(`dshscan: ${err instanceof Error ? err.message : String(err)}`);
        console.error(USAGE);
        return 2;
    }
    if (values.help) {
        console.log(USAGE);
        return 0;
    }
    if (values.version) {
        console.log("DShScan 0.1.0");
        return 0;
    }
    if (positionals.length === 0) {
        console.error(USAGE);
        return 2;
    }
    const targetRaw = positionals[0];
    // 索引缺失/损坏不应让整个扫描崩溃：降级为无元数据通道并提示。
    let plugins = [];
    try {
        plugins = loadIndex(values.index);
    }
    catch (err) {
        console.error(`dshscan: warning: cannot read plugin index (${err instanceof Error ? err.message : String(err)}); metadata channel disabled`);
    }
    const target = resolveTarget(targetRaw, plugins, values.offline ?? false);
    const opts = {
        indexPath: values.index,
        offline: values.offline ?? false,
        semantic: values.semantic ?? false,
        llmModel: values["llm-model"],
        llmBaseUrl: values["llm-base-url"],
        llmApiKey: values["llm-api-key"],
    };
    let report;
    try {
        report = await scanTarget(target, opts);
    }
    catch (err) {
        console.error(`dshscan: scan failed: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
    }
    const json = JSON.stringify(report, null, values.pretty ? 2 : 0);
    if (values.output) {
        writeFileSync(values.output, json, "utf-8");
        console.error(`Report written to ${values.output}`);
    }
    else {
        console.log(json);
    }
    return 0;
}
//# sourceMappingURL=cli.js.map