/**
 * DShScan — DSH plugin security scanner.
 *
 * Registers a `dshscan` tool that runs the SkillSpector-style security scanner
 * on a DSH plugin name, GitHub repo, local directory, zip, or Markdown file.
 *
 * @module dshscan
 */
import { defineTool } from "@deepseek-ai/dsh-tools";
import { loadIndex, resolveTarget, scanTarget } from "../dist/scanner.js";

export const name = "dshscan";
export const inject = ["tools"];

export function apply(ctx, config = {}) {
  ctx.tools.register(defineTool({
    name: "dshscan",
    description:
      "Scan a DSH plugin, GitHub repository, local directory, zip, or Markdown file for security risks. Returns a SkillSpector-style JSON report with risk_score, severity, safe_to_install, recommendation, and findings.",
    parameters: {
      target: {
        type: "string",
        required: true,
        description:
          "Plugin name from dshbase, GitHub URL (github:owner/repo), or a local path to a directory/zip/Markdown file.",
      },
      offline: {
        type: "boolean",
        description:
          "Do not clone remote Git repositories; use metadata-only scan when source is unavailable.",
      },
      semantic: {
        type: "boolean",
        description:
          "Enable LLM semantic scan. Requires DSCAN_LLM_API_KEY or OPENAI_API_KEY.",
      },
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args) {
      const indexPath =
        typeof config.index === "string" && config.index ? config.index : undefined;

      let plugins = [];
      try {
        plugins = loadIndex(indexPath);
      } catch {
        // Index is optional; scanner still works for local targets.
      }

      const target = resolveTarget(args.target, plugins, args.offline === true);
      const report = await scanTarget(target, {
        indexPath,
        offline: args.offline === true,
        semantic: args.semantic === true,
      });

      return JSON.stringify(report, null, 2);
    },
  }));
}
