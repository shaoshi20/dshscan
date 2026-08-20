import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { runBenchmark } from "./benchmark.js";
import { loadIndex, resolveTarget, scanTarget, type ScanOptions } from "./scanner.js";
import { RULES } from "./rules.js";
import type { PluginMeta, Policy, ScanReport, Severity } from "./types.js";
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
      --html               Output a standalone HTML report instead of JSON
      --batch              Batch scan dshbase plugins (default offline)
      --limit <number>     Max plugins to scan in batch mode (default 50)
      --all                Scan all plugins in batch mode
      --online             Allow cloning remote repos in batch mode
      --audit              Run npm audit on scanned package dependencies
      --rules <file>       Load additional JSON rules (id,severity,category,title,pattern,recommendation)
      --policy <file>      Load policy JSON (ignoreRules, severityOverrides, includeScopes, excludeScopes)
      --audit-log <file>   Append JSONL audit log for flagged findings
      --serve              Start a local web dashboard
      --port <number>      Port for --serve (default 8787)
      --history <file>     Dashboard trend history file (default ./.dshscan-history.json or DSCAN_HISTORY)
      --benchmark          Run the benchmark evaluation suite
      --benchmark-dir <d>  Benchmark cases directory (default ./benchmark/cases)
  -h, --help               Show this help
      --version            Show version
`;

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderHtmlReport(report: ScanReport): string {
  const findings = report.findings
    .map(
      (f) => `<li><strong>[${escapeHtml(f.severity)}] ${escapeHtml(f.id)}</strong> ${escapeHtml(f.title)}<br><code>${escapeHtml(f.evidence)}</code><br><small>${escapeHtml(f.recommendation)}</small></li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>DShScan Report — ${escapeHtml(report.target.displayName)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#222}
h1{border-bottom:2px solid #eee;padding-bottom:10px}
.badge{display:inline-block;padding:4px 10px;border-radius:12px;color:#fff;font-size:14px}
.critical{background:#c00}.high{background:#e67e22}.medium{background:#f1c40f;color:#222}.low{background:#27ae60}
ul{list-style:none;padding:0}li{background:#f8f9fa;margin:8px 0;padding:10px;border-radius:8px}
code{background:#eee;padding:2px 4px;border-radius:4px}
</style>
</head>
<body>
<h1>DShScan Report</h1>
<p>Target: <strong>${escapeHtml(report.target.displayName)}</strong></p>
<p>Risk Score: <strong>${report.risk_score}</strong> <span class="badge ${escapeHtml(report.severity)}">${escapeHtml(report.severity)}</span></p>
<p>Safe to install: <strong>${report.safe_to_install}</strong></p>
<p>Scan mode: ${escapeHtml(report.scan_mode)}</p>
<p>Findings: ${report.findings.length}</p>
<h2>Findings</h2>
<ul>${findings || "<li>No findings</li>"}</ul>
<h2>Recommendation</h2>
<p>${escapeHtml(report.recommendation)}</p>
</body>
</html>`;
}

function renderHtmlBatch(batch: {
  version: string;
  offline: boolean;
  scanned: number;
  results: Array<Record<string, unknown>>;
}): string {
  const rows = batch.results
    .map((r) => {
      if (r.error) {
        return `<tr><td>${escapeHtml(r.name)}</td><td colspan="5">ERROR ${escapeHtml(r.error)}</td></tr>`;
      }
      return `<tr><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.risk_score)}</td><td>${escapeHtml(r.severity)}</td><td>${escapeHtml(r.safe_to_install)}</td><td>${escapeHtml(r.findings)}</td><td>${escapeHtml(r.scan_mode)}</td></tr>`;
    })
    .join("\n");
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>DShScan Batch Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f4f4f4}
</style>
</head>
<body>
<h1>DShScan Batch Report</h1>
<p>Version ${escapeHtml(batch.version)} · Scanned ${batch.scanned} · Offline ${batch.offline}</p>
<table>
<thead><tr><th>Plugin</th><th>Risk</th><th>Severity</th><th>Safe</th><th>Findings</th><th>Mode</th></tr></thead>
<tbody>${rows}</tbody>
</table>
</body>
</html>`;
}

function loadCustomRules(file: string): void {
  const data = JSON.parse(readFileSync(file, "utf-8")) as Array<Record<string, unknown>>;
  if (!Array.isArray(data)) throw new Error("rules file must be a JSON array");
  for (const item of data) {
    if (
      typeof item.id !== "string" ||
      typeof item.pattern !== "string" ||
      typeof item.title !== "string"
    ) {
      throw new Error("each custom rule needs id, pattern, title");
    }
    const severity = String(item.severity ?? "medium") as Severity;
    RULES.push({
      id: item.id,
      severity,
      category: String(item.category ?? "custom"),
      title: item.title,
      pattern: new RegExp(String(item.pattern), "i"),
      recommendation: String(item.recommendation ?? ""),
    });
  }
}

function loadPolicy(file: string): Policy {
  return JSON.parse(readFileSync(file, "utf-8")) as Policy;
}

function defaultHistoryPath(): string {
  return process.env.DSCAN_HISTORY ?? join(process.cwd(), ".dshscan-history.json");
}

function loadHistory(file: string): Array<Record<string, unknown>> {
  try {
    const data = JSON.parse(readFileSync(file, "utf-8")) as Array<Record<string, unknown>>;
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function appendHistory(file: string, record: Record<string, unknown>): void {
  const history = loadHistory(file);
  history.push(record);
  writeFileSync(file, JSON.stringify(history.slice(-200), null, 2), "utf-8");
}

async function serveDashboard(plugins: PluginMeta[], port: number, values: {
  index?: string;
  offline?: boolean;
  semantic?: boolean;
  audit?: boolean;
  policy?: Policy;
  "audit-log"?: string;
  "llm-model"?: string;
  "llm-base-url"?: string;
  "llm-api-key"?: string;
  history?: string;
}): Promise<number> {
  const historyFile = values.history ?? defaultHistoryPath();
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>DShScan Web Dashboard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;color:#222}
h1{border-bottom:2px solid #eee;padding-bottom:10px}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0;align-items:center}
input,button{font-size:16px;padding:8px;margin:4px 0}
label{display:flex;align-items:center;gap:4px}
pre{background:#f4f4f4;padding:12px;border-radius:8px;overflow:auto;max-height:300px}
.charts{display:flex;flex-wrap:wrap;gap:20px;margin:16px 0}
.chart-box{flex:1 1 400px;border:1px solid #ddd;border-radius:8px;padding:12px}
canvas{width:100%;height:220px}
table{border-collapse:collapse;width:100%;margin-top:12px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}
th{background:#f4f4f4}
</style>
</head>
<body>
<h1>DShScan Web Dashboard</h1>
<div class="controls">
  <input id="target" placeholder="plugin-name / github:owner/repo / path" style="width:50%">
  <button onclick="scan()">Scan</button>
  <label><input id="offline" type="checkbox"> offline</label>
  <label><input id="semantic" type="checkbox"> semantic</label>
  <label><input id="audit" type="checkbox"> audit</label>
</div>
<div class="charts">
  <div class="chart-box"><h3>Risk Score Trend</h3><canvas id="riskChart" height="220"></canvas></div>
  <div class="chart-box"><h3>Findings per Scan</h3><canvas id="findingsChart" height="220"></canvas></div>
  <div class="chart-box"><h3>Severity Distribution</h3><canvas id="severityChart" height="220"></canvas></div>
</div>
<h2>Recent Scans</h2>
<table id="historyTable">
<thead><tr><th>Time</th><th>Target</th><th>Risk</th><th>Severity</th><th>Safe</th><th>Findings</th><th>Mode</th></tr></thead>
<tbody></tbody>
</table>
<h2>Last Report</h2>
<pre id="out">Waiting...</pre>
<script>
var records=[];
function el(id){return document.getElementById(id);}
async function loadHistory(){
  try{
    const res=await fetch('/api/history');
    records=await res.json();
    render();
  }catch(e){console.error(e);}
}
async function scan(){
  const target=el('target').value;
  const offline=el('offline').checked;
  const semantic=el('semantic').checked;
  const audit=el('audit').checked;
  const out=el('out');
  out.textContent='Scanning...';
  try{
    const res=await fetch('/api/scan?target='+encodeURIComponent(target)+'&offline='+offline+'&semantic='+semantic+'&audit='+audit);
    out.textContent=await res.text();
  }catch(e){
    out.textContent='Error: '+e;
  }
  await loadHistory();
}
function render(){
  renderTable();
  renderLine('riskChart', records.map(function(h){return Number(h.risk_score)||0;}), '#e67e22');
  renderLine('findingsChart', records.map(function(h){return Number(h.findings)||0;}), '#3498db');
  renderSeverity();
}
function renderTable(){
  const tbody=el('historyTable').querySelector('tbody');
  tbody.innerHTML='';
  const rows=records.slice().reverse().slice(0,20);
  for(let i=0;i<rows.length;i++){
    const h=rows[i];
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+new Date(h.timestamp).toLocaleString()+'</td><td>'+escapeHtml(h.target)+'</td><td>'+h.risk_score+'</td><td>'+h.severity+'</td><td>'+h.safe_to_install+'</td><td>'+h.findings+'</td><td>'+h.scan_mode+'</td>';
    tbody.appendChild(tr);
  }
}
function escapeHtml(v){
  return String(v==null?'':v).replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function renderLine(canvasId, values, color){
  const canvas=el(canvasId);
  const ctx=canvas.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const w=canvas.clientWidth||canvas.parentNode.clientWidth||600;
  const h=canvas.clientHeight||220;
  canvas.width=w*dpr; canvas.height=h*dpr; ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);
  if(!values.length){
    ctx.fillStyle='#999'; ctx.fillText('No data yet',10,20); return;
  }
  const pad=24;
  const max=Math.max.apply(null,values.concat([100]));
  const min=Math.min.apply(null,values.concat([0]));
  const range=(max-min)||1;
  const n=values.length;
  ctx.strokeStyle='#eee'; ctx.fillStyle='#666'; ctx.font='12px system-ui';
  for(let i=0;i<=4;i++){
    const y=pad+((h-pad*2)*i/4);
    ctx.beginPath(); ctx.moveTo(pad,y); ctx.lineTo(w-pad,y); ctx.stroke();
    const val=max-((max-min)*i/4);
    ctx.fillText(String(Math.round(val)),4,y+4);
  }
  ctx.strokeStyle=color; ctx.lineWidth=2; ctx.beginPath();
  for(let i=0;i<n;i++){
    const x=pad+((w-pad*2)*(n===1?0.5:i/(n-1)));
    const y=pad+((h-pad*2)*(1-(values[i]-min)/range));
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  }
  ctx.stroke();
  ctx.fillStyle=color;
  for(let i=0;i<n;i++){
    const x=pad+((w-pad*2)*(n===1?0.5:i/(n-1)));
    const y=pad+((h-pad*2)*(1-(values[i]-min)/range));
    ctx.beginPath(); ctx.arc(x,y,3,0,Math.PI*2); ctx.fill();
  }
}
function renderSeverity(){
  const canvas=el('severityChart');
  const ctx=canvas.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const w=canvas.clientWidth||canvas.parentNode.clientWidth||600;
  const h=canvas.clientHeight||220;
  canvas.width=w*dpr; canvas.height=h*dpr; ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);
  const sev=['critical','high','medium','low'];
  const colors=['#c0392b','#e67e22','#f1c40f','#27ae60'];
  const counts={critical:0,high:0,medium:0,low:0};
  for(let i=0;i<records.length;i++){
    const s=records[i].severity;
    if(sev.indexOf(s)>=0) counts[s]++;
  }
  const max=Math.max.apply(null,sev.map(function(s){return counts[s];}).concat([1]));
  const pad=24;
  const slot=(w-pad*2)/sev.length;
  ctx.fillStyle='#666'; ctx.font='12px system-ui';
  for(let i=0;i<sev.length;i++){
    const s=sev[i]; const c=counts[s];
    const x=pad+i*slot+slot*0.15;
    const bw=slot*0.7;
    const bh=(h-pad*2)*c/max;
    const y=pad+((h-pad*2)*(1-c/max));
    ctx.fillStyle=colors[i];
    ctx.fillRect(x,y,bw,Math.max(bh,c?2:0));
    ctx.fillStyle='#333';
    ctx.fillText(s+' '+c, x, h-6);
  }
}
loadHistory();
</script>
</body>
</html>`;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/" || url.pathname === "/index.html") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(html);
      return;
    }
    if (url.pathname === "/api/history") {
      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(loadHistory(historyFile)));
      return;
    }
    if (url.pathname === "/api/scan") {
      const target = url.searchParams.get("target") ?? "";
      const offline = url.searchParams.get("offline") === "true";
      const semantic = url.searchParams.get("semantic") === "true";
      const audit = url.searchParams.get("audit") === "true";
      try {
        const t = resolveTarget(target, plugins, offline);
        const report = await scanTarget(t, {
          indexPath: values.index,
          offline,
          semantic,
          audit,
          policy: values.policy,
          auditLog: values["audit-log"],
          llmModel: values["llm-model"],
          llmBaseUrl: values["llm-base-url"],
          llmApiKey: values["llm-api-key"],
        });
        appendHistory(historyFile, {
          timestamp: new Date().toISOString(),
          target: report.target.displayName,
          risk_score: report.risk_score,
          severity: report.severity,
          safe_to_install: report.safe_to_install,
          findings: report.findings.length,
          scan_mode: report.scan_mode,
        });
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(report, null, 2));
      } catch (err) {
        res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        res.end(String(err instanceof Error ? err.message : err));
      }
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("Not found");
  });

  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  console.error(`DShScan dashboard: http://127.0.0.1:${port}`);
  return new Promise<number>(() => {});
}

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
    html?: boolean;
    audit?: boolean;
    rules?: string;
    policy?: string;
    "audit-log"?: string;
    serve?: boolean;
    port?: string;
    history?: string;
    batch?: boolean;
    limit?: string;
    all?: boolean;
    online?: boolean;
    benchmark?: boolean;
    "benchmark-dir"?: string;
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
        html: { type: "boolean" },
        audit: { type: "boolean" },
        rules: { type: "string" },
        policy: { type: "string" },
        "audit-log": { type: "string" },
        serve: { type: "boolean" },
        port: { type: "string" },
        history: { type: "string" },
        batch: { type: "boolean" },
        limit: { type: "string" },
        all: { type: "boolean" },
        online: { type: "boolean" },
        benchmark: { type: "boolean" },
        "benchmark-dir": { type: "string" },
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
  if (!values.batch && !values.benchmark && !values.serve && positionals.length === 0) {
    console.error(USAGE);
    return 2;
  }

  if (values.benchmark) {
    const casesDir = values["benchmark-dir"] ?? join(process.cwd(), "benchmark", "cases");
    let benchmarkFailed = false;
    try {
      const result = runBenchmark(casesDir);
      benchmarkFailed = result.summary.passedCases !== result.summary.totalCases;
      if (values.summary) {
        const lines = [
          `DShScan ${VERSION} — benchmark`,
          `Cases: ${result.summary.passedCases}/${result.summary.totalCases} passed`,
          `TP=${result.summary.tp} FP=${result.summary.fp} FN=${result.summary.fn}`,
          `Precision=${result.summary.precision} Recall=${result.summary.recall} F1=${result.summary.f1}`,
          "",
          ...result.cases.map((c) => {
            const problems = [
              ...c.falseNegatives.map((id) => `missing ${id}`),
              ...c.falsePositives.map((id) => `unexpected ${id}`),
            ];
            return `${c.pass ? "PASS" : "FAIL"} ${c.name}${problems.length ? " — " + problems.join(", ") : ""}`;
          }),
          "",
          "Per-rule:",
          ...Object.entries(result.byRule).map(
            ([id, m]) => `${id}: precision=${m.precision} recall=${m.recall} f1=${m.f1} (tp=${m.tp} fp=${m.fp} fn=${m.fn})`,
          ),
        ];
        if (values.output) {
          writeFileSync(values.output, lines.join("\n"), "utf-8");
          console.error(`Benchmark summary written to ${values.output}`);
        } else {
          console.log(lines.join("\n"));
        }
      } else {
        const json = JSON.stringify(result, null, values.pretty ? 2 : 0);
        if (values.output) {
          writeFileSync(values.output, json, "utf-8");
          console.error(`Benchmark report written to ${values.output}`);
        } else {
          console.log(json);
        }
      }
    } catch (err) {
      console.error(`dshscan: benchmark failed: ${err instanceof Error ? err.message : String(err)}`);
      return 2;
    }
    return benchmarkFailed ? 1 : 0;
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

  if (values.rules) {
    try {
      loadCustomRules(values.rules);
    } catch (err) {
      console.error(`dshscan: failed to load custom rules: ${err instanceof Error ? err.message : String(err)}`);
      return 2;
    }
  }

  let policy: Policy | undefined;
  if (values.policy) {
    try {
      policy = loadPolicy(values.policy);
    } catch (err) {
      console.error(`dshscan: failed to load policy: ${err instanceof Error ? err.message : String(err)}`);
      return 2;
    }
  }

  if (values.serve) {
    const serveValues = { ...values, policy } as Parameters<typeof serveDashboard>[2];
    return await serveDashboard(
      plugins,
      Number(values.port ?? 8787) || 8787,
      serveValues,
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
          audit: values.audit ?? false,
          policy,
          auditLog: values["audit-log"],
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
    if (values.html) {
      const html = renderHtmlBatch(batchReport as Parameters<typeof renderHtmlBatch>[0]);
      if (values.output) {
        writeFileSync(values.output, html, "utf-8");
        console.error(`Batch HTML report written to ${values.output}`);
      } else {
        console.log(html);
      }
    } else if (values.summary) {
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
    audit: values.audit ?? false,
    policy,
    auditLog: values["audit-log"],
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

  if (values.html) {
    const html = renderHtmlReport(report);
    if (values.output) {
      writeFileSync(values.output, html, "utf-8");
      console.error(`HTML report written to ${values.output}`);
    } else {
      console.log(html);
    }
  } else if (values.summary) {
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
