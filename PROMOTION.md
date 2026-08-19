# DShScan 推广素材

## 一句话介绍

> DShScan：给 DeepSeek Harness 插件做“上车前安检”的开源安全扫描器，模仿 NVIDIA SkillSpector，输出风险分、严重等级、证据和安装建议。

## README 增强文案（可选用）

DShScan 是面向 DSH 插件生态的 SkillSpector 式安全审查器：

- 输入插件名 / GitHub 仓库 / 本地目录 / zip / md，输出 `risk_score`、`severity`、`safe_to_install`、`recommendation`、`findings`
- 静态规则 + 可选 LLM 语义双通道
- 覆盖 DSH 特有攻击面：`cordis.patch.yml` 插件树注入、`client.mjs` 浏览器侧恶意代码、profile 配置篡改
- 自动下载 npm 包源码、npm audit、依赖仿冒检测、manifest 校验
- 支持批量扫描、HTML 报告、Web Dashboard、自定义规则/策略
- 已收录于 dshbase 插件市场

## 社区帖子草稿

### V2EX / 掘金

标题：我给 DeepSeek Harness 写了一个插件安全扫描器 DShScan

正文：

最近 DSH 插件生态涨得很快，但插件安装前缺少安全检查。我参考 NVIDIA SkillSpector 做了 DShScan：

- 风险评分 0-100 + 严重等级 + 是否可安全安装
- 静态规则覆盖远程管道执行、混淆、凭据窃取、持久化、提示注入
- DSH 特有规则：cordis.patch.yml 插件树注入、client.mjs 浏览器侧恶意代码、profile 篡改
- 自动 npm pack 扫描真实包内容，支持 npm audit
- 支持批量扫描 dshbase 全部插件
- 已上架 dshbase：`dsh plugin add @shaoshi/dshscan`

安装即用：

```bash
npm i -g @shaoshi/dshscan
dshscan <plugin-name>
dshscan --batch --all --offline
dshscan --serve
```

欢迎 star：https://github.com/shaoshi20/dshscan

### Twitter/X

> I built DShScan, a SkillSpector-style security scanner for DeepSeek Harness plugins.
> Static + optional LLM scanning, DSH-specific attack surface rules, npm source scan, batch audit, web dashboard.
> Already listed on dshbase.
> Try: `npm i -g @shaoshi/dshscan`
> https://github.com/shaoshi20/dshscan

## Awesome 列表提交内容

### awesome-dsh-plugins / awesome-deepseek-harness

```markdown
- [DShScan](https://github.com/shaoshi20/dshscan) - DSH plugin security scanner inspired by NVIDIA SkillSpector: risk score, severity, evidence, install recommendation, static + semantic dual-channel scanning, DSH-specific attack surface rules, npm source scan, batch audit, HTML reports, web dashboard.
```

## 示例命令

```bash
# 单插件扫描
dshscan OpenViking

# 批量扫描 dshbase 前 50
dshscan --batch --limit 50 --index /path/to/dshbase-directory.json

# Web 面板
dshscan --serve --port 8787
```

## 截图

- Demo report: `docs/demo-report.png`
- HTML report: `docs/demo-report.html`
