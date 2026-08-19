# DShScan 插件市场批量风险报告

- 生成时间：2026-08-19
- 工具版本：DShScan 0.3.1
- 扫描范围：dshbase 插件目录（1719 个插件）
- 扫描模式：离线批量扫描（`--batch --all --offline`）
- 数据源：dshbase 本地索引 `dshbase-directory.json`

> ⚠️ 离线模式只基于索引元数据 + 静态限制分析，**未拉取源码**。下列插件表示“需要优先人工复核”，不直接等于恶意。

## 总览

| 指标 | 数量 |
|---|---:|
| 扫描插件总数 | 1719 |
| 风险等级 critical | 0 |
| 风险等级 high | 0 |
| 风险等级 medium | 1335 |
| 风险等级 low | 384 |
| `safe_to_install=false` | 4 |
| 命中疑似 typosquatting（M005） | 4 |

> 大量 medium 主要来自离线模式下的 `E002 Remote source not scanned`，不代表真实风险。

## 需重点人工复核的插件

按风险分排序，共 4 个：

| 插件 | 风险分 | 严重级 | 安全安装 | 命中 |
|---|---:|---|---:|---|
| DSH-Plugins-Marketplace | 45 | medium | ❌ | M005 疑似仿冒 + E002 未拉源码 |
| ds-web-ui | 45 | medium | ❌ | M005 疑似仿冒 + M002 低 stars + E002 |
| dsh-skills-viewer | 45 | medium | ❌ | M005 疑似仿冒 + M002 低 stars + E002 |
| dsh-fusion | 45 | medium | ❌ | M005 疑似仿冒 + M002 低 stars + E002 |

### 详情

#### 1. DSH-Plugins-Marketplace
- 仓库：`github:bradeGithub/DSH-Plugins-Marketplace`
- Stars：123 / verified：true / trust：silver
- 风险点：名称与知名 `dsh-plugin-marketplace` 高度相似，触发 M005 typosquatting 提示
- 建议：核对仓库所有者与历史，再决定是否安装

#### 2. ds-web-ui
- 仓库：`github:xing-shuyin/ds-web-ui`
- Stars：2 / verified：true / trust：silver
- 风险点：名称与 `dsh-web-ui` 相似；stars 极低
- 建议：低星 + 疑似仿冒，安装前重点审查

#### 3. dsh-skills-viewer
- 仓库：`github:winterhuan/dsh-skills-viewer`
- Stars：1 / verified：true / trust：silver
- 风险点：名称与 `dsh-skill-viewer` 相似；stars 极低
- 建议：低星 + 疑似仿冒，安装前重点审查

#### 4. dsh-fusion
- 仓库：`github:omdsh-dev/dsh-fusion`
- Stars：1 / verified：true / trust：silver
- 风险点：M005 疑似仿冒；stars 极低
- 建议：低星 + 疑似仿冒，安装前重点审查

## 在线复核结果（已执行）

| 插件 | 风险分 | 严重级 | 安全安装 | Findings | 主要命中 |
|---|---:|---|---:|---:|---|
| DSH-Plugins-Marketplace | 100 | critical | ❌ | 42 | R001 / R012 / R005 / R006 / R011 |
| ds-web-ui | 30 | medium | ✅ | 59 | D001 未锁定依赖 |
| dsh-skills-viewer | 15 | low | ✅ | 9 | D001 未锁定依赖 |
| dsh-fusion | 30 | medium | ✅ | 24 | D001 + R009 prepare 脚本 |

> 注意：`DSH-Plugins-Marketplace` 本身是一个“插件市场/安全扫描类”项目，代码里包含大量 `curl|bash`、`Invoke-Expression` 等**检测规则字符串**，因此 R001/R012 命中可能来自其自身检测逻辑/文档，而非真实恶意行为。需要人工结合上下文判断。

## 建议下一步

- 对 `DSH-Plugins-Marketplace` 做人工代码审计，重点确认 `lib/index.js` 中的检测规则字符串与真实执行路径。
- 其余 3 个主要是依赖未锁定的供应链卫生问题，建议固定版本后使用。
- 如确认安全，可在策略中忽略对应 M005：
  ```json
  { "ignoreRules": ["M005"] }
  ```

## 原始数据

批量扫描 JSON 已保存至：

```text
reports/market-batch.json
```
