# DSH-Plugins-Marketplace `lib/index.js` 人工代码审计

- 审计对象：https://github.com/bradeGithub/DSH-Plugins-Marketplace
- 版本：`dsh-plugin-marketplace@1.5.4`
- 审计文件：`lib/index.js`
- 审计时间：2026-08-19
- 结论：**未发现隐蔽后门/凭据外传；但该插件是一个“高权限插件管理器”，会按用户操作执行远端仓库的安装脚本，属于设计内的高风险能力。**

## 一、检测规则（非真实执行，DShScan 部分命中属于误报）

以下代码只是“字符串/正则检测器”，不会执行被检测内容：

| 位置 | 内容 |
|---|---|
| `lib/index.js:2401-2449` | `SCRIPT_HAZARD_PATTERNS`：curl\|bash、iwr\|iex、schtasks、systemctl、凭据文件、shell rc 等正则 |
| `lib/index.js:2451-2467` | `scanScriptHazards()`：读取安装脚本并做静态危险模式扫描 |

DShScan 之前报的 R001/R006 命中这些正则字符串，属于**检测规则本身被检测**，不是真实恶意执行。

## 二、真实执行路径（设计内的高风险能力）

| 位置 | 行为 | 风险 |
|---|---|---|
| `lib/index.js:4077-4105` | 安装 `script` 类型插件时，执行克隆仓库里的 `install.ps1` / `install.sh` | **远程代码执行**（用户发起安装时） |
| `lib/index.js:4107-4169+` | 安装 `cordis-plugin` 时执行 `npm install`，用户确认后执行 build 脚本，写入 profile node_modules / bundle 注册 | 供应链执行面 |
| `lib/index.js:1978-2001` | 通过 `cmd.exe` 启动 npm/pnpm | 包管理器执行 |
| `lib/index.js:2752-2757,2797,3502` | 调用 dsh CLI、git clone | 系统命令执行 |
| `lib/index.js:172,216,252,413,431,453,517,1443,1509,1881,4132` | 写 profile 环境文件、dotenv、反馈文件、已安装清单、缓存、package.json | 持久化/配置修改 |

## 三、已有的安全缓解

- 环境变量白名单/过滤：`buildMinimalEnv()` / `buildFilteredEnv()`
- answers 只放行扫描确认过的环境变量名，`__` 内部键不进环境
- 包名白名单校验 `PKG_NAME_PATTERN`
- 目标路径必须位于 profile node_modules 内（路径穿越防护）
- 安装脚本执行前有 `scanScriptHazards()` 静态危险扫描
- 构建脚本 / npm scripts 需要用户显式确认
- 子模块 URL 只允许 `https://` 与相对路径

## 四、结论

1. **不是恶意后门**：未发现隐藏的凭据回传、混淆 payload 或未授权外联。
2. **是高风险工具**：它会按用户指令执行第三方仓库的安装脚本。若用户从不可信来源安装 `script` 类型插件，等于主动执行远程代码。
3. **DShScan 的 critical 分需要人工修正**：R001/R012 部分来自检测规则误报，但真实执行路径确实存在，因此仍应视为“需要用户高度确认的高权限插件”。

## 建议

- 仅在信任的仓库上使用此插件安装功能。
- 安装 `script` 类型插件前，先人工审查 `install.sh` / `install.ps1`。
- 如不需要“脚本安装”能力，可考虑禁用或限制该插件的安装权限。
