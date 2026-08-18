export const SEVERITY_WEIGHTS = {
    low: 5,
    medium: 15,
    high: 30,
    critical: 50,
};
export const RULES = [
    {
        id: "R001",
        severity: "critical",
        category: "remote-code-execution",
        title: "Remote script piped to shell",
        pattern: /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b|(?:ba)?sh\s*[<(]\s*(?:curl|wget)|Invoke-Expression|iex\s+\(/i,
        recommendation: "Remove remote-pipe-to-shell installers. Vendor the script, pin a checksum, and review before execution.",
    },
    {
        id: "R002",
        severity: "high",
        category: "dynamic-code-execution",
        title: "Dangerous dynamic code execution",
        // 只报真正危险的形式：独立 eval(（负向环视排除 pipeline.eval / "locomo-eval"
        // 这类方法名与字符串）、命令位置的 shell `eval "..."`（行首或 ;/&&/|| 后）、
        // new Function / vm 沙箱逃逸 / os.system / child_process 的 shell 变体。
        pattern: /(?<![\w.-])eval\s*\(|(?:^|;|\|\||&&)\s*(?:sudo\s+)?eval\s+["']|new\s+Function\s*\(|vm\.runIn(?:NewContext|ThisContext)\s*\(|os\.system\s*\(|child_process\.(?:exec|execSync)\s*\(/i,
        recommendation: "Avoid arbitrary shell/dynamic execution. If required, validate inputs, use argument arrays, and avoid shell=true.",
    },
    {
        id: "R002b",
        severity: "medium",
        category: "dynamic-code-execution",
        title: "Shell execution with shell:true / shell=True",
        // 单独出现时是弱信号（参数数组 + shell:true 常见于构建脚本）；
        // 与远程内容结合时才升级为高风险（由 R001/R005 覆盖）。
        pattern: /shell\s*[:=]\s*true|(?:subprocess\.(?:call|run|Popen)|Popen)\b[^\n]*shell\s*=\s*True/i,
        recommendation: "Prefer argument arrays without shell:true. If a shell is required, ensure inputs are not attacker-controlled.",
    },
    {
        id: "R003",
        severity: "high",
        category: "obfuscation",
        title: "Obfuscated code pattern",
        pattern: /(?:base64|Buffer\.from|atob|btoa|String\.fromCharCode|fromCharCode|\\x[0-9a-fA-F]{2}|chr\s*\(\s*\d+)[^\n]*(?:eval|exec|Function|compile)|(?:eval|exec|Function)\s*\([^\n]*(?:base64|Buffer\.from|atob|String\.fromCharCode|\\x[0-9a-fA-F]{2}|chr\s*\()/i,
        recommendation: "Decode and inspect the obfuscated payload. Obfuscated installers are a high-risk supply-chain signal.",
    },
    {
        id: "R004",
        severity: "medium",
        category: "network-exfiltration",
        title: "Cleartext HTTP endpoint in code",
        // 排除模板插值（${x} / {x} / %s，含 ${VAR:-http://...} 默认值）、
        // IPv6 回环 [::1]、W3C/XML 命名空间 URI 与本地/示例域名；
        // 只报代码里写死的公网 http:// 端点。
        pattern: /(?<![\w$:{-])http:\/\/(?!\$\{|#\{|\{|%)(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|xmlns\.|purl\.org)[\w./:-]*|(?:[a-z0-9-]+\.)*(?:local|example)(?:\/|:|\s|["']|$)|example\.(?:com|org|net)(?:\/|:|\s|["']|$)|[a-z0-9-]+\.test(?:\/|:|\s|["']|$))[^\s"'`)]+/i,
        recommendation: "Use HTTPS for any network communication. If HTTP is required for local development, ensure it is not used to exfiltrate data.",
    },
    {
        id: "R004b",
        severity: "medium",
        category: "network-exfiltration",
        title: "Hardcoded IP address callback",
        // 排除私网/链路本地/环回段（10.x、172.16-31.x、192.168.x、169.254.x、127.x），
        // 它们在内网配置/测试夹具里太常见；只留公网硬编码 IP 作为弱信号。
        pattern: /(?:https?|wss?|ftp):\/\/(?!127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[^\s"'`)]*|["'`](?!127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}["'`]/i,
        recommendation: "Hardcoded IP endpoints are often staging/exfiltration infrastructure. Resolve the domain and verify ownership.",
    },
    {
        id: "R005",
        severity: "high",
        category: "credential-theft",
        title: "Credential access combined with suspicious code",
        pattern: /(?=.*(?:process\.env|getenv|os\.environ|environ\[|Deno\.env))(?=.*(?:api[_-]?key|secret|token|password|passwd|credential|bearer))(?=.*(?:https?:\/\/|fetch\s*\(|axios|requests\.|urllib|http\.|send|upload|post))/i,
        recommendation: "Avoid reading secrets and sending them to external endpoints. Use secret managers and never log or exfiltrate credentials.",
    },
    {
        id: "R006",
        severity: "high",
        category: "persistence-privilege",
        title: "Persistence or privilege escalation pattern",
        // 只保留真正的持久化/提权信号；chmod +x、sudo、cron 定时、/etc/ 路径、
        // npm install -g 在正常脚本/文档里太常见，删掉以压低误报。
        pattern: /(?:chmod\s+777|systemctl\s+enable|reg\s+add\b[^\n]*\\Run|schtasks\b|launchctl\s+(?:load|submit)|crontab\s+-e|CurrentVersion\\Run|--unsafe-perm)/i,
        recommendation: "Avoid persistent background installs or privilege escalation unless explicitly documented and user-approved.",
    },
    {
        id: "R007",
        severity: "medium",
        category: "package-install-script",
        title: "Package manager install script from remote source",
        pattern: /(?:npm|pnpm|yarn|pip|pip3|gem|cargo|go\s+(?:install|get))\b[^\n]*(?:https?:\/\/|git\+|github\.com|bit\.ly|tinyurl\.com)/i,
        recommendation: "Install packages from the official registry with pinned versions. Review third-party tarball/Git URLs before use.",
    },
    {
        id: "R008",
        severity: "critical",
        category: "prompt-injection",
        title: "Prompt injection / instruction override in documentation",
        // 去掉过宽的 "do not tell/show the user" 分支（agent 插件的安装技能里
        // 正常会隐藏自动化步骤）；保留更强的指令覆盖信号。
        pattern: /(?:ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|above|prior|earlier|system).{0,60}instructions?|disregard\s+.{0,40}instructions?|you\s+are\s+now\s+|\*\*(?:system|developer)\s+prompt\s*\*\*|jailbreak)/i,
        recommendation: "Treat documentation/README as untrusted data. If the plugin instructs the agent to override instructions or hide behavior, do not install.",
    },
];
export function buildFinding(rule, evidence, source = "static") {
    return {
        id: rule.id,
        severity: rule.severity,
        category: rule.category,
        title: rule.title,
        evidence,
        recommendation: rule.recommendation,
        source,
        rule: rule.id,
    };
}
//# sourceMappingURL=rules.js.map