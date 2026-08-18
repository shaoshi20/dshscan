# Security Policy

DShScan is a security tool that analyzes untrusted DSH plugins. We take security
reports seriously.

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Report privately by email or GitHub Private Vulnerability Reporting:

- GitHub Security Advisories: https://github.com/shaoshi20/dshscan/security/advisories/new
- Email: please open a private advisory first; if email is required, use the
  address listed on the GitHub profile.

Include in your report:

- Affected version(s)
- Steps to reproduce
- Impact description
- Any suggested fix (optional)

## Scope

- Scanner code execution / RCE via malicious plugin content
- Zip-slip or path traversal in archive handling
- Prompt injection into the semantic audit LLM
- Information disclosure (e.g., leaking local paths or secrets)
- Denial of service via pathological inputs (large files, deep recursion, regex backtracking)

## Response

We aim to acknowledge reports within 3 business days and provide a fix/patch
timeline. Security fixes are released as soon as practical.
