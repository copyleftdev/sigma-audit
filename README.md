# Sigma Stack Audit

Full-spectrum security audit combining five analysis layers into a single actionable report.

**[Live Report: calcom/cal.com](https://copyleftdev.github.io/sigma-audit/)**

## What It Does

One command audits a GitHub repository across five complementary layers:

| Layer | Tool | Finds |
|-------|------|-------|
| **Structure** | [Vajra](https://github.com/copyleftdev/vajra) | Dependency health, structural anomalies |
| **Code** | [Semgrep](https://semgrep.dev) | XSS, injection, weak crypto (OWASP SAST) |
| **Patterns** | [Zentinel](https://github.com/copyleftdev/zentinel) | Hardcoded secrets, raw SQL, missing CSRF, old TLS |
| **Supply Chain** | [VulnGraph MCP](https://vulngraph.tools) | CVE intel, EPSS probability, exploit PoCs, ATT&CK mapping |
| **Issues** | GitHub API | Existing security advisories and issue cross-reference |

Each CVE is enriched with:
- **EPSS score** — probability of exploitation in the next 30 days
- **Exploit maturity** — WEAPONIZED / FUNCTIONAL / POC / NONE
- **Proof-of-concept links** — ExploitDB, GitHub PoCs, Nuclei templates
- **CWE classification** — root cause weakness
- **ATT&CK techniques** — mapped via CAPEC bridge (CWE → CAPEC → ATT&CK)
- **Remediation** — vulnerable version ranges and fix versions
- **GitHub issues** — whether it's already been reported

## Usage

```bash
python3 sigma-audit.py calcom/cal.com
python3 sigma-audit.py vercel/next.js --branch canary --output nextjs-audit.html
```

## Requirements

- Python 3.8+
- [Semgrep](https://semgrep.dev/docs/getting-started/)
- [Zentinel](https://github.com/copyleftdev/zentinel)
- [VulnGraph MCP server](https://vulngraph.tools) running locally
- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated

## Architecture

```
                    sigma-audit.py
                         |
          +--------------+--------------+
          |              |              |
     Clone Repo    Extract Deps    Scan Code
          |              |              |
          v              v              v
    +-----------+  +-----------+  +-----------+
    |  Semgrep  |  | VulnGraph |  | Zentinel  |
    |   SAST    |  |    MCP    |  |  Patterns |
    +-----------+  +-----------+  +-----------+
                         |
              +----------+----------+
              |          |          |
         analyze    exploit    attack
          deps      intel     surface
              |          |          |
              +----------+----------+
                         |
                   GitHub Issues
                   Cross-Reference
                         |
                  Kinetic HTML Report
```

## Report Sections

1. **Executive Summary** — auto-generated prose with key findings
2. **Risk Dashboard** — animated counters for CVEs, severity, exploitability
3. **CVE Intelligence** — expandable cards with full exploit intel, PoC links, ATT&CK mapping
4. **Kill Chains** — visual attack chain flow diagrams (Package → CVE → CWE → Technique)
5. **ATT&CK Grid** — clickable technique badges linked to MITRE
6. **Semgrep SAST** — code-level findings with file locations
7. **Zentinel Patterns** — rule frequency chart and critical findings

## Example Output

The [live report for calcom/cal.com](https://copyleftdev.github.io/sigma-audit/) found:

- **146 CVEs** across 377 npm dependencies
- **4 weaponized/functional exploits** with public PoCs
- **108 attack chains** mapped to **64 ATT&CK techniques**
- **17,102 security pattern findings** including 47 hardcoded secrets
- **10 SAST findings** including XSS and weak crypto

Top finding: [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) — Next.js middleware auth bypass (CVSS 9.1, EPSS 93%, 12 public PoCs).

## License

MIT
