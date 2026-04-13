# Sigma Stack Audit

Full-spectrum security audit combining five analysis layers into a living audit registry.

**[Dashboard](https://copyleftdev.github.io/sigma-audit/)** | **[cal.com Report](https://copyleftdev.github.io/sigma-audit/reports/calcom-cal.com/)**

## How It Works

Run the script against any GitHub repo. It audits across five layers, generates an interactive report, and optionally publishes it to the dashboard.

```bash
# Audit locally
python3 sigma-audit.py calcom/cal.com

# Audit and publish to the live dashboard
python3 sigma-audit.py calcom/cal.com --publish
```

Every `--publish` updates the dashboard automatically — no manual steps.

## Five Layers

| Layer | Tool | Finds |
|-------|------|-------|
| **Structure** | [Vajra](https://github.com/copyleftdev/vajra) | Dependency health, structural anomalies |
| **Code** | [Semgrep](https://semgrep.dev) | XSS, injection, weak crypto (OWASP SAST) |
| **Patterns** | [Zentinel](https://github.com/copyleftdev/zentinel) | Hardcoded secrets, raw SQL, missing CSRF, old TLS |
| **Supply Chain** | [VulnGraph MCP](https://vulngraph.tools) | CVE intel, EPSS, exploit PoCs, ATT&CK mapping |
| **Issues** | GitHub API | Existing advisories and issue cross-reference |

## What Each CVE Gets

- **EPSS score** — probability of exploitation in the next 30 days
- **Exploit maturity** — WEAPONIZED / FUNCTIONAL / POC / NONE
- **Proof-of-concept links** — ExploitDB, GitHub PoCs, Nuclei templates, Sigma rules
- **CWE classification** — root cause weakness
- **ATT&CK techniques** — mapped via CAPEC bridge (CWE -> CAPEC -> ATT&CK)
- **Remediation** — vulnerable version ranges and fix versions
- **GitHub issues** — whether it's already been reported

## Architecture

```
  sigma-audit.py calcom/cal.com --publish
          |
    +-----+-----+-----+-----+
    |     |     |     |     |
  Clone  Deps  SAST  Zent  MCP
    |     |     |     |     |
    +-----+-----+-----+-----+
          |
    +-----------+
    | VulnGraph |  analyze_deps -> exploit_intel -> attack_surface
    |    MCP    |  15 CVEs deep-dived, kill chains mapped
    +-----------+
          |
    GitHub Issues Cross-Reference
          |
    Generate Kinetic HTML Report
          |
    Push to sigma-audit repo
          |
    docs/reports/<slug>/index.html  <- individual report
    docs/reports/manifest.json      <- dashboard reads this
    docs/index.html                 <- dashboard auto-populates
          |
    GitHub Pages deploys automatically
```

## Dashboard

The [dashboard](https://copyleftdev.github.io/sigma-audit/) dynamically loads `manifest.json` and renders a card for each audited repo showing:

- CVE count and severity breakdown
- Exploit maturity (weaponized/functional count)
- Attack chain count and ATT&CK technique coverage
- Top CVE with CVSS and EPSS scores
- Overall risk level
- Click-through to the full interactive report

Adding a new audit is one command: `python3 sigma-audit.py owner/repo --publish`

## Requirements

- Python 3.8+
- [Semgrep](https://semgrep.dev/docs/getting-started/)
- [Zentinel](https://github.com/copyleftdev/zentinel)
- [VulnGraph MCP server](https://vulngraph.tools) running locally
- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated

## License

MIT
