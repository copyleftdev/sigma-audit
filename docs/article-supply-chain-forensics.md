---
title: "We Audited 10 Popular Open-Source Projects. Here's the Supply Chain Map No One's Talking About."
published: true
description: "Forensic analysis of npm supply chain risk across 10 major projects. Every claim is verifiable. Every number has a curl command."
tags: security, npm, supplychain, opensource
canonical_url: https://copyleftdev.github.io/sigma-audit/
cover_image: 
---

## Methodology

We built a five-layer security audit pipeline — [Vajra](https://github.com/copyleftdev/vajra) for structural analysis, [Semgrep](https://semgrep.dev) for SAST, [Zentinel](https://github.com/copyleftdev/zentinel) for pattern scanning, [VulnGraph MCP](https://vulngraph.tools) for CVE/exploit/ATT&CK intelligence, and the GitHub API for issue cross-referencing — and ran it against 10 widely-used open-source projects:

| Project | Stars | Language | Deps |
|---------|-------|----------|------|
| [calcom/cal.com](https://github.com/calcom/cal.com) | 39K | TypeScript | 377 |
| [directus/directus](https://github.com/directus/directus) | 30K | TypeScript | 316 |
| [payloadcms/payload](https://github.com/payloadcms/payload) | 35K | TypeScript | 315 |
| [fastify/fastify](https://github.com/fastify/fastify) | 36K | JavaScript | 53 |
| [strapi/strapi](https://github.com/strapi/strapi) | 67K | TypeScript | 394 |
| [drizzle-team/drizzle-orm](https://github.com/drizzle-team/drizzle-orm) | 34K | TypeScript | 130 |
| [unjs/nitro](https://github.com/unjs/nitro) | 11K | TypeScript | 143 |
| [elysiajs/elysia](https://github.com/elysiajs/elysia) | 18K | TypeScript | 25 |
| [pallets/flask](https://github.com/pallets/flask) | 70K | Python | 20 |
| [django/django](https://github.com/django/django) | 83K | Python | 6 |

Every audit ran the full pipeline: dependency extraction, CVE lookup enriched with EPSS exploit probability and ATT&CK technique mapping, static analysis, and pattern scanning. The raw data, individual reports, and the live dashboard are at **[copyleftdev.github.io/sigma-audit](https://copyleftdev.github.io/sigma-audit/)**.

This article isn't about the CVEs themselves. It's about what the CVE data reveals when you look at it as a *supply chain graph*.

---

## Finding 1: Four npm Packages Have a Single Point of Failure

These packages have exactly **one npm maintainer** — a single human with full publish access, no co-signer, no organizational backup:

### axios — 98 million weekly downloads, 1 maintainer

```
$ curl -s "https://registry.npmjs.org/axios" | jq ".maintainers"
[
  {
    "name": "jasonsaayman",
    "email": "jasonsaayman@gmail.com"
  }
]
```

**One person** controls the HTTP client used by 98 million installs per week. Axios has 134 published versions and 9 CVEs in our corpus, including [CVE-2024-39338](https://nvd.nist.gov/vuln/detail/CVE-2024-39338) (SSRF) and [CVE-2021-3749](https://nvd.nist.gov/vuln/detail/CVE-2021-3749) (ReDoS, CVSS 7.5). The package appeared in 3 of our 10 audited projects.

### mysql2 — 8.6 million weekly downloads, 1 maintainer

```
$ curl -s "https://registry.npmjs.org/mysql2" | jq ".maintainers"
[
  {
    "name": "sidorares",
    "email": "sidorares@yandex.com"
  }
]
```

Sole control of the most popular MySQL driver for Node.js. 278 versions, 4 CVEs including [CVE-2024-21508](https://nvd.nist.gov/vuln/detail/CVE-2024-21508) (code injection, CVSS 9.8).

### h3 — Powers all Nuxt/Nitro HTTP, 1 maintainer

```
$ curl -s "https://registry.npmjs.org/h3" | jq ".maintainers"
[
  {
    "name": "pi0",
    "email": "pooya@pi0.io"
  }
]
```

h3 is the HTTP framework under [Nitro](https://github.com/unjs/nitro), which powers Nuxt. 139 versions, 4 CVEs in 2026 alone. A compromised `@pi0` npm token would affect every Nuxt application.

### elysia — 678 versions, 1 maintainer

```
$ curl -s "https://registry.npmjs.org/elysia" | jq ".maintainers"
[
  {
    "name": "aomkirby123",
    "email": "saltyaom@gmail.com"
  }
]
```

The Bun-native framework. 678 published versions from a single account. 3 CVEs in our corpus.

**Verify any of these yourself:**
```bash
curl -s "https://registry.npmjs.org/<package>" | jq ".maintainers"
```

### Why this matters

npm [requires only an email and password](https://docs.npmjs.com/creating-a-new-user-account-on-the-www) to create an account. npm tokens can be stolen from CI logs, `.npmrc` files committed to repos, or phished. The [ua-parser-js incident](https://github.com/nicknisi/ua-parser-js/issues/536) (2021, 8M weekly downloads) and [event-stream incident](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident) (2018) both followed this exact pattern: single maintainer, one compromised credential, millions of downstream installs poisoned.

---

## Finding 2: jsonwebtoken Maintainers Have Completely Turned Over

This one is structural, not a vulnerability.

```
$ curl -s "https://registry.npmjs.org/jsonwebtoken" | jq "{author, maintainers}"
{
  "author": {
    "name": "auth0"
  },
  "maintainers": [
    { "name": "charlesrea" },
    { "name": "madhuri.rm23" },
    { "name": "julien.wollscheid" },
    { "name": "javierquevedo" }
  ]
}
```

jsonwebtoken was created by **auth0** — a well-known identity company (now part of Okta). The current maintainer list contains **none of the original team**. Four new maintainers now control a package with:

- **38 million weekly downloads**
- 82 published versions
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235): JWT verification bypass — appeared in **4 of our 10 audited projects**
- The CVE has an EPSS score of 32.5% (top 7% of all CVEs by exploit probability)

**Verify:**
```bash
curl -s "https://registry.npmjs.org/jsonwebtoken" | jq "{author, maintainers}"
curl -s "https://api.npmjs.org/downloads/point/last-week/jsonwebtoken"
```

We're not suggesting the new maintainers are malicious. We are pointing out that a package depended on by 38 million weekly installs for *authentication token verification* has undergone complete ownership transfer, and none of the downstream projects in our corpus appear to have noticed or re-evaluated their dependency.

---

## Finding 3: next and react-dom Publish via Bot Accounts

```
$ curl -s "https://registry.npmjs.org/next" | jq ".maintainers"
[
  { "name": "vercel-release-bot" },
  { "name": "zeit-bot" }
]
```

```
$ curl -s "https://registry.npmjs.org/react-dom" | jq ".maintainers"
[
  { "name": "fb" },
  { "name": "react-bot" }
]
```

Next.js (**3,730 versions**, 37M weekly downloads) and React DOM (**2,732 versions**) are published exclusively by bot accounts. No human npm account has publish access.

This is a deliberate architectural choice by Vercel and Meta — bot publishing ensures consistency and prevents rogue individual publishes. But it shifts the risk surface: instead of phishing a human, an attacker targets the **CI/CD pipeline**, the **bot's npm token**, or the **GitHub Actions workflow** that triggers the publish.

A compromised `vercel-release-bot` token would be the highest-impact npm supply chain attack in history. Next.js is the framework under cal.com, Payload CMS, and hundreds of thousands of production applications.

---

## Finding 4: 23 CVEs Are Shared Across Multiple Projects

When the same CVE appears in multiple unrelated projects, it means they share a vulnerable upstream dependency. The dependency graph creates *blast radius*.

| CVE | CVSS | EPSS | Projects | Package |
|-----|------|------|----------|---------|
| [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) | — | 32.5% | **4** | jsonwebtoken |
| [CVE-2019-10742](https://nvd.nist.gov/vuln/detail/CVE-2019-10742) | — | 13.1% | 3 | axios |
| [CVE-2021-3749](https://nvd.nist.gov/vuln/detail/CVE-2021-3749) | 7.5 | 8.3% | 3 | axios |
| [CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337) | 7.2 | 4.3% | 3 | lodash |
| [CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203) | — | 3.6% | 3 | lodash |
| [CVE-2019-10744](https://nvd.nist.gov/vuln/detail/CVE-2019-10744) | — | 3.3% | 3 | lodash |
| [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) | **9.1** | **93.0%** | 2 | next |
| [CVE-2024-34351](https://nvd.nist.gov/vuln/detail/CVE-2024-34351) | 7.5 | **92.8%** | 2 | next |

**Verify EPSS scores:**
```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2015-9235"
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2025-29927"
```

CVE-2025-29927 (Next.js middleware auth bypass) has a **93% EPSS score** — meaning there's a 93% probability it will be exploited in the wild in the next 30 days. It has **12 public proof-of-concept exploits** including an ExploitDB entry ([EDB:52124](https://www.exploit-db.com/exploits/52124)) and a [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/search?q=CVE-2025-29927). It affects both cal.com and Payload CMS.

---

## Finding 5: CWE-400 Is the Ecosystem's Structural Weakness

Across all 10 projects, the most common weakness types are:

| CWE | Description | Projects | Occurrences |
|-----|-------------|----------|-------------|
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Resource Exhaustion | 5 | 10 |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | ReDoS | 7 | 9 |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Input Validation | 7 | 8 |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | XSS | 5 | 7 |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | SSRF | 3 | 6 |

CWE-400 and CWE-1333 together — denial of service via resource exhaustion and regular expression backtracking — hit **7 of 10 projects**. This isn't a coincidence. The JavaScript ecosystem's reliance on regex-heavy string processing (URL parsing, header validation, input sanitization) creates a structural exposure to ReDoS. The same pattern appears in Flask's Python dependencies (Werkzeug).

---

## Finding 6: T1574.007 Is Exposed in 9 of 10 Projects

Using VulnGraph's CAPEC bridge (CWE → CAPEC → ATT&CK), we mapped CVEs to MITRE ATT&CK techniques. The most-exposed technique:

**[T1574.007](https://attack.mitre.org/techniques/T1574/007/) — Path Interception by PATH Environment Variable** — exposed in **9 of 10 projects**.

This means 9 out of 10 projects have at least one CVE whose root cause weakness (CWE) maps, via CAPEC, to a technique that real-world threat actors use for persistence and privilege escalation.

The full ATT&CK exposure across the corpus: **161 technique instances** across **90 unique techniques**, spanning Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, and Collection.

---

## The Risk Density Map

Not all dependency strategies are equal. We calculated CVE density — the number of known vulnerabilities per declared dependency:

| Project | CVEs | Deps | CVE/Dep | Interpretation |
|---------|------|------|---------|----------------|
| pallets/flask | 31 | 20 | **1.55** | Lean stack, concentrated risk |
| fastify/fastify | 45 | 53 | 0.85 | Moderate, well-maintained |
| django/django | 5 | 6 | 0.83 | Minimal deps, mature project |
| elysiajs/elysia | 16 | 25 | 0.64 | Young framework, emerging |
| calcom/cal.com | 146 | 377 | 0.39 | Monorepo dilution |
| strapi/strapi | 32 | 394 | 0.08 | Heavy deps, low density |

Flask has a **1.55 CVE-per-dependency ratio** — the highest in the corpus. Its 20 dependencies include Werkzeug (8 CVEs), Jinja2 (4 CVEs), and MarkupSafe. A smaller dependency count doesn't mean less risk; it means each dependency carries more weight.

---

## Reproducing This Analysis

Every number in this article can be independently verified. The tools:

```bash
# 1. Clone the audit registry
git clone https://github.com/copyleftdev/sigma-audit.git
cd sigma-audit

# 2. Run an audit on any repo
python3 sigma-audit.py <owner/repo> --publish

# 3. Verify npm maintainer claims
curl -s "https://registry.npmjs.org/axios" | jq ".maintainers"

# 4. Verify download impact
curl -s "https://api.npmjs.org/downloads/point/last-week/axios"

# 5. Verify EPSS scores
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2025-29927"

# 6. Verify CVE details
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-29927"
```

The full forensic evidence bundle (17 records with SHA-256 prefixes and verification commands) is in the repository at [`reports/forensic-evidence.json`](https://github.com/copyleftdev/sigma-audit/blob/main/reports/forensic-evidence.json).

The live dashboard with all 10 audit reports: **[copyleftdev.github.io/sigma-audit](https://copyleftdev.github.io/sigma-audit/)**

---

## What We're Not Saying

We found no evidence of intentional malice. No single actor appeared across multiple vulnerable packages. The npm maintainer sets for the 14 most-vulnerable packages are completely isolated — 44 unique accounts with zero overlap.

What we *are* saying: **the infrastructure for a supply chain attack is already in place**, and it's structural, not personal:

1. Four packages with 100M+ combined weekly downloads are controlled by a single npm credential each
2. One of the most widely-depended authentication packages has undergone complete ownership transfer
3. Two of the highest-traffic packages in the ecosystem publish through bot accounts with no human approval gate
4. 23 CVEs create shared blast radius across projects that believe their dependency trees are independent

These aren't bugs to fix. They're architectural properties of the npm ecosystem that every engineering team should be aware of when choosing dependencies.

---

*Tools used: [VulnGraph MCP](https://vulngraph.tools) (CVE/EPSS/ATT&CK intelligence, 501K nodes, 640K edges, sub-millisecond queries), [Vajra](https://github.com/copyleftdev/vajra) (structural analysis), [Semgrep](https://semgrep.dev) (SAST), [Zentinel](https://github.com/copyleftdev/zentinel) (pattern scanning). Full audit source: [sigma-audit](https://github.com/copyleftdev/sigma-audit).*
