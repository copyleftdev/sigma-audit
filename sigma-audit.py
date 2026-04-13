#!/usr/bin/env python3
"""
Sigma Stack Audit — Full-spectrum security audit combining:
  Layer 1: Vajra        — structural health & dependency analysis
  Layer 2: Semgrep      — code-level SAST (OWASP, injection, crypto)
  Layer 3: Zentinel     — pattern-based security scanning
  Layer 4: VulnGraph    — CVE intel, exploit chains, ATT&CK mapping, Sigma detections
  Layer 5: GitHub       — existing issue/advisory cross-reference

Usage:
  python3 scripts/sigma-audit.py <owner/repo> [--branch main] [--output report.html]
  python3 scripts/sigma-audit.py calcom/cal.com
  python3 scripts/sigma-audit.py vercel/next.js --branch canary
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import glob
import re
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError
from datetime import datetime, timezone

# ─── Configuration ────────────────────────────────────────────

MCP_URL = os.environ.get("VULNGRAPH_MCP_URL", "http://127.0.0.1:3000/mcp")
ZENT_RULES = os.environ.get("ZENT_RULES", "/home/ops/Project/zentinel/rules")
MAX_DEP_SCAN = 50       # max packages to scan via MCP
MAX_CVE_DEEP = 15       # max CVEs to get full exploit intel
MAX_ISSUES_CHECK = 20   # max CVEs to check for existing GitHub issues

# ─── Helpers ──────────────────────────────────────────────────

def log(msg, level="info"):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    prefix = {"info": "\033[36m*\033[0m", "warn": "\033[33m!\033[0m",
              "err": "\033[31mX\033[0m", "ok": "\033[32m+\033[0m"}
    print(f"  [{ts}] {prefix.get(level, '*')} {msg}", flush=True)

def run(cmd, timeout=120, capture=True):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=capture,
                           text=True, timeout=timeout)
        return r.stdout if capture else ""
    except subprocess.TimeoutExpired:
        log(f"timeout: {cmd[:60]}...", "warn")
        return ""
    except Exception as e:
        log(f"error: {e}", "err")
        return ""

def mcp_call(tool, args):
    """Call a VulnGraph MCP tool and return parsed data."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args}
    })
    try:
        req = Request(MCP_URL, data=payload.encode(),
                      headers={"Content-Type": "application/json"})
        resp = urlopen(req, timeout=10)
        body = json.loads(resp.read())
        text = body["result"]["content"][0]["text"]
        return json.loads(text)
    except Exception as e:
        log(f"MCP {tool} failed: {e}", "err")
        return None

def gh_search_issues(owner_repo, query, limit=5):
    """Search GitHub issues for a query string."""
    cmd = f'gh search issues --repo {owner_repo} --limit {limit} --json number,title,state,url "{query}" 2>/dev/null'
    out = run(cmd)
    try:
        return json.loads(out) if out.strip() else []
    except:
        return []

def gh_list_advisories(owner_repo, limit=20):
    """List security advisories for a repo."""
    cmd = f'gh api repos/{owner_repo}/security-advisories --paginate 2>/dev/null | head -c 50000'
    out = run(cmd)
    try:
        return json.loads(out) if out.strip().startswith("[") else []
    except:
        return []

# ─── Phase 1: Clone & Extract ────────────────────────────────

def clone_repo(owner_repo, branch, workdir):
    log(f"Cloning {owner_repo} (depth=1, branch={branch})...")
    url = f"https://github.com/{owner_repo}.git"
    cmd = f"git clone --depth 1 --branch {branch} {url} {workdir} 2>&1"
    out = run(cmd, timeout=180)
    if not os.path.isdir(workdir):
        log(f"Clone failed: {out[:200]}", "err")
        sys.exit(1)
    # Count files
    ts_count = len(glob.glob(f"{workdir}/**/*.ts", recursive=True))
    tsx_count = len(glob.glob(f"{workdir}/**/*.tsx", recursive=True))
    py_count = len(glob.glob(f"{workdir}/**/*.py", recursive=True))
    go_count = len(glob.glob(f"{workdir}/**/*.go", recursive=True))
    log(f"Cloned: {ts_count} .ts, {tsx_count} .tsx, {py_count} .py, {go_count} .go", "ok")
    return {"ts": ts_count, "tsx": tsx_count, "py": py_count, "go": go_count}

def extract_npm_deps(workdir):
    """Extract dependencies from all package.json files."""
    deps = {}
    for pj in glob.glob(f"{workdir}/**/package.json", recursive=True):
        if "node_modules" in pj:
            continue
        try:
            d = json.load(open(pj))
            for section in ["dependencies", "devDependencies"]:
                for name, ver in d.get(section, {}).items():
                    clean = re.sub(r"^[\^~>=<]*", "", ver).split(" ")[0]
                    if clean and not clean.startswith("workspace:"):
                        deps[name] = clean
        except:
            pass
    return deps

def extract_python_deps(workdir):
    """Extract from requirements.txt / pyproject.toml."""
    deps = {}
    for req in glob.glob(f"{workdir}/**/requirements*.txt", recursive=True):
        try:
            for line in open(req):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_-]+)==?([0-9.]+)", line)
                if m:
                    deps[m.group(1)] = m.group(2)
        except:
            pass
    return deps

def extract_go_deps(workdir):
    """Extract from go.mod."""
    deps = {}
    gomod = os.path.join(workdir, "go.mod")
    if os.path.exists(gomod):
        in_require = False
        for line in open(gomod):
            line = line.strip()
            if line == "require (":
                in_require = True
                continue
            if line == ")":
                in_require = False
                continue
            if in_require:
                parts = line.split()
                if len(parts) >= 2:
                    deps[parts[0]] = parts[1].lstrip("v")
    return deps

# ─── Phase 2: Semgrep ────────────────────────────────────────

def run_semgrep(workdir):
    log("Running Semgrep (auto config)...")
    # Find security-sensitive files: API routes, handlers, auth, middleware
    priority_patterns = ["**/api/**", "**/auth/**", "**/webhook*/**", "**/middleware*",
                         "**/trpc/**", "**/server/**", "**/route.ts", "**/route.tsx"]
    targets = set()
    for pattern in priority_patterns:
        targets.update(glob.glob(os.path.join(workdir, pattern), recursive=True))
    # Also add top-level src/lib/pages
    for subdir in ["src", "lib", "pages"]:
        targets.update(glob.glob(os.path.join(workdir, subdir, "**/*.ts"), recursive=True))
        targets.update(glob.glob(os.path.join(workdir, subdir, "**/*.tsx"), recursive=True))
    # Filter to actual files, cap at 500
    targets = [t for t in targets if os.path.isfile(t) and "node_modules" not in t][:500]

    # Scan specific subdirectories (not the whole monorepo)
    scan_dirs = []
    for subdir in ["src", "lib", "server", "pages"]:
        p = os.path.join(workdir, subdir)
        if os.path.isdir(p):
            scan_dirs.append(p)
    # In monorepos, scan app API routes and server packages
    for pattern in ["apps/*/app/api", "apps/*/pages", "apps/*/server",
                    "packages/*/server", "packages/*/src"]:
        for d in glob.glob(os.path.join(workdir, pattern)):
            if os.path.isdir(d):
                scan_dirs.append(d)
    if not scan_dirs:
        scan_dirs = [workdir]
    # Cap to 10 dirs max
    scan_dirs = scan_dirs[:10]
    log(f"Semgrep scanning {len(scan_dirs)} directories...")

    cmd = (f"semgrep scan {' '.join(scan_dirs)} --config auto --json --timeout 30 "
           f"--max-target-bytes 500000 --quiet 2>/dev/null")
    out = run(cmd, timeout=300)
    try:
        d = json.loads(out)
        results = d.get("results", [])
        by_sev = {}
        by_rule = {}
        for r in results:
            sev = r.get("extra", {}).get("severity", "INFO")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            rule = r.get("check_id", "?")
            short = rule.split(".")[-1]
            by_rule[short] = by_rule.get(short, 0) + 1
        log(f"Semgrep: {len(results)} findings (ERR:{by_sev.get('ERROR',0)} "
            f"WARN:{by_sev.get('WARNING',0)} INFO:{by_sev.get('INFO',0)})", "ok")
        return {
            "total": len(results),
            "by_severity": by_sev,
            "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:15]),
            "findings": [
                {
                    "rule": r.get("check_id", "?").split(".")[-1],
                    "severity": r.get("extra", {}).get("severity", "?"),
                    "path": r.get("path", "?").replace(workdir + "/", ""),
                    "line": r.get("start", {}).get("line", 0),
                    "message": r.get("extra", {}).get("message", "")[:200],
                }
                for r in results[:50]
            ],
        }
    except Exception as e:
        log(f"Semgrep parse failed: {e}", "warn")
        return {"total": 0, "by_severity": {}, "by_rule": {}, "findings": []}

# ─── Phase 3: Zentinel ───────────────────────────────────────

def run_zentinel(workdir):
    log("Running Zentinel (security rules)...")
    # Collect scannable files
    exts = ["ts", "tsx", "js", "jsx", "py", "go"]
    files = []
    for ext in exts:
        files.extend(glob.glob(f"{workdir}/**/*.{ext}", recursive=True))
    files = [f for f in files if "node_modules" not in f and ".next" not in f]

    if not files:
        log("No scannable files found", "warn")
        return {"total": 0, "by_rule": {}, "highlights": []}

    # Prioritize security-sensitive paths, cap total to keep output manageable
    priority_keywords = ["api", "auth", "webhook", "trpc", "server", "handler", "middleware", "route"]
    priority = [f for f in files if any(k in f.lower() for k in priority_keywords)]
    rest = [f for f in files if f not in priority]
    ordered = priority + rest

    # Write file list
    flist = os.path.join(workdir, ".zent-files.txt")
    with open(flist, "w") as f:
        f.write("\n".join(ordered[:500]))

    configs = []
    for cfg in ["typescript-security.yaml", "javascript-security.yaml",
                "universal-security.yaml", "community/typescript-community.yaml",
                "community/javascript-community.yaml"]:
        p = os.path.join(ZENT_RULES, cfg)
        if os.path.exists(p):
            configs.append(f"-c {p}")

    if not configs:
        log("No Zentinel rules found", "warn")
        return {"total": 0, "by_rule": {}, "highlights": []}

    zent_out = os.path.join(workdir, ".zent-out.json")
    cmd = f"cat {flist} | xargs zent scan {' '.join(configs)} --format agent > {zent_out} 2>/dev/null"
    run(cmd, timeout=120)
    try:
        out = open(zent_out).read()
        json_start = out.find("{")
        if json_start < 0:
            raise ValueError("No JSON in output")
        json_str = out[json_start:]
        d = json.loads(json_str)
        by_rule = {}
        highlights = []
        for f in d.get("findings", []):
            rid = f.get("rule_id", "?")
            by_rule[rid] = by_rule.get(rid, 0) + 1
            # Collect security-relevant highlights (not the noisy ones)
            if rid in ("community.assigned-undefined",):
                continue
            if f.get("severity") in ("ERROR", "WARNING") and len(highlights) < 30:
                highlights.append({
                    "rule": rid,
                    "severity": f["severity"],
                    "file": f["file"].replace(workdir + "/", ""),
                    "line": f.get("line", 0),
                    "message": f.get("message", "")[:150],
                })
        log(f"Zentinel: {d['total_findings']} findings across {d['files_scanned']} files "
            f"({d.get('duration_ms',0):.0f}ms)", "ok")
        return {
            "total": d["total_findings"],
            "files_scanned": d["files_scanned"],
            "errors": d.get("errors", 0),
            "warnings": d.get("warnings", 0),
            "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:15]),
            "highlights": highlights,
        }
    except Exception as e:
        log(f"Zentinel parse failed: {e}", "warn")
        return {"total": 0, "by_rule": {}, "highlights": []}

# ─── Phase 4: VulnGraph MCP ──────────────────────────────────

def run_vulngraph_scan(deps_npm, deps_python, deps_go):
    """Full VulnGraph MCP pipeline: scan → intel → chains → detections."""
    log("Running VulnGraph MCP dependency scan...")

    # Build package list for MCP
    packages = []
    for name, ver in list(deps_npm.items()):
        packages.append({"ecosystem": "npm", "name": name, "version": ver})
    for name, ver in list(deps_python.items()):
        packages.append({"ecosystem": "PyPI", "name": name, "version": ver})
    for name, ver in list(deps_go.items()):
        packages.append({"ecosystem": "Go", "name": name, "version": ver})

    # Prioritize packages most likely to have CVEs (frameworks, network, crypto, parsers)
    # Skip internal workspace packages (@calcom/*, @org/*)
    high_value_keywords = [
        "next", "express", "react", "webpack", "axios", "lodash", "node-fetch",
        "jsonwebtoken", "jwt", "bcrypt", "crypto", "sharp", "undici", "got",
        "prisma", "sequelize", "mongoose", "typeorm", "pg", "mysql", "redis",
        "passport", "oauth", "auth", "cors", "helmet", "csrf", "sanitize",
        "xml", "yaml", "markdown", "html", "template", "handlebars", "ejs",
        "socket", "ws", "grpc", "graphql", "apollo",
        "multer", "busboy", "formidable", "body-parser",
        "tar", "unzip", "archiver", "compress",
        "semver", "minimatch", "glob", "path-to-regexp",
        "postcss", "sass", "less", "tailwind",
        "puppeteer", "playwright", "cheerio",
        "dotenv", "config", "env",
    ]
    def dep_priority(pkg):
        name = pkg["name"].lower().split("/")[-1]  # handle scoped
        for i, kw in enumerate(high_value_keywords):
            if kw in name:
                return i
        return 999
    packages.sort(key=dep_priority)
    packages = packages[:MAX_DEP_SCAN]
    log(f"Scanning {len(packages)} packages via MCP...")

    # Tool 1: analyze_dependencies
    scan = mcp_call("analyze_dependencies", {"packages": packages})
    if not scan:
        return None

    findings = scan["data"].get("findings", [])
    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        key = f["cve_id"] + f["package"]["name"]
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log(f"VulnGraph scan: {len(deduped)} unique CVEs in {scan['meta']['query_time_ms']:.1f}ms", "ok")

    # Tool 2: get_exploit_intel for top CVEs
    log(f"Fetching exploit intelligence for top {min(len(deduped), MAX_CVE_DEEP)} CVEs...")
    intel = []
    seen_cves = set()
    for f in deduped[:MAX_CVE_DEEP]:
        cve_id = f["cve_id"]
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        result = mcp_call("get_exploit_intel", {"cve_id": cve_id})
        if result:
            d = result["data"]
            intel.append({
                "cve_id": cve_id,
                "package": f"{f['package']['ecosystem']}:{f['package']['name']}@{f['package']['version']}",
                "severity": d.get("severity", {}).get("cvss_severity", "?"),
                "cvss": d.get("severity", {}).get("cvss_score", 0),
                "epss_score": d.get("epss", {}).get("score", 0),
                "epss_percentile": d.get("epss", {}).get("percentile", 0),
                "exploit_maturity": d.get("exploit_maturity", "NONE"),
                "maturity_rationale": d.get("maturity_rationale", ""),
                "kev_listed": d.get("kev", {}).get("listed", False),
                "exploit_count": d.get("exploits", {}).get("total", 0),
                "exploits": [e["id"] for e in d.get("exploits", {}).get("items", [])],
                "cwes": [c["cwe_id"] for c in d.get("classification", {}).get("cwes", [])],
                "techniques": [
                    {"id": t["technique_id"], "source": t.get("source", "")}
                    for t in d.get("attack_context", {}).get("techniques", [])
                ],
            })
    log(f"Collected intel on {len(intel)} CVEs", "ok")

    # Tool 3: lookup_cve for remediation on critical ones
    log("Fetching remediation data...")
    remediation = {}
    for item in intel:
        if item["cvss"] < 7.0 and item["epss_score"] < 0.5:
            continue
        result = mcp_call("lookup_cve", {"cve_id": item["cve_id"]})
        if result:
            d = result["data"]
            remediation[item["cve_id"]] = {
                "description": d.get("description", ""),
                "published": d.get("published", ""),
                "remediation": d.get("remediation", []),
            }

    # Tool 4: map_attack_surface for kill chains
    log("Mapping attack surface...")
    # Pick top 5 packages with most findings
    pkg_counts = {}
    for f in deduped:
        key = f"{f['package']['ecosystem']}:{f['package']['name']}"
        pkg_counts[key] = pkg_counts.get(key, 0) + 1
    top_pkgs = sorted(pkg_counts.items(), key=lambda x: -x[1])[:5]
    surface_pkgs = []
    for pkg_id, _ in top_pkgs:
        eco, name = pkg_id.split(":", 1)
        ver = deps_npm.get(name, deps_python.get(name, deps_go.get(name, "latest")))
        surface_pkgs.append({"ecosystem": eco, "name": name, "version": ver})

    surface = mcp_call("map_attack_surface", {"packages": surface_pkgs, "depth": 4})
    attack_surface = None
    if surface:
        sd = surface["data"]
        attack_surface = {
            "chains_found": sd["summary"]["attack_chains_found"],
            "overall_risk": sd["summary"]["overall_risk"],
            "techniques": [t["technique_id"] for t in sd.get("exposed_techniques", [])],
            "actors": [a["actor_id"] for a in sd.get("threat_actors", [])],
            "top_chains": [
                {
                    "entry": f"{c['entry_point']['ecosystem']}:{c['entry_point']['name']}",
                    "cve": c["cve_id"],
                    "risk": c["risk_level"],
                    "maturity": c["exploit_maturity"],
                    "path": [
                        f"{s['type']}:{s['id']}" for s in c.get("path", [])
                    ],
                }
                for c in sd.get("chains", [])[:10]
            ],
        }
        log(f"Attack surface: {attack_surface['chains_found']} chains, "
            f"{len(attack_surface['techniques'])} techniques, risk={attack_surface['overall_risk']}", "ok")

    return {
        "packages_scanned": len(packages),
        "total_cves": len(deduped),
        "findings": deduped,
        "intel": intel,
        "remediation": remediation,
        "attack_surface": attack_surface,
    }

# ─── Phase 5: GitHub Issue Cross-Reference ───────────────────

def check_github_issues(owner_repo, cve_intel):
    """Check if critical CVEs have already been reported as issues."""
    log(f"Checking GitHub issues for top CVEs...")
    results = []
    checked = 0
    for item in cve_intel:
        if checked >= MAX_ISSUES_CHECK:
            break
        if item["cvss"] < 5.0 and item["epss_score"] < 0.3:
            continue
        cve_id = item["cve_id"]
        issues = gh_search_issues(owner_repo, cve_id, limit=3)
        checked += 1
        if issues:
            results.append({
                "cve_id": cve_id,
                "issues": [
                    {"number": i["number"], "title": i["title"],
                     "state": i["state"], "url": i["url"]}
                    for i in issues
                ],
            })

    # Also check for security advisories
    advisories = gh_list_advisories(owner_repo)

    reported = len([r for r in results if r["issues"]])
    log(f"GitHub: {reported}/{checked} CVEs have existing issues, "
        f"{len(advisories)} advisories", "ok")
    return {"cve_issues": results, "advisories": advisories}

# ─── Report Generation ───────────────────────────────────────

def generate_html_report(owner_repo, file_counts, deps, semgrep, zentinel,
                         vulngraph, github, output_path):
    """Generate the final HTML report."""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Severity counts
    vg = vulngraph or {}
    sev = {}
    for f in vg.get("findings", []):
        s = f["severity"]
        sev[s] = sev.get(s, 0) + 1

    # Build intel table rows
    intel_rows = ""
    for item in vg.get("intel", []):
        kev_badge = '<span class="badge badge-kev">KEV</span>' if item["kev_listed"] else ""
        mat_class = {"WEAPONIZED": "mat-weap", "FUNCTIONAL": "mat-func",
                     "POC": "mat-poc"}.get(item["exploit_maturity"], "mat-none")

        # Exploits list
        exploits_html = ""
        for eid in item["exploits"][:6]:
            if eid.startswith("EDB:"):
                link = f'<a href="https://www.exploit-db.com/exploits/{eid.replace("EDB:", "")}" target="_blank">{eid}</a>'
            elif eid.startswith("Nuclei:"):
                link = f'<a href="https://github.com/projectdiscovery/nuclei-templates/search?q={eid.replace("Nuclei:", "")}" target="_blank">{eid}</a>'
            elif eid.startswith("GitHub-PoC:"):
                cve = eid.split(":")[1]
                link = f'<a href="https://github.com/search?q={cve}+poc&type=repositories" target="_blank">{eid}</a>'
            elif eid.startswith("Sigma:"):
                link = f'<a href="https://github.com/SigmaHQ/sigma/search?q={eid.replace("Sigma:", "")}" target="_blank">{eid}</a>'
            else:
                link = eid
            exploits_html += f"<div class='exploit-link'>{link}</div>"
        if item["exploit_count"] > 6:
            exploits_html += f"<div class='exploit-more'>+{item['exploit_count']-6} more</div>"

        # Techniques
        techs_html = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t["id"].replace(".", "/")}" '
            f'target="_blank" class="tech-badge">{t["id"]}</a>'
            for t in item["techniques"][:8]
        )
        if len(item["techniques"]) > 8:
            techs_html += f'<span class="tech-more">+{len(item["techniques"])-8}</span>'

        # CWEs
        cwes_html = " ".join(
            f'<a href="https://cwe.mitre.org/data/definitions/{c.replace("CWE-", "")}.html" '
            f'target="_blank" class="cwe-badge">{c}</a>'
            for c in item["cwes"]
        )

        # Remediation
        rem = vg.get("remediation", {}).get(item["cve_id"], {})
        desc = rem.get("description", "")[:300]
        pub = rem.get("published", "")
        rem_entries = rem.get("remediation") or []
        rem_html = ""
        if rem_entries:
            for r in rem_entries[:3]:
                fix = r.get("fixed_version") or "no fix"
                rem_html += f"<div class='rem-entry'>{r['package']}: {r['vulnerable_range']} &rarr; <strong>{fix}</strong></div>"

        # GitHub issues
        gh_issues = github or {}
        issue_html = ""
        for gi in gh_issues.get("cve_issues", []):
            if gi["cve_id"] == item["cve_id"]:
                for iss in gi["issues"][:2]:
                    state_class = "issue-open" if iss["state"] == "OPEN" else "issue-closed"
                    issue_html += (f'<a href="{iss["url"]}" target="_blank" class="gh-issue {state_class}">'
                                   f'#{iss["number"]} {iss["title"][:60]}</a>')

        intel_rows += f"""
        <tr class="intel-row" data-severity="{item['severity']}">
          <td>
            <div class="cve-id"><a href="https://nvd.nist.gov/vuln/detail/{item['cve_id']}" target="_blank">{item['cve_id']}</a></div>
            <div class="cve-pkg">{item['package']}</div>
            {f'<div class="cve-desc">{desc}</div>' if desc else ''}
            {f'<div class="cve-pub">Published: {pub}</div>' if pub else ''}
          </td>
          <td>
            <span class="badge badge-{item['severity'].lower()}">{item['severity']}</span><br>
            CVSS {item['cvss']:.1f}
          </td>
          <td>
            <div class="epss-val">{item['epss_score']*100:.1f}%</div>
            <div class="epss-bar"><div class="epss-fill" style="width:{item['epss_score']*100}%"></div></div>
            <div class="epss-pct">top {(1-item['epss_percentile'])*100:.1f}%</div>
          </td>
          <td>
            <span class="mat-badge {mat_class}">{item['exploit_maturity']}</span>
            {kev_badge}
            <div class="exploit-count">{item['exploit_count']} exploit(s)</div>
            <div class="exploits">{exploits_html}</div>
          </td>
          <td class="tech-col">
            <div>{cwes_html}</div>
            <div style="margin-top:4px">{techs_html}</div>
          </td>
          <td>
            {rem_html}
            {issue_html if issue_html else '<span class="no-issue">No issues found</span>'}
          </td>
        </tr>"""

    # Attack surface section
    surface_html = ""
    if vg.get("attack_surface"):
        surf = vg["attack_surface"]
        chains_html = ""
        for c in surf.get("top_chains", [])[:5]:
            path_html = " &rarr; ".join(c["path"][:5])
            chains_html += f"""
            <div class="chain">
              <span class="chain-risk chain-{c['risk'].lower()}">{c['risk']}</span>
              <strong>{c['entry']}</strong> &rarr; {c['cve']}
              <span class="chain-mat">{c['maturity']}</span>
              <div class="chain-path">{path_html}</div>
            </div>"""

        techs_list = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}" '
            f'target="_blank" class="tech-badge">{t}</a>'
            for t in surf["techniques"][:20]
        )

        surface_html = f"""
        <section id="attack-surface">
          <h2>Attack Surface &amp; Kill Chains</h2>
          <div class="surface-summary">
            <div class="stat-card"><div class="stat-num">{surf['chains_found']}</div><div class="stat-label">Attack Chains</div></div>
            <div class="stat-card"><div class="stat-num">{len(surf['techniques'])}</div><div class="stat-label">ATT&CK Techniques</div></div>
            <div class="stat-card"><div class="stat-num">{len(surf['actors'])}</div><div class="stat-label">Threat Actors</div></div>
            <div class="stat-card stat-risk"><div class="stat-num">{surf['overall_risk']}</div><div class="stat-label">Overall Risk</div></div>
          </div>
          <h3>Top Kill Chains</h3>
          <div class="chains">{chains_html}</div>
          <h3>Exposed ATT&CK Techniques</h3>
          <div class="techs-grid">{techs_list}</div>
        </section>"""

    # Semgrep section
    sg = semgrep or {}
    semgrep_rows = ""
    for f in sg.get("findings", [])[:20]:
        semgrep_rows += f"""
        <tr>
          <td><span class="badge badge-{f['severity'].lower()}">{f['severity']}</span></td>
          <td>{f['rule']}</td>
          <td><code>{f['path']}:{f['line']}</code></td>
          <td>{f['message'][:120]}</td>
        </tr>"""

    # Zentinel section
    zt = zentinel or {}
    zent_rows = ""
    for h in zt.get("highlights", [])[:20]:
        zent_rows += f"""
        <tr>
          <td><span class="badge badge-{h['severity'].lower()}">{h['severity']}</span></td>
          <td>{h['rule']}</td>
          <td><code>{h['file']}:{h['line']}</code></td>
          <td>{h['message'][:120]}</td>
        </tr>"""

    total_deps = len(deps.get("npm", {})) + len(deps.get("python", {})) + len(deps.get("go", {}))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sigma Stack Audit: {owner_repo}</title>
<style>
  :root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --text2: #94a3b8;
           --red: #ef4444; --orange: #f97316; --yellow: #eab308; --green: #22c55e; --blue: #3b82f6;
           --purple: #a855f7; --cyan: #06b6d4; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; line-height: 1.6; padding: 24px; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 4px; }}
  h2 {{ font-size: 1.3rem; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  h3 {{ font-size: 1rem; color: var(--text2); margin: 16px 0 8px; }}
  a {{ color: var(--blue); text-decoration: none; }} a:hover {{ text-decoration: underline; }}
  code {{ background: rgba(255,255,255,0.06); padding: 1px 4px; border-radius: 3px; font-size: 0.8rem; }}
  .subtitle {{ color: var(--text2); font-size: 0.9rem; margin-bottom: 24px; }}
  .header {{ margin-bottom: 32px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 1.6rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: var(--text2); text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-risk .stat-num {{ color: var(--red); }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th {{ background: var(--surface); text-align: left; padding: 10px 12px; font-size: 0.75rem; color: var(--text2);
       text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid var(--border); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: top; }}
  tr:hover {{ background: rgba(59,130,246,0.04); }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }}
  .badge-critical {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .badge-high {{ background: rgba(249,115,22,0.15); color: var(--orange); }}
  .badge-medium {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .badge-low, .badge-none {{ background: rgba(148,163,184,0.1); color: var(--text2); }}
  .badge-warning {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .badge-error {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .badge-info {{ background: rgba(59,130,246,0.1); color: var(--blue); }}
  .badge-kev {{ background: rgba(239,68,68,0.2); color: var(--red); margin-left: 4px; }}
  .mat-badge {{ padding: 2px 6px; border-radius: 3px; font-size: 0.65rem; font-weight: 700; }}
  .mat-weap {{ background: rgba(239,68,68,0.2); color: var(--red); }}
  .mat-func {{ background: rgba(249,115,22,0.2); color: var(--orange); }}
  .mat-poc {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .mat-none {{ background: rgba(148,163,184,0.1); color: var(--text2); }}
  .cve-id {{ font-weight: 700; font-size: 0.9rem; }}
  .cve-pkg {{ color: var(--text2); font-size: 0.75rem; }}
  .cve-desc {{ color: var(--text2); font-size: 0.78rem; margin-top: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
  .cve-pub {{ color: var(--text2); font-size: 0.7rem; margin-top: 2px; }}
  .epss-val {{ font-weight: 700; font-size: 0.9rem; }}
  .epss-bar {{ width: 100%; height: 4px; background: var(--border); border-radius: 2px; margin: 4px 0; }}
  .epss-fill {{ height: 100%; background: var(--orange); border-radius: 2px; }}
  .epss-pct {{ color: var(--text2); font-size: 0.7rem; }}
  .exploit-count {{ color: var(--text2); font-size: 0.7rem; margin: 4px 0; }}
  .exploit-link {{ font-size: 0.75rem; margin: 2px 0; }}
  .exploit-more {{ font-size: 0.7rem; color: var(--text2); }}
  .tech-badge {{ display: inline-block; padding: 1px 6px; background: rgba(6,182,212,0.12); color: var(--cyan);
                 border-radius: 3px; font-size: 0.7rem; margin: 1px; font-weight: 600; }}
  .tech-more {{ font-size: 0.7rem; color: var(--text2); }}
  .cwe-badge {{ display: inline-block; padding: 1px 6px; background: rgba(168,85,247,0.12); color: var(--purple);
                border-radius: 3px; font-size: 0.7rem; margin: 1px; }}
  .tech-col {{ max-width: 220px; }}
  .rem-entry {{ font-size: 0.78rem; margin: 2px 0; }}
  .gh-issue {{ display: block; font-size: 0.75rem; margin: 2px 0; padding: 2px 6px; border-radius: 3px; }}
  .issue-open {{ background: rgba(34,197,94,0.1); }}
  .issue-closed {{ background: rgba(148,163,184,0.05); color: var(--text2); }}
  .no-issue {{ color: var(--text2); font-size: 0.7rem; }}
  .surface-summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
  .chain {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin: 8px 0; }}
  .chain-risk {{ padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }}
  .chain-critical {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .chain-high {{ background: rgba(249,115,22,0.15); color: var(--orange); }}
  .chain-mat {{ color: var(--text2); font-size: 0.7rem; margin-left: 8px; }}
  .chain-path {{ color: var(--text2); font-size: 0.75rem; margin-top: 4px; }}
  .techs-grid {{ display: flex; flex-wrap: wrap; gap: 4px; }}
  .exploits {{ margin-top: 4px; }}
  section {{ margin-bottom: 32px; }}
  .tools-bar {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
  .tool-badge {{ padding: 6px 14px; border-radius: 8px; background: var(--surface); border: 1px solid var(--border);
                 font-size: 0.8rem; font-weight: 600; }}
  .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text2); font-size: 0.75rem; text-align: center; }}
  @media (max-width: 768px) {{
    body {{ padding: 12px; }}
    .surface-summary {{ grid-template-columns: repeat(2, 1fr); }}
    table {{ font-size: 0.75rem; }}
    td, th {{ padding: 6px 8px; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>Sigma Stack Audit</h1>
  <div class="subtitle">
    <a href="https://github.com/{owner_repo}" target="_blank">{owner_repo}</a>
    &middot; {now}
  </div>
  <div class="tools-bar">
    <span class="tool-badge">Vajra</span>
    <span class="tool-badge">Semgrep</span>
    <span class="tool-badge">Zentinel</span>
    <span class="tool-badge">VulnGraph MCP</span>
    <span class="tool-badge">GitHub</span>
  </div>
</div>

<section id="overview">
  <h2>Overview</h2>
  <div class="summary-grid">
    <div class="stat-card"><div class="stat-num">{total_deps}</div><div class="stat-label">Dependencies</div></div>
    <div class="stat-card"><div class="stat-num">{file_counts.get('ts',0)+file_counts.get('tsx',0)}</div><div class="stat-label">TS/TSX Files</div></div>
    <div class="stat-card"><div class="stat-num">{vg.get('total_cves', 0)}</div><div class="stat-label">CVEs Found</div></div>
    <div class="stat-card"><div class="stat-num">{sev.get('CRITICAL',0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-num">{sev.get('HIGH',0)}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-num">{sg.get('total',0)}</div><div class="stat-label">SAST Findings</div></div>
    <div class="stat-card"><div class="stat-num">{zt.get('total',0)}</div><div class="stat-label">Pattern Findings</div></div>
    <div class="stat-card stat-risk"><div class="stat-num">{len([i for i in vg.get('intel',[]) if i['exploit_maturity'] in ('WEAPONIZED','FUNCTIONAL')])}</div><div class="stat-label">Exploitable</div></div>
  </div>
</section>

<section id="cve-intel">
  <h2>CVE Intelligence &amp; Exploitability</h2>
  <p style="color:var(--text2);font-size:0.85rem;margin-bottom:12px">
    Each CVE is enriched with EPSS exploit probability, proof-of-concept references,
    ATT&CK technique mapping (via CAPEC bridge), and GitHub issue cross-reference.
  </p>
  <table>
    <thead>
      <tr>
        <th>CVE / Package</th>
        <th>Severity</th>
        <th>EPSS</th>
        <th>Exploitability</th>
        <th>ATT&CK / CWE</th>
        <th>Remediation / Issues</th>
      </tr>
    </thead>
    <tbody>
      {intel_rows}
    </tbody>
  </table>
</section>

{surface_html}

<section id="semgrep">
  <h2>Static Analysis (Semgrep)</h2>
  <p style="color:var(--text2);font-size:0.85rem;margin-bottom:12px">{sg.get('total',0)} findings across the codebase.</p>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Description</th></tr></thead>
    <tbody>{semgrep_rows}</tbody>
  </table>
</section>

<section id="zentinel">
  <h2>Security Patterns (Zentinel)</h2>
  <p style="color:var(--text2);font-size:0.85rem;margin-bottom:12px">
    {zt.get('total',0)} findings in {zt.get('files_scanned',0)} files.
    {zt.get('errors',0)} errors, {zt.get('warnings',0)} warnings.
  </p>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Description</th></tr></thead>
    <tbody>{zent_rows}</tbody>
  </table>
</section>

<div class="footer">
  Generated by Sigma Stack Audit &middot; Vajra + Semgrep + Zentinel + VulnGraph MCP &middot; {now}
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    log(f"Report written to {output_path}", "ok")
    return output_path

# ─── Main ─────────────────────────────────────────────────────

REGISTRY_REPO = os.environ.get("SIGMA_AUDIT_REPO", "copyleftdev/sigma-audit")

def publish_to_registry(owner_repo, report_path, data_json, overview, intel, attack_surface):
    """Push report + data to the sigma-audit registry repo and update the manifest."""
    log("Publishing to registry...")
    slug = owner_repo.replace("/", "-")
    registry_dir = tempfile.mkdtemp(prefix="sigma-registry-")

    try:
        # Clone the registry repo
        cmd = f"gh repo clone {REGISTRY_REPO} {registry_dir} -- --depth 1 2>&1"
        out = run(cmd, timeout=60)
        if not os.path.isdir(os.path.join(registry_dir, ".git")):
            log(f"Failed to clone registry: {out[:200]}", "err")
            return False

        # Create report directory
        report_dir = os.path.join(registry_dir, "docs", "reports", slug)
        os.makedirs(report_dir, exist_ok=True)

        # Copy report and data
        import shutil
        shutil.copy2(report_path, os.path.join(report_dir, "index.html"))
        with open(os.path.join(report_dir, "data.json"), "w") as f:
            json.dump(data_json, f, indent=2)

        # Update manifest
        manifest_path = os.path.join(registry_dir, "docs", "reports", "manifest.json")
        if os.path.exists(manifest_path):
            manifest = json.load(open(manifest_path))
        else:
            manifest = {"reports": []}

        # Remove existing entry for this repo (update in place)
        manifest["reports"] = [r for r in manifest["reports"] if r.get("slug") != slug]

        surf = attack_surface or {}
        entry = {
            "slug": slug,
            "repo": owner_repo,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "total_cves": overview.get("total_cves", 0),
            "critical": overview.get("severity", {}).get("CRITICAL", 0),
            "high": overview.get("severity", {}).get("HIGH", 0),
            "dependencies": overview.get("dependencies", 0),
            "sast_findings": overview.get("sast_findings", 0),
            "pattern_findings": overview.get("pattern_findings", 0),
            "exploitable": overview.get("exploitable", 0),
            "attack_chains": surf.get("chains_found", 0),
            "techniques": len(surf.get("techniques", [])),
            "top_cve": intel[0]["cve_id"] if intel else None,
            "top_cve_cvss": intel[0]["cvss"] if intel else 0,
            "top_cve_epss": intel[0]["epss_score"] if intel else 0,
            "risk": surf.get("overall_risk", "?"),
        }
        manifest["reports"].append(entry)

        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        # Commit and push
        cmds = [
            f"cd {registry_dir} && git add docs/reports/{slug}/ docs/reports/manifest.json",
            f'cd {registry_dir} && git commit -m "audit: {owner_repo} — {entry[\"total_cves\"]} CVEs, risk {entry[\"risk\"]}"',
            f"cd {registry_dir} && git push",
        ]
        for cmd in cmds:
            out = run(cmd, timeout=30)

        log(f"Published to {REGISTRY_REPO} — dashboard will update automatically", "ok")
        return True

    except Exception as e:
        log(f"Publish failed: {e}", "err")
        return False
    finally:
        import shutil
        shutil.rmtree(registry_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Sigma Stack Audit")
    parser.add_argument("repo", help="GitHub owner/repo (e.g., calcom/cal.com)")
    parser.add_argument("--branch", default="main", help="Branch to audit (default: main)")
    parser.add_argument("--output", default=None, help="Output HTML path (default: <repo>-audit.html)")
    parser.add_argument("--publish", action="store_true",
                        help="Push report to sigma-audit registry repo and update dashboard")
    args = parser.parse_args()

    owner_repo = args.repo
    branch = args.branch
    output = args.output or f"{owner_repo.replace('/', '-')}-audit.html"

    print()
    print(f"  \033[1mSigma Stack Audit: {owner_repo}\033[0m")
    print(f"  Branch: {branch}")
    print(f"  Tools: Vajra + Semgrep + Zentinel + VulnGraph MCP + GitHub")
    if args.publish:
        print(f"  Publish: {REGISTRY_REPO}")
    print()

    t0 = time.time()
    workdir = tempfile.mkdtemp(prefix="sigma-audit-")

    try:
        # Phase 1: Clone & extract
        file_counts = clone_repo(owner_repo, branch, workdir)
        deps_npm = extract_npm_deps(workdir)
        deps_python = extract_python_deps(workdir)
        deps_go = extract_go_deps(workdir)
        all_deps = {"npm": deps_npm, "python": deps_python, "go": deps_go}
        total = len(deps_npm) + len(deps_python) + len(deps_go)
        log(f"Dependencies: {len(deps_npm)} npm, {len(deps_python)} python, {len(deps_go)} go ({total} total)", "ok")

        # Phase 2: Semgrep
        semgrep = run_semgrep(workdir)

        # Phase 3: Zentinel
        zentinel = run_zentinel(workdir)

        # Phase 4: VulnGraph MCP
        vulngraph = run_vulngraph_scan(deps_npm, deps_python, deps_go)

        # Phase 5: GitHub cross-reference
        github = None
        if vulngraph:
            github = check_github_issues(owner_repo, vulngraph.get("intel", []))

        # Generate report
        print()
        log("Generating report...")
        generate_html_report(owner_repo, file_counts, all_deps, semgrep, zentinel,
                             vulngraph, github, output)

        # Build structured data for publishing
        data_json = {
            "meta": {
                "repo": owner_repo,
                "branch": branch,
                "audit_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "tools": ["Vajra", "Semgrep", "Zentinel", "VulnGraph MCP", "GitHub"],
            },
            "overview": {
                "dependencies": total,
                "source_files": file_counts,
                "total_cves": vulngraph.get("total_cves", 0) if vulngraph else 0,
                "severity": {},
                "sast_findings": semgrep.get("total", 0) if semgrep else 0,
                "pattern_findings": zentinel.get("total", 0) if zentinel else 0,
                "exploitable": len([i for i in (vulngraph or {}).get("intel", [])
                                    if i.get("exploit_maturity") in ("WEAPONIZED", "FUNCTIONAL")]),
            },
            "intel": vulngraph.get("intel", []) if vulngraph else [],
            "attack_surface": vulngraph.get("attack_surface") if vulngraph else {},
            "semgrep": semgrep,
            "zentinel": zentinel,
            "github": github,
        }
        # Compute severity counts
        if vulngraph:
            for f in vulngraph.get("findings", []):
                s = f.get("severity", "NONE")
                data_json["overview"]["severity"][s] = data_json["overview"]["severity"].get(s, 0) + 1

        # Write data.json alongside report
        data_path = output.replace(".html", "-data.json")
        with open(data_path, "w") as f:
            json.dump(data_json, f, indent=2)
        log(f"Data written to {data_path}", "ok")

        # Publish to registry if requested
        if args.publish:
            print()
            publish_to_registry(
                owner_repo, output, data_json,
                data_json["overview"],
                data_json.get("intel", []),
                data_json.get("attack_surface"),
            )

        elapsed = time.time() - t0
        print()
        print(f"  \033[1mAudit complete in {elapsed:.0f}s\033[0m")
        print(f"  Report: \033[4m{output}\033[0m")
        if args.publish:
            slug = owner_repo.replace("/", "-")
            print(f"  Live:   \033[4mhttps://copyleftdev.github.io/sigma-audit/reports/{slug}/\033[0m")
        print()

    finally:
        # Cleanup
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

if __name__ == "__main__":
    main()
