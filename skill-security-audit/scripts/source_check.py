#!/usr/bin/env python3
"""Source / reputation check for a skill's origin.
Usage: python3 -I source_check.py <github-url | owner/repo | domain> [sources.json]
Uses only the public GitHub REST API (no auth, read-only). Sends nothing about the user.
Set GITHUB_TOKEN to raise the rate limit (optional).
"""
import json, os, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LISTS = os.path.join(HERE, "..", "sources.json")
CONCERN = ["malware", "malicious", "backdoor", "steal", "exfil", "token", "credential", "security", "virus", "phishing", "scam", "spam", "ads", "tracking", "telemetry", "suspicious", "compromised", "hijack"]


def gh(path):
    req = urllib.request.Request("https://api.github.com" + path, headers={"Accept": "application/vnd.github+json", "User-Agent": "skill-security-audit"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok: req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}"}
    except Exception:
        # Fallback: system curl (uses macOS trust store when Python lacks CA certs)
        import subprocess
        cmd = ["curl", "-sS", "--max-time", "15", "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: skill-security-audit"]
        if tok: cmd += ["-H", f"Authorization: Bearer {tok}"]
        try:
            res = subprocess.run(cmd + ["https://api.github.com" + path], capture_output=True, text=True, timeout=20)
            data = json.loads(res.stdout)
            if isinstance(data, dict) and data.get("message") and "id" not in data and "items" not in data:
                return {"_error": data["message"][:120]}
            return data
        except Exception as e2:
            return {"_error": str(e2)}


def age_days(iso):
    if not iso: return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days


def match(lst, owner, repo, domain):
    for e in lst:
        v = e.get("value", "").lower()
        if v and v in {owner, f"{owner}/{repo}", domain}:
            return e
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(64)
    src = sys.argv[1].strip()
    lists = json.load(open(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_LISTS))
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s#?]+)", src) or re.fullmatch(r"([\w.-]+)/([\w.-]+)", src)
    owner, repo = (m.group(1).lower(), m.group(2).lower().removesuffix(".git")) if m else ("", "")
    domain = (re.search(r"https?://([^/]+)", src).group(1).lower() if "://" in src else ("github.com" if m else src.lower()))
    out = {"source": src, "owner": owner, "repo": repo, "domain": domain, "flags": []}

    bl = match(lists.get("blocklist", []), owner, repo, domain)
    al = match(lists.get("allowlist", []), owner, repo, domain)
    out["list_status"] = "BLOCKED" if bl else "ALLOWLISTED" if al else "UNKNOWN"
    if bl: out["flags"].append(f"CRITICAL: on blocklist — {bl.get('reason','')}")

    if not owner:
        out["flags"].append("HIGH: not a GitHub repo — no public reputation signals; treat as untrusted")
        print(json.dumps(out, indent=2)); return

    r = gh(f"/repos/{owner}/{repo}")
    if "_error" in r:
        out["flags"].append(f"HIGH: repo lookup failed ({r['_error']}) — private, deleted, or rate-limited")
        print(json.dumps(out, indent=2)); return
    u = gh(f"/users/{owner}")
    contrib = gh(f"/repos/{owner}/{repo}/contributors?per_page=100")
    rel = gh(f"/repos/{owner}/{repo}/releases?per_page=5")
    commits = gh(f"/repos/{owner}/{repo}/commits?per_page=5")
    q = "+".join(["repo:" + f"{owner}/{repo}", "(" + "+OR+".join(CONCERN[:6]) + ")"])
    issues = gh(f"/search/issues?q={q}&per_page=20")

    out["repo_info"] = {
        "stars": r.get("stargazers_count"), "forks": r.get("forks_count"), "watchers": r.get("subscribers_count"),
        "open_issues": r.get("open_issues_count"), "license": (r.get("license") or {}).get("spdx_id"),
        "created_days_ago": age_days(r.get("created_at")), "last_push_days_ago": age_days(r.get("pushed_at")),
        "archived": r.get("archived"), "is_fork": r.get("fork"), "parent": (r.get("parent") or {}).get("full_name"),
        "default_branch": r.get("default_branch"),
    }
    out["owner_info"] = {
        "type": u.get("type"), "account_age_days": age_days(u.get("created_at")), "public_repos": u.get("public_repos"),
        "followers": u.get("followers"), "verified_org": u.get("is_verified"), "blog": u.get("blog"), "company": u.get("company"),
    }
    out["contributors"] = len(contrib) if isinstance(contrib, list) else None
    out["latest_releases"] = [x.get("tag_name") for x in rel] if isinstance(rel, list) else []
    out["recent_commits"] = [{"sha": c["sha"][:10], "author": (c.get("author") or {}).get("login"), "verified_sig": c["commit"].get("verification", {}).get("verified"), "msg": c["commit"]["message"].splitlines()[0][:80]} for c in commits] if isinstance(commits, list) else []
    out["concern_issues"] = [{"title": i["title"], "state": i["state"], "url": i["html_url"]} for i in issues.get("items", [])] if isinstance(issues, dict) else []

    ri, oi = out["repo_info"], out["owner_info"]
    f = out["flags"]
    if (ri["stars"] or 0) < 10: f.append("HIGH: <10 stars — little community vetting")
    elif (ri["stars"] or 0) < 100: f.append("MEDIUM: <100 stars")
    if (ri["created_days_ago"] or 0) < 30: f.append("HIGH: repo younger than 30 days")
    if (oi["account_age_days"] or 0) < 90: f.append("HIGH: owner account younger than 90 days")
    if (oi["followers"] or 0) < 5 and oi["type"] == "User": f.append("MEDIUM: owner has <5 followers")
    if ri["archived"]: f.append("MEDIUM: repo archived — no security fixes")
    if (ri["last_push_days_ago"] or 0) > 365: f.append("MEDIUM: no push in >1 year")
    if ri["is_fork"]: f.append(f"MEDIUM: fork of {ri['parent']} — compare against upstream")
    if not ri["license"]: f.append("LOW: no license")
    if (out["contributors"] or 0) <= 1: f.append("LOW: single contributor (no peer review)")
    if out["concern_issues"]: f.append(f"MEDIUM: {len(out['concern_issues'])} issues mention security-type keywords — read them")
    if (ri["stars"] or 0) > 200 and (ri["created_days_ago"] or 999) < 60 and (out["contributors"] or 0) <= 1:
        f.append("HIGH: many stars on a new single-author repo — possible star farming")
    if al: f.append(f"INFO: allowlisted — {al.get('reason','')}")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
