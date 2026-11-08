#!/usr/bin/env python3
"""Static security scanner for Claude skills / plugins / MCP bundles.
Usage: python3 -I scan.py <path-to-skill-dir-or-file> [--json] [--full] [--color] [--mark-clean]
--color: ANSI gradient cost bar for a terminal (default is emoji, which also renders in chat/phone).
Reads files only. Never executes anything from the target.
Exit code: 0 = no HIGH/CRITICAL, 1 = HIGH found, 2 = CRITICAL found.
"""
import json, os, re, stat, sys, unicodedata
from collections import Counter

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# (category, severity, regex, explanation)
RULES = [
    # --- remote code execution / download-and-run
    ("rce", "CRITICAL", r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b", "Downloads and pipes straight into a shell"),
    ("rce", "CRITICAL", r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh", "Decodes hidden payload into a shell"),
    ("rce", "CRITICAL", r"powershell[^\n]*-(e|enc|encodedcommand)\b", "Encoded PowerShell payload"),
    ("rce", "HIGH", r"\b(eval|exec)\s*\(", "Dynamic code execution (eval/exec)"),
    ("rce", "HIGH", r"\bnew\s+Function\s*\(|\bvm\.runIn", "Dynamic JS code execution"),
    ("rce", "HIGH", r"__import__\s*\(|importlib\.import_module|\bcompile\s*\(", "Dynamic import/compile"),
    ("rce", "MEDIUM", r"subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\(", "Runs shell commands"),
    ("rce", "MEDIUM", r"\b(npx|uvx|pipx run|bunx)\s+[^\s]+", "Runs a package fetched at runtime"),
    ("deps", "MEDIUM", r"\b(pip3?|npm|pnpm|yarn|gem|cargo|brew)\s+(install|add|i)\b", "Installs dependencies (check names/pins)"),
    ("deps", "HIGH", r"\"(pre|post)install\"\s*:", "npm install-time script (runs on install)"),
    # --- secrets / private data access
    ("secrets", "CRITICAL", r"~/?\.ssh|id_rsa|id_ed25519|authorized_keys", "Touches SSH keys"),
    ("secrets", "CRITICAL", r"\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials", "Touches cloud/dev credentials"),
    ("secrets", "CRITICAL", r"\.claude/\.credentials|\.claude\.json|claude_desktop_config|anthropic_api_key", "Touches Claude credentials/config"),
    ("secrets", "CRITICAL", r"security\s+(find|dump)-(generic|internet)-password|dump-keychain|Keychains/", "Reads macOS Keychain"),
    ("secrets", "CRITICAL", r"Login Data|Cookies(\.sqlite)?\b|Local State|key4\.db|logins\.json|1Password|Bitwarden", "Reads browser/password-manager stores"),
    ("secrets", "HIGH", r"os\.environ(?!\.get\(['\"][A-Z_]+['\"]\))|process\.env(?!\.[A-Z_]+)|\bprintenv\b|\benv\s*\|", "Dumps all environment variables"),
    ("secrets", "HIGH", r"(API_KEY|SECRET|TOKEN|PASSWORD)\b", "Mentions secrets/tokens (verify use)"),
    ("secrets", "MEDIUM", r"(^|[\s\"'/])\.env\b", "Reads .env files"),
    ("privacy", "HIGH", r"Library/Messages|chat\.db|AddressBook|Contacts|Photos Library|Library/Mail|\.bash_history|\.zsh_history", "Reads personal data (messages, contacts, mail, history)"),
    ("privacy", "MEDIUM", r"screencapture|pbpaste|clipboard|getUserMedia|keylog|pynput|CGEventTap", "Screen/clipboard/keyboard capture"),
    # --- exfiltration / third-party sharing
    ("exfil", "CRITICAL", r"discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot", "Posts to chat webhook (classic exfil channel)"),
    ("exfil", "CRITICAL", r"pastebin\.com|transfer\.sh|ngrok\.io|requestbin|webhook\.site|pipedream\.net|interact\.sh|burpcollaborator|oast\.", "Known exfil/tunnel/paste endpoint"),
    ("exfil", "HIGH", r"\b(nc|ncat|netcat|socat)\s+-|/dev/tcp/|socket\.socket\(", "Raw network socket / reverse shell pattern"),
    ("exfil", "MEDIUM", r"requests\.(post|put)|urllib\.request|fetch\(|axios\.|curl\s+[^\n]*(-d|--data|-F|-T|--upload)", "Sends data over HTTP"),
    ("exfil", "LOW", r"analytics|telemetry|tracking|mixpanel|segment\.io|posthog|sentry\.io|google-analytics", "Telemetry/analytics"),
    # --- persistence / backdoor
    ("backdoor", "CRITICAL", r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap)|crontab\s|/etc/cron|systemctl\s+enable|schtasks", "Installs persistence (runs at boot/login)"),
    ("backdoor", "HIGH", r"\.(bashrc|zshrc|bash_profile|zprofile|profile)\b", "Edits shell startup files"),
    ("backdoor", "HIGH", r"\bsudo\b|chmod\s+[0-7]*[4-7][0-7]{3}|chmod\s+\+s|setuid", "Privilege escalation"),
    ("backdoor", "HIGH", r"osascript|tccutil|spctl\s+--master-disable|xattr\s+-d\s+com\.apple\.quarantine|csrutil", "Bypasses macOS security (Gatekeeper/TCC/quarantine)"),
    # --- Claude harness tampering
    ("claude-tamper", "CRITICAL", r"dangerously-skip-permissions|bypassPermissions|\"defaultMode\"\s*:\s*\"(bypass|acceptEdits)", "Disables Claude permission prompts"),
    ("claude-tamper", "HIGH", r"settings(\.local)?\.json|\"hooks\"\s*:|PreToolUse|PostToolUse|UserPromptSubmit|SessionStart", "Adds/edits Claude hooks or settings"),
    ("claude-tamper", "HIGH", r"\"permissions\"\s*:|\"allow\"\s*:\s*\[", "Grants itself tool permissions"),
    ("claude-tamper", "HIGH", r"CLAUDE\.md|\.claude/(skills|agents|commands|memory)|MEMORY\.md", "Writes to Claude memory/skills/instructions"),
    ("claude-tamper", "MEDIUM", r"mcpServers|\.mcp\.json", "Registers MCP servers"),
    # --- prompt injection (mostly in .md)
    ("injection", "HIGH", r"ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(system|previous)", "Instruction override attempt"),
    ("injection", "HIGH", r"(do not|don't|never) (tell|inform|mention|show|reveal)[^\n]{0,40}(user|human)", "Hides actions from the user"),
    ("injection", "HIGH", r"without (asking|confirmation|permission|telling)|silently|automatically approve|no need to (ask|confirm)", "Skips user consent"),
    ("injection", "MEDIUM", r"you are now|new system prompt|act as (root|admin|developer mode)|jailbreak|DAN mode", "Role/system hijack phrasing"),
    ("injection", "MEDIUM", r"<!--[\s\S]{0,400}?-->", "HTML comment (hidden text in Markdown)"),
    # --- destructive
    ("destructive", "HIGH", r"rm\s+-[rf]{2}\s+(/|~|\$HOME|\*)|\bmkfs\b|\bdd\s+if=|diskutil\s+erase|shred\s", "Destructive file/disk operation"),
    # --- advertising / monetization
    ("ads", "MEDIUM", r"sponsored|affiliate|promo ?code|discount code|referral|utm_(source|medium|campaign)|\?ref=|buy now|upgrade to (pro|premium)", "Advertising/affiliate content"),
    ("ads", "LOW", r"(recommend|mention|suggest)[^\n]{0,30}(our|my) (product|service|company|website)", "Self-promotion instruction"),
    # --- crypto
    ("crypto", "HIGH", r"xmrig|stratum\+tcp|coinhive|cryptonight|minerd", "Crypto-miner"),
    ("crypto", "MEDIUM", r"\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", "Hard-coded wallet address"),
]
COMPILED = [(c, s, re.compile(p, re.I), e) for c, s, p, e in RULES]

INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­"}
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
BIN_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyo", ".class", ".jar", ".app", ".pkg", ".dmg", ".msi", ".deb", ".rpm", ".node", ".wasm"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2"}
TEXT_LIMIT = 2_000_000
URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
HEX_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){20,}")


# Plain "what do I do" verdict per severity (shown for every level present).
ACTION = {
    "CRITICAL": "Do not install.",
    "HIGH": "Do not install until fixed, unless the author is trusted and the reason is clear.",
    "MEDIUM": "Install only after checking the flagged lines; usually a small fix or a condition.",
    "LOW": "OK to install; just be aware.",
}
# Cheapest rewrite per category: smallest edit that removes the risk and keeps the skill's purpose.
FIX = {
    "rce": "Replace eval/exec/shell calls with a fixed command list or a safe parser (json.loads, ast.literal_eval); pin any npx/uvx package to an exact version.",
    "deps": "Pin every dependency to an exact version; delete install-time scripts.",
    "secrets": "Remove the credential/env read; ask the user to pass only the one value needed.",
    "privacy": "Remove the personal-data read; work only on files the user names.",
    "exfil": "Delete the outbound call, or limit it to one documented domain that receives no user data.",
    "backdoor": "Delete the persistence/privilege step; run only when the user invokes the skill.",
    "claude-tamper": "Remove edits to Claude settings/hooks/memory; tell the user what to change instead.",
    "injection": "Delete the hidden or overriding text; keep only plain task steps.",
    "destructive": "Scope the delete to the skill's own temp folder and ask before running it.",
    "ads": "Strip promo/affiliate/tracking text and links.",
    "crypto": "Remove the miner or wallet address.",
    "binary": "Replace the binary/archive with readable source, or drop it.",
    "obfuscation": "Replace the encoded blob/minified code with readable source.",
    "filesystem": "Remove the symlink/hidden file or explain why it's needed.",
}
# Token cost model (approx, chars/4). Fix cost = per-finding context read + edit; LOW needs no fix.
FIX_TOKENS = {"CRITICAL": 800, "HIGH": 600, "MEDIUM": 300, "LOW": 0}
AUDIT_OVERHEAD, FIX_OVERHEAD = 3000, 1000  # SKILL.md + report; re-scan + summary
SIZES = [(5_000, "Very Small"), (20_000, "Small"), (60_000, "Medium"), (150_000, "Large"), (float("inf"), "Very Large")]
BAR_CELLS = "🟩🟩🟩🟨🟨🟨🟧🟧🟥🟥"  # green -> red gradient; works in chat on Mac and phone


def size_label(tokens):
    return next(lbl for lim, lbl in SIZES if tokens < lim)


def cost_bar(tokens, color=False):
    """10-cell gradient bar, log scale: 1k tokens = 1 cell, 300k+ = full."""
    import math
    n = max(1, min(10, round(10 * math.log10(max(tokens, 1000) / 1000) / math.log10(300))))
    if not color:
        return BAR_CELLS[:n] + "⬜" * (10 - n)
    cells = []
    for i in range(10):  # ANSI truecolor, green -> yellow -> red
        t = i / 9
        r, g = (int(510 * t), 200) if t < 0.5 else (255, int(200 * (2 - 2 * t)))
        cells.append(f"\033[38;2;{min(r, 255)};{g};40m█" if i < n else "\033[38;2;90;90;90m░")
    return "".join(cells) + "\033[0m"


def estimate(paths, unchanged, merged):
    read_chars = 0
    for full, rel in paths:
        if rel in unchanged:
            continue
        try:
            if os.path.splitext(full)[1].lower() not in BIN_EXT | ARCHIVE_EXT and not os.path.islink(full):
                read_chars += min(os.path.getsize(full), TEXT_LIMIT)
        except OSError:
            pass
    audit = AUDIT_OVERHEAD + read_chars // 4 + 40 * len(merged)
    per = [FIX_TOKENS[m["sev"]] for m in merged.values()]
    fix = (FIX_OVERHEAD + sum(per)) if any(per) else 0
    return audit, fix


def add(findings, sev, cat, path, line, msg, snippet=""):
    findings.append({"severity": sev, "category": cat, "file": path, "line": line, "issue": msg, "snippet": snippet[:160]})


def scan_file(full, rel, findings, domains, root):
    st = os.lstat(full)
    if stat.S_ISLNK(st.st_mode):
        target = os.path.realpath(full)
        sev = "HIGH" if not target.startswith(os.path.realpath(root)) else "LOW"
        add(findings, sev, "filesystem", rel, 0, f"Symlink -> {target}")
        return
    ext = os.path.splitext(full)[1].lower()
    if st.st_mode & stat.S_IXUSR:
        add(findings, "LOW", "filesystem", rel, 0, "File is executable")
    if ext in BIN_EXT:
        add(findings, "HIGH", "binary", rel, 0, f"Compiled/binary file ({ext}) — cannot be reviewed as source")
        return
    if ext in ARCHIVE_EXT:
        add(findings, "HIGH", "binary", rel, 0, f"Nested archive ({ext}) — contents hidden from review")
        return
    if st.st_size > TEXT_LIMIT:
        add(findings, "MEDIUM", "filesystem", rel, 0, f"Very large file ({st.st_size} bytes)")
        return
    with open(full, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:8000]:
        add(findings, "HIGH", "binary", rel, 0, "Binary content (null bytes) in non-binary extension")
        return
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if lines and max((len(l) for l in lines), default=0) > 1000 and ext in {".js", ".py", ".sh", ".ts", ".mjs", ".cjs"}:
        add(findings, "HIGH", "obfuscation", rel, 0, "Minified/very long line in source — possible obfuscation")
    for i, line in enumerate(lines, 1):
        for cat, sev, rx, expl in COMPILED:
            if rx.search(line):
                add(findings, sev, cat, rel, i, expl, line.strip())
        for m in URL_RE.finditer(line):
            domains[m.group(1).lower()] += 1
        if B64_RE.search(line):
            add(findings, "HIGH", "obfuscation", rel, i, "Long base64-like blob (hidden payload?)", line.strip())
        if HEX_RE.search(line):
            add(findings, "HIGH", "obfuscation", rel, i, "Hex-escaped string (hidden payload?)", line.strip())
        bad = [c for c in line if c in INVISIBLE or c in BIDI or 0xE0000 <= ord(c) <= 0xE007F]
        if bad:
            names = sorted({unicodedata.name(c, hex(ord(c))) for c in bad})
            add(findings, "CRITICAL" if any(c in BIDI or ord(c) >= 0xE0000 for c in bad) else "HIGH",
                "injection", rel, i, "Invisible/bidi/tag unicode (hidden instructions): " + ", ".join(names), repr(line.strip())[:160])
    # multiline HTML comments
    for m in re.finditer(r"<!--([\s\S]*?)-->", text):
        if len(m.group(1).strip()) > 0 and ext in {".md", ".mdx", ".txt", ".html"}:
            ln = text.count("\n", 0, m.start()) + 1
            add(findings, "MEDIUM", "injection", rel, ln, "Hidden HTML comment — read it", m.group(1).strip()[:160])


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(64)
    root = os.path.abspath(sys.argv[1]); as_json = "--json" in sys.argv
    findings, domains, inventory = [], Counter(), []
    paths = [(root, os.path.basename(root))] if os.path.isfile(root) else []
    if os.path.isdir(root):
        for d, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [x for x in dirs if x not in {".git", "node_modules", "__pycache__"}]
            if "node_modules" in os.listdir(d):
                add(findings, "MEDIUM", "deps", os.path.relpath(d, root), 0, "Vendored node_modules — large unreviewable surface")
            for f in files:
                full = os.path.join(d, f); paths.append((full, os.path.relpath(full, root)))
            for x in dirs:
                if x.startswith(".") and x not in {".claude-plugin", ".github"}:
                    add(findings, "LOW", "filesystem", os.path.relpath(os.path.join(d, x), root), 0, "Hidden directory")
    for full, rel in paths:
        inventory.append(rel)
        if os.path.basename(rel).startswith(".") and os.path.basename(rel) not in {".gitignore", ".mcp.json"}:
            add(findings, "LOW", "filesystem", rel, 0, "Hidden file")
        try:
            scan_file(full, rel, findings, domains, root)
        except OSError as e:
            add(findings, "MEDIUM", "filesystem", rel, 0, f"Unreadable: {e}")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    counts = Counter(f["severity"] for f in findings)
    # --- hash cache: files byte-identical to a previously reviewed-clean version need no manual re-read
    import hashlib
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit-cache.json")
    try: cache = json.load(open(cache_path))
    except Exception: cache = {}
    hashes = {}
    for full, rel in paths:
        try: hashes[rel] = hashlib.sha256(open(full, "rb").read()).hexdigest()
        except OSError: pass
    unchanged = sorted(r for r, h in hashes.items() if h in cache)
    if "--mark-clean" in sys.argv:  # call only after a human-approved review
        import datetime
        for r, h in hashes.items(): cache[h] = {"file": r, "date": datetime.date.today().isoformat()}
        json.dump(cache, open(cache_path, "w"), indent=0)
    merged = {}  # one entry per file:line, highest severity wins
    for f in findings:
        k = (f["file"], f["line"])
        m = merged.setdefault(k, {"sev": f["severity"], "tags": [], "cats": [], "snip": f["snippet"]})
        if SEV_ORDER[f["severity"]] > SEV_ORDER[m["sev"]]: m["sev"] = f["severity"]
        tag = f"{f['category']}:{f['issue']}"
        if tag not in m["tags"]: m["tags"].append(tag)
        if f["category"] not in m["cats"]: m["cats"].append(f["category"])
    audit_t, fix_t = estimate(paths, set(unchanged), merged)
    present = [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)]
    fix_cats = []  # categories needing a fix (MEDIUM+), worst first
    for m in sorted(merged.values(), key=lambda m: -SEV_ORDER[m["sev"]]):
        if SEV_ORDER[m["sev"]] >= 2:
            for c in m["cats"]:
                if c not in fix_cats and c in FIX: fix_cats.append(c)
    cost = {"audit_tokens": audit_t, "audit_size": size_label(audit_t), "fix_tokens": fix_t,
            "fix_size": size_label(fix_t) if fix_t else "None"}
    result = {"target": root, "files": inventory, "domains": dict(domains.most_common()), "counts": dict(counts),
              "cost": cost, "verdicts": {s: ACTION[s] for s in present},
              "cheapest_rewrite": [{"category": c, "fix": FIX[c]} for c in fix_cats],
              "findings": findings, "unchanged_reviewed": unchanged}
    color = "--color" in sys.argv

    def summary():
        print(f"Cost: audit ~{audit_t // 1000 or '<1'}k tokens {cost_bar(audit_t, color)} {cost['audit_size']}")
        if fix_t:
            print(f"      fix   ~{fix_t // 1000 or '<1'}k tokens {cost_bar(fix_t, color)} {cost['fix_size']} (upper bound; false positives cost nothing)")
        else:
            print("      fix   none needed")
        print("What to do:" + ("".join(f"\n  {s.title()}: {ACTION[s]}" for s in present) or " No findings. OK to install after manual review."))
        if fix_cats:
            print("Cheapest rewrite (keeps the skill's purpose; apply only on the user's yes):")
            for c in fix_cats: print(f"  - {c}: {FIX[c]}")

    if as_json:
        print(json.dumps(result, separators=(",", ":")))
    elif "--full" not in sys.argv:
        # Compact (default): same findings, merged per file:line, one snippet, no repetition
        print(f"Files({len(inventory)}): " + ", ".join(inventory))
        if unchanged: print(f"Unchanged since reviewed-clean ({len(unchanged)}, skip manual re-read unless flagged): " + ", ".join(unchanged))
        print("Domains: " + (", ".join(f"{d}({n})" for d, n in domains.most_common()) or "none"))
        print("Counts: " + " ".join(f"{k[0]}={counts.get(k,0)}" for k in SEV_ORDER if k != "INFO"))
        summary()
        grouped = {}  # MEDIUM/LOW repeats: one line per (file, tags) with all line numbers
        for (fp, ln), m in sorted(merged.items(), key=lambda kv: (-SEV_ORDER[kv[1]["sev"]], kv[0])):
            if SEV_ORDER[m["sev"]] >= 3:
                snip = f" | {m['snip'][:100]}" if m["snip"] else ""
                print(f"{m['sev'][0]} {fp}:{ln} {'; '.join(m['tags'])}{snip}")
            else:
                g = grouped.setdefault((m["sev"], fp, "; ".join(m["tags"])), {"lines": [], "snip": m["snip"]})
                g["lines"].append(ln)
        for (sev, fp, tags), g in grouped.items():
            snip = f" | e.g. {g['snip'][:80]}" if g["snip"] else ""
            print(f"{sev[0]} {fp}:{','.join(map(str, g['lines']))} {tags}{snip}")
    else:
        print(f"Target: {root}\nFiles ({len(inventory)}):"); [print("  -", p) for p in inventory]
        print("\nExternal domains referenced:"); [print(f"  - {d} ({n})") for d, n in domains.most_common()] or print("  (none)")
        print("\nCounts:", {k: counts.get(k, 0) for k in SEV_ORDER}); summary()
        for f in findings:
            if f["severity"] == "INFO": continue
            print(f"[{f['severity']}] {f['category']} {f['file']}:{f['line']} — {f['issue']}")
            if f["snippet"]: print(f"      {f['snippet']}")
    sys.exit(2 if counts.get("CRITICAL") else 1 if counts.get("HIGH") else 0)


if __name__ == "__main__":
    main()
