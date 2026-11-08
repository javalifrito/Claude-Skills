# skill-security-audit

A Claude skill that audits a shared skill, plugin, MCP server, hook, agent or command **before** you install it, and returns a verdict: **APPROVE**, **APPROVE WITH CONDITIONS** or **REJECT**.

It never runs the code it audits. It only reads it.

## What it checks

- **Source reputation** (`scripts/source_check.py`): allow/block lists, stars, forks, repo and owner age, contributors, license, last push, signed commits, and issues that mention security problems. Uses the public GitHub API only and sends nothing about you.
- **Static scan** (`scripts/scan.py`): lists every file and external domain, and flags remote code execution, credential and private-data access, persistence/backdoors, obfuscation, prompt injection (including hidden unicode), ads and tracking, supply-chain risks and destructive operations, by severity.
- **Manual review**: a 15-point checklist Claude works through for every file (see `SKILL.md`).

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | The skill: when it triggers, hard rules, steps, verdict rules |
| `scripts/scan.py` | Static scanner. `python3 -I scan.py <dir> [--json] [--full] [--mark-clean]` |
| `scripts/source_check.py` | Source/reputation check. `python3 -I source_check.py <github-url \| owner/repo \| domain>` |
| `sources.json` | Allowlist and blocklist of sources. Edit only with the user's approval. |
| `audit-log.md` | One line per audit: date, skill, source@SHA, verdict, top reason |

## Install

Copy this folder to `~/.claude/skills/skill-security-audit/`. The scripts need Python 3 only (standard library, no dependencies). Set `GITHUB_TOKEN` to raise the GitHub API rate limit (optional).

## Use

Ask Claude "is this skill safe?" with a link, zip, folder or marketplace name, or just ask it to install a shared skill: the skill triggers first and reports before anything is installed.

## Note

Scanning this skill with itself reports many CRITICAL/HIGH hits. They are false positives: the scanner's own detection patterns and the checklist in `SKILL.md` name the very things they look for.
