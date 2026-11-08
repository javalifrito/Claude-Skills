# Claude-Skills

Personal Claude skills by [@javalifrito](https://github.com/javalifrito). One folder per skill.

| Skill | What it does |
|---|---|
| [skill-security-audit](skill-security-audit/) | Audits any shared skill, plugin, MCP server or hook before you install it. Returns APPROVE / APPROVE WITH CONDITIONS / REJECT. |

## Install a skill

Each skill works on both the Mac and the phone from the same files.

- **Claude Code (Mac/PC):** copy the skill's folder into `~/.claude/skills/`, so you have `~/.claude/skills/<skill-name>/SKILL.md`. Start it with `/<skill-name>` or just ask.
- **Phone / claude.ai:** download `<skill-name>.zip` from the [latest release](../../releases/latest) and upload it at claude.ai → Settings → Capabilities → Skills. It then works on web, desktop and mobile. Start it by asking (e.g. "audit this skill").
