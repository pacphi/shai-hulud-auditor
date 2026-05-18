# 🐛 shai-hulud-auditor

> 🛡️ A zero-dependency Node script that hunts for the **Mini Shai-Hulud / Shai-Hulud 2.0** npm supply-chain compromise (Apr–May 2026) — across one repo, a whole folder of repos, or any git URL.
>
> **Tracking:** [CVE-2026-45321](https://borecraft.com/news/tanstack-mini-shai-hulud-cve-2026-45321-guide.html) · Snyk **GHSA-g7cv-rxg3-hmpx** · Mini Shai-Hulud waves of **29 April – 13 May 2026**.

---

## ⚠️ Read this first

- **🪪 SLSA provenance signatures pass on these packages.** The attacker used a stolen OIDC token to publish through the legitimate TanStack pipeline, so `npm audit signatures` and provenance attestation checks **report green on compromised versions**. You must check the version list, not the signature. ([Wiz][wiz-readme], [VentureBeat][vb-readme])
- **🪤 The watchdog wipes `$HOME` on token revocation.** Image / snapshot the host before touching credentials. Order is: **disarm persistence → re-audit → rotate** — see [MACOS.md](MACOS.md) / [LINUX.md](LINUX.md).
- **📅 If you ran `npm install` / `npm ci` between 29 April and 13 May 2026**, re-audit. That's the Mini Shai-Hulud publish window — anything resolved inside it should be re-checked, including CI build agents. ([Snyk][snyk-readme], [Carthage][carth-readme])
- **🤖 Driving an AI coding assistant?** [PROMPTS.md](PROMPTS.md) has 12 copy-pasteable prompts that walk an assistant through every check below — per-repo audit, host triage, lockfile-history forensics, workflow secret / OIDC inspection, CI hardening PRs — with the watchdog warning baked in so it can't accidentally trigger the wiper.

[wiz-readme]: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
[vb-readme]: https://venturebeat.com/security/shai-hulud-worm-172-npm-pypi-packages-valid-provenance-ci-cd-audit
[snyk-readme]: https://snyk.io/blog/tanstack-npm-packages-compromised/
[carth-readme]: https://carthageelectronics.com/npm-supply-chain-crisis-mini-shai-hulud-may-2026/

---

## 📚 Related docs

- [MACOS.md](MACOS.md) — host-level remediation on macOS (LaunchAgent, APFS snapshots, reinstall)
- [LINUX.md](LINUX.md) — host-level remediation on Linux (systemd, btrfs/LVM/ZFS, reimage)
- [HARDENING.md](HARDENING.md) — preventive controls for CI build agents and dev workstations
- [TEMPLATES.md](TEMPLATES.md) — comms templates for paused releases, IR updates, stakeholder briefings
- [PROMPTS.md](PROMPTS.md) — copy-pasteable prompts for driving an AI assistant through the same triage
- [scripts/triage-macos.sh](scripts/triage-macos.sh) · [scripts/triage-linux.sh](scripts/triage-linux.sh) — read-only persistence inventories
- [scripts/remediate-repo.sh](scripts/remediate-repo.sh) — repo-level cleanup helper (refuses to run while host persistence is present)

---

## 🤔 Why you want this

The Shai-Hulud worm slipped malicious versions into **170+ packages** across TanStack, Mistral, UiPath, OpenSearch, and friends. The payload exfiltrates tokens **and** ships a watchdog that wipes `$HOME` if it detects revocation. Not great. 😬

`shai-hulud-audit` tells you, fast:

- ✅ Is anything in my lockfiles a known-bad `package@version`?
- ⚠️ Does any `package.json` even *name* an at-risk package?
- 🕳️ Is the `@tanstack/setup` orphan-commit IOC sitting in my `node_modules`?
- 🪤 Are the persistence hooks (`~/.claude/setup.mjs`, `gh-token-monitor.service`, …) on this machine?

No installs. No dependencies. One file. Run it everywhere.

---

## ✨ Features

- 📦 **npm + pnpm** lockfile support (`package-lock.json` v1/v2/v3, `pnpm-lock.yaml` v5/v6/v9)
- 🌲 **Recursive** — point it at a folder of repos and get a per-project verdict
- 🌐 **Clone-and-scan** — give it a GitHub / GitLab / Bitbucket / SSH / generic git URL and it shallow-clones to a temp dir, audits, then cleans up
- 🧪 Detects the `@tanstack/setup` optionalDependency + `router_init.js` IOCs
- 🖥️ Checks machine-level persistence paths
- 🎯 Clean exit codes for CI: `0` clean, `1` findings, `2` error
- 🪶 Zero runtime deps — just Node ≥ 16

---

## 🚀 Quick start

```bash
# Audit the current directory
node audit.js

# Audit one specific project
node audit.js ~/code/my-app

# Audit a whole folder of repos
node audit.js ~/code

# Audit a remote repo without cloning it yourself
node audit.js https://github.com/your-org/your-repo.git
```

Make it executable if you like:

```bash
chmod +x audit.js
./audit.js .
```

---

## 🎛️ Modes

### 1. 📁 Single project

```bash
node audit.js ./my-app
```

Looks for `package-lock.json`, `pnpm-lock.yaml`, and `package.json` in the given directory.

### 2. 🌲 Recursive (a "repo of repos")

```bash
node audit.js ~/workspace
```

Walks the tree, skipping `node_modules`, `.git`, `dist`, `build`, `.next`, `.turbo`, `.cache`, hidden dirs, and symlinks. Each project gets its own line:

```
[clean]       repoB                  (npm, 842 pkgs)
[COMPROMISED] frontend/web           (pnpm, 1503 pkgs)
    lockfile: @tanstack/react-router@1.169.5
[COMPROMISED] services/api           (package.json-only, 0 pkgs)
    package-json: at-risk name "@mistralai/mistralai" declared in dependencies ("^2.2.3") — compromised versions: 2.2.3, 2.2.4
```

### 3. 🌐 Git URL (clone + scan + cleanup)

```bash
node audit.js https://github.com/your-org/your-repo.git
node audit.js git@github.com:your-org/your-repo.git
node audit.js https://gitlab.com/group/project.git
node audit.js https://bitbucket.org/team/repo.git
```

Performs `git clone --depth 1` into `os.tmpdir()/shai-hulud-audit-XXXX/`, runs the full audit, and removes the temp dir on exit (including `SIGINT`/`SIGTERM`). 🧹

---

## 📊 What you get

```
Mini Shai-Hulud Audit
Date:    2026-05-18T18:36:48.926Z
IOC set: 170 package names, 344 versions

Discovering projects
  Found 12 project directories.

Per-project audit
  [clean]       .
  [COMPROMISED] packages/router      (pnpm, 1487 pkgs)
      lockfile: @tanstack/router-core@1.169.5
  ...

Machine-level persistence hooks
  No known persistence hooks detected.

Summary
  Projects scanned:     12  (npm: 4, pnpm: 7, other: 1)
  Resolved packages:    18342
  Compromised projects: 1
  Total findings:       1
  Persistence hits:     0
```

---

## 🤖 In CI

```yaml
- name: Shai-Hulud audit
  run: node audit.js .
```

Pipeline fails (`exit 1`) the instant anything matches. 🟥

---

## 🤖 With an AI assistant

If you're already working with Claude Code / Cursor / Aider / Copilot Workspace, [PROMPTS.md](PROMPTS.md) ships 12 self-contained prompts you can paste verbatim:

| # | Prompt | When to use |
|---|---|---|
| 1 | Audit a single repo | Starting cold on any repo |
| 2 | Triage the host for persistence | Starting cold on any machine |
| 3 | Pin past IOCs + refresh lockfile | Auditor flagged a `package-json` finding |
| 4 | Audit workflows for OIDC / secrets | Need to know if CI could have leaked tokens |
| 5 | Check GitHub run history in window | Reconstructing what ran between 29 Apr–13 May |
| 6 | Lockfile-history forensics | Prove the worm never resolved in this repo |
| 7 | Repo secret / variable inventory | Decide what to rotate |
| 8 | Pre-commit safety check | About to push remediation commits |
| 9 | Build a CI hardening PR | Applying HARDENING.md §1 in one PR |
| 10 | Stakeholder comms drafting | Slack post / leadership note / IR status |
| 11 | Post-incident retrospective | After the all-clear |
| 12 | Re-audit on a schedule | LaunchAgent or systemd timer for weekly checks |

Every prompt that touches credentials or persistence repeats the **watchdog warning** verbatim and asks the assistant to **show a diff before any destructive action** — so even a misconfigured agent can't accidentally `rm -rf` or revoke tokens.

---

## 🚨 If it finds something

🛑 **Do NOT immediately revoke npm tokens or delete files.**

The malware ships a token-monitor watchdog that triggers a `$HOME` wipe when it detects revocation. Order of operations matters: **disarm persistence → re-audit → rotate credentials → reinstall.**

Step-by-step playbooks:

- 🍎 **macOS:** [MACOS.md](MACOS.md) + `bash scripts/triage-macos.sh`
- 🐧 **Linux:** [LINUX.md](LINUX.md) + `bash scripts/triage-linux.sh`
- 🔧 **Repo-level cleanup (cross-platform):** `bash scripts/remediate-repo.sh /path/to/repo`
- 🛡️ **Preventing the next wave:** [HARDENING.md](HARDENING.md)
- 📣 **Briefing stakeholders / pausing a release:** [TEMPLATES.md](TEMPLATES.md)
- 🤖 **Have an AI assistant drive it for you:** [PROMPTS.md](PROMPTS.md) — start with **#1 Audit a single repo** and **#2 Triage the host for persistence**, then follow the sequence the prompts spell out.

Quick summary:

1. 🖼️ Image / snapshot the affected machine first.
2. 🧯 Disconnect it from the network.
3. 🪤 Quarantine the persistence artefacts BEFORE touching any tokens.
4. 🧼 Rotate credentials from a **clean** environment afterward.

---

## 🧠 How it works (60-second tour)

The script is one file, organised top-to-bottom in six sections:

1. **IOC data** — the compromised `package@version` list + persistence paths
2. **Audit primitives** — pure `isCompromised(name, version)` checks
3. **Lockfile parsers** — npm JSON + pnpm YAML (regex, no deps) → flat `{name, version}` lists
4. **Project auditor** — runs every check against one directory, returns a structured result
5. **Discovery** — recursive walker + git-URL clone helper
6. **Reporting / main** — CLI, per-project lines, summary

Want to extend the IOC list? Edit the `COMPROMISED` map at the top. That's it. ✂️

---

## 🙏 Credits

- **[Peter Hollis](https://github.com/peter-hollis-orkastrate)** — originated the version of the audit script this repo is built on, including the IOC inventory and persistence-path checks. The Orkastrate pre-release audit checklist that informed [HARDENING.md](HARDENING.md) and [TEMPLATES.md](TEMPLATES.md) also came from his work.
- The security researchers and vendors whose IOC writeups are cited throughout [MACOS.md](MACOS.md), [LINUX.md](LINUX.md), and [HARDENING.md](HARDENING.md) — StepSecurity, Snyk, Wiz, Expel, Arctic Wolf, Phoenix Security, Picus, Elastic, VentureBeat, Carthage Electronics, Intrudify, Datadog, Orca, Guardz, Socprime, Corgea, Microsoft Security, Unit 42, Socket.

---

## 📜 License

Use it, fork it, ship it. Stay safe out there. 🌵

