# Linux Remediation Guide — Shai-Hulud / Mini Shai-Hulud

This guide is for developers and SREs who ran `audit.js` on Linux and got hits
— either in their projects (`package-json` / `lockfile` findings) or on the
machine itself (persistence hooks: user-level systemd unit, dotfile artefacts,
or root-level units). It walks the safe order of operations, distro-friendly
commands, and links to authoritative external write-ups so you can verify any
step before running it.

> **The single most important rule:** **remove on-host persistence BEFORE you
> revoke any tokens.** The `gh-token-monitor` daemon polls GitHub roughly
> every 60 seconds; if it sees a watched token get revoked it executes
> `rm -rf $HOME`. Sources: [Wiz][wiz], [Expel][expel], [Arctic Wolf][arctic],
> [Mini Shai-Hulud Scanner][scanner].

---

## 0a. Things that **do not** save you

- **`npm audit signatures` / provenance attestations.** The attacker published
  through the legitimate TanStack OIDC pipeline. SLSA provenance is valid on
  the compromised versions. ([VentureBeat][venturebeat], [Wiz][wiz])
- **2FA on the maintainer's account.** It was bypassed entirely — OIDC tokens
  were extracted from a CI runner.
- **A green `npm install` with no errors.** Lifecycle scripts succeed quietly;
  that's the whole point.

## 0b. When to re-audit

Re-run `node audit.js .` against any repo (or any CI build agent's workspace)
that has had **`npm install`**, **`npm ci`**, **`pnpm install`**, or
**`yarn install`** run inside the exposure window of **29 April 2026 –
13 May 2026** (the Mini Shai-Hulud publish window). Pull CI logs for that
range and re-audit the workspaces of any matching runs.

## 0c. Decision tree

```
$ node audit.js ~
                │
                ├── Persistence hits: 0      AND   Compromised projects: 0
                │       → You're clean. Stop. Re-run after each install.
                │
                ├── Persistence hits: 0      AND   Compromised projects ≥ 1
                │       → Section 4 (repo-only remediation). No reinstall needed.
                │
                └── Persistence hits ≥ 1     (regardless of repo findings)
                        → Section 1 (contain) → 2 (rotate) → 3 (reimage)
                          → 4 (repo cleanup) on a clean machine.
```

---

## 1. Contain the host (only if persistence hits ≥ 1)

### 1a. Cut network egress, not everything

You want to stop exfil and stop the watchdog from observing token revocation,
but keep enough local access to take snapshots. Choose one:

```sh
# Hard cut (all egress except loopback). Restores on reboot.
sudo nft add table inet shai_block 2>/dev/null
sudo nft 'add chain inet shai_block out { type filter hook output priority 0; policy drop; }'
sudo nft 'add rule inet shai_block out oifname "lo" accept'
sudo nft 'add rule inet shai_block out ct state established,related accept'

# Or, if you use iptables:
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Or, dumb but effective:
sudo ip link set dev eth0 down                    # adjust interface name
```

The watchdog needs network connectivity to check token state, so cutting egress
disarms its trigger condition while you investigate. Keep network OFF until
section 1d is complete.

### 1b. Take a filesystem snapshot for forensics

```sh
# btrfs
sudo btrfs subvolume snapshot -r / /snap-pre-remediation-$(date +%F)

# LVM (replace VG/LV with your names)
sudo lvcreate --size 5G --snapshot --name shai_snap /dev/mapper/vg0-root

# ZFS
sudo zfs snapshot rpool/ROOT/default@pre-remediation

# Anything else (last resort): tar critical bits to external media.
sudo tar --xattrs -cpf /media/external/preserve-$(date +%F).tar \
  /home/$USER/.claude /home/$USER/.vscode /home/$USER/.config/systemd \
  /etc/systemd/system /var/log
```

### 1c. Inventory persistence (read-only)

Run the bundled script:

```sh
bash scripts/triage-linux.sh
```

Or do it by hand:

```sh
# User-level systemd
systemctl --user list-unit-files | grep -Ei 'token|github|gh-token'
ls -la ~/.config/systemd/user/ 2>/dev/null
ls -la ~/.local/bin/ | grep -Ei 'token|github|gh-token' 2>/dev/null

# Root / system-level systemd
sudo systemctl list-unit-files | grep -Ei 'token|github|gh-token'
ls -la /etc/systemd/system/ | grep -Ei 'token|github|gh-token'
ls -la /usr/local/bin/ | grep -Ei 'token|github|gh-token'

# Per-user / system cron
crontab -l 2>/dev/null
sudo ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
sudo cat /var/spool/cron/crontabs/* 2>/dev/null

# Desktop autostart (GNOME/KDE)
ls -la ~/.config/autostart/ 2>/dev/null

# Shell rc tampering — `command -v` shadowing, function override, exec at login
grep -nE 'gh-token|token-monitor|router_init|router_runtime' \
     ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.config/fish/config.fish \
     2>/dev/null

# IDE artefacts
ls -la ~/.claude/ 2>/dev/null
ls -la ~/.vscode/ 2>/dev/null
grep -l 'router_runtime\|router_init' ~/.vscode/tasks.json 2>/dev/null

# Worm payload on disk
sudo find / -xdev -name 'router_init.js'     -size +1M 2>/dev/null
sudo find / -xdev -name 'router_runtime.js'  2>/dev/null
sudo find / -xdev -path '*/.claude/setup.mjs' 2>/dev/null
sudo find / -xdev -path '*/.vscode/setup.mjs' 2>/dev/null
```

Known IOC file names (Wiz, Expel, Carthage, audit.js IOC list):

| Path | Notes |
|---|---|
| `~/.config/systemd/user/gh-token-monitor.service` | Wiz / Carthage variant |
| `~/.local/bin/gh-token-monitor.sh` | Wiz variant |
| `/etc/systemd/system/gh-token-monitor.service` | audit.js IOC list |
| `~/.claude/setup.mjs` | preinstall persistence |
| `~/.claude/router_runtime.js` | worm runtime |
| `~/.claude/setup_bun.js`, `bun_environment.js` | Bun-flavoured variants |
| `~/.vscode/setup.mjs` | VS Code persistence |
| `~/.vscode/tasks.json` (modified) | `folderOpen` task added |

### 1d. Disarm the daemon BEFORE removing files

Order matters. Stop the unit so it can't react during file deletion:

```sh
# User-level
systemctl --user stop  gh-token-monitor.service 2>/dev/null
systemctl --user disable gh-token-monitor.service 2>/dev/null
systemctl --user mask gh-token-monitor.service 2>/dev/null
systemctl --user daemon-reload

# System-level
sudo systemctl stop  gh-token-monitor.service 2>/dev/null
sudo systemctl disable gh-token-monitor.service 2>/dev/null
sudo systemctl mask gh-token-monitor.service 2>/dev/null
sudo systemctl daemon-reload

# Kill stragglers
pgrep -af 'token-monitor|router_runtime|router_init'
# If anything matches: kill -9 <pid>

# Verify nothing running
systemctl --user list-units --type=service | grep -Ei 'token|gh-token'
sudo systemctl list-units --type=service | grep -Ei 'token|gh-token'
ss -ntp | grep -Ei 'node|bun'                  # outbound conns
```

Then quarantine (don't delete yet — preserve for incident response):

```sh
mkdir -p ~/quarantine-shai-hulud

mv ~/.config/systemd/user/gh-token-monitor.service ~/quarantine-shai-hulud/ 2>/dev/null
mv ~/.local/bin/gh-token-monitor.sh                ~/quarantine-shai-hulud/ 2>/dev/null
sudo mv /etc/systemd/system/gh-token-monitor.service ~/quarantine-shai-hulud/ 2>/dev/null

mv ~/.claude ~/quarantine-shai-hulud/dot-claude 2>/dev/null
cp ~/.vscode/tasks.json ~/quarantine-shai-hulud/vscode-tasks.json 2>/dev/null
```

Re-run the auditor to confirm zero persistence hits before continuing:

```sh
node audit.js ~
```

---

## 2. Rotate credentials (only AFTER section 1 reports zero persistence)

Do this from a **different, known-clean** machine, not the one you just
disarmed. The watchdog is gone but you should still treat the host as
untrusted until you've reimaged.

**Scoping rule:** anything reachable as an environment variable, file, secret
mount, or token from the compromised user account — or from any CI build
agent that pulled an affected version — is in scope. When in doubt, rotate
it. Also review your GitHub **org audit log** for unexpected workflow runs /
token uses **since 29 April 2026**, and pull Azure DevOps / GitLab / Jenkins
audit trails for the same window.

Order:

1. **npm publish/automation tokens** — npmjs.com → Access Tokens → revoke all.
2. **GitHub PATs, fine-grained tokens, OIDC trusts** — github.com → Settings →
   Developer settings → Personal access tokens; also review SSO authorisations
   and any OAuth apps. Check `Settings → Security log` and org `Audit log` for
   pushes / Actions runs you didn't trigger.
3. **SSH keys** — generate new on the clean host, remove old from GitHub /
   GitLab / Bitbucket.
4. **Cloud creds** — AWS access keys + IAM roles; GCP service-account JSON;
   Azure SPNs; Cloudflare, Vercel, Netlify, Fly.io, Docker Hub, GHCR,
   HashiCorp Vault, Kubernetes service-account tokens (`~/.kube/config`).
5. **CI/CD secrets** — GitHub Actions repository + organisation secrets,
   GitLab CI variables, CircleCI contexts, Jenkins credentials.
6. **Anything in dotfiles** — grep your shell rc, `~/.npmrc`, `~/.netrc`,
   `~/.aws/credentials`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`,
   any `.env*` files for tokens before you destroy them.

The Wiz, Carthage, and Phoenix Security write-ups all stress: **assume every
secret accessible from the compromised user account is exposed.**

---

## 3. Reimage the host

Linux gives you more options than macOS. Pick based on blast radius:

- **Workstation:** clean OS reinstall to a fresh partition. Mount the old
  `/home` read-only and copy out documents file-by-file. Do **not** restore
  `~/.config`, `~/.local`, `~/.claude`, `~/.vscode`, `~/.npmrc`, shell rc
  files, or any `node_modules`.
- **Server / build agent:** rebuild from your provisioning automation
  (Ansible, Pulumi, cloud-init). Treat the old image as quarantined. Rebuild
  immutable AMIs / container base images from upstream sources.
- **CI runner:** terminate and recreate from a fresh runner image. If a
  GitHub Actions self-hosted runner is involved, also rotate the runner
  registration token.

After reinstall:

```sh
# Clean clone with no scripts run during install.
git clone <repo>
cd <repo>
npm ci --ignore-scripts                  # or: pnpm install --ignore-scripts
node /path/to/audit.js .                 # confirm clean
```

---

## 4. Repo-level remediation (no host reimage needed)

If `Persistence hits: 0` you only need to clean the flagged repos. Use this
section.

### 4a. Snapshot

```sh
# btrfs / LVM / ZFS as in section 1b, or use git to fence:
git stash --include-untracked
```

### 4b. For each repo flagged COMPROMISED

```sh
cd /path/to/repo

# Wipe resolved deps and lockfile so nothing pinned to bad versions survives.
rm -rf node_modules
rm -f package-lock.json pnpm-lock.yaml yarn.lock
rm -rf .next .turbo .nuxt dist build .cache

# Edit package.json: pin each flagged dep above the IOC versions.
# `audit.js` prints the compromised version list; bump past it.
# Example: "@tanstack/react-router": "^1.170.4"

# First install: ignore lifecycle scripts so postinstall payloads can't run.
pnpm install --ignore-scripts            # or: npm install --ignore-scripts

# Re-audit. Should report clean (or "clean (info)" for pinned-past notes).
node /path/to/audit.js .
```

Use the bundled helper to do the rm/snapshot/audit dance in one step (it does
**not** modify your package.json — version pinning stays a human decision):

```sh
bash scripts/remediate-repo.sh /path/to/repo
```

### 4c. Manual cross-check (belt-and-suspenders)

If you don't fully trust the auditor (or want a second-pair-of-eyes scan
before deleting `node_modules`), these one-liners catch the same IOCs the
script does:

```sh
# Orphan-commit IOC: optionalDependencies['@tanstack/setup'] pointing at a tarball/commit.
grep -r '"@tanstack/setup"' node_modules 2>/dev/null

# router_init.js IOC: large embedded payload, sometimes >1MB.
find node_modules -name 'router_init.js' -size +1M 2>/dev/null

# Suspicious commit ref in lockfiles (worm phones home through tanstack/router#79ac49ee...).
grep -nE 'tanstack/router#[0-9a-f]{6,}' package-lock.json pnpm-lock.yaml 2>/dev/null
```

If any of these return rows, the lockfile was poisoned even if the version
strings look fine — discard and rebuild as in §4b.

### 4d. Inspect `~/.npm` cache for orphan tarballs

`audit.js` reports git-clone tmp dirs in `~/.npm/_cacache/tmp`. These are
left-overs from cancelled installs and are not malicious by themselves, but
the worm sometimes seeds tarballs there. Inspect, then clean if you want:

```sh
ls -la ~/.npm/_cacache/tmp 2>/dev/null
npm cache verify
# If anything looks off, full reset:
npm cache clean --force
```

---

## 5. Verification checklist

```sh
# Persistence — must be 0
node audit.js ~ | grep -E 'Persistence hits|PRESENT'

# Per-repo — must be 0 real findings (info-only is fine)
node audit.js ~ | grep -E 'Compromised projects|Total findings'

# Outbound to known C2 should resolve nowhere.
dig +short git-tanstack.com
dig +short seed1.getsession.org
dig +short filev2.getsession.org

# Local /etc/hosts sinkhole as defence-in-depth:
sudo tee -a /etc/hosts <<'EOF'
0.0.0.0 git-tanstack.com
0.0.0.0 seed1.getsession.org
0.0.0.0 seed2.getsession.org
0.0.0.0 seed3.getsession.org
0.0.0.0 filev2.getsession.org
EOF

# Flush nsswitch cache (varies by distro):
sudo systemctl restart systemd-resolved 2>/dev/null \
  || sudo systemctl restart nscd 2>/dev/null \
  || true
```

---

## 5b. Hardening before the next install / release

Once the host and repos are clean, lock the door. See [HARDENING.md](HARDENING.md)
for the full preventive playbook (CI agents, lockfile discipline, monitoring).
The two highest-leverage controls:

- `npm config set ignore-scripts true` **persistently** on every CI build
  agent. Lifecycle scripts are the primary execution vector for this worm
  family. Carthage and the Orkastrate pre-release audit both recommend this
  as a permanent CI policy, not just a one-time install flag.
- Pin direct dependencies to **exact** versions in `package.json` and commit
  the lockfile. Drop `^` / `~` ranges on production-bound packages. Even
  with the auditor's range-intersection check, exact pinning is the only way
  to make `npm ci` deterministic against future compromises.

## 6. CI/CD-specific notes

The worm's primary spread vector is OIDC token theft from GitHub Actions
runners. For each repo:

- Inventory `.github/workflows/*` for `permissions: id-token: write` plus
  any third-party action whose `@<sha>` you can't pin. Replace floating
  tags with commit SHAs.
- In GitHub Actions: rotate the repo / org's OIDC subject claim and any
  cloud-side trust policies (AWS `sts:AssumeRoleWithWebIdentity` conditions,
  GCP Workload Identity Federation providers).
- For self-hosted runners, rebuild the runner image and re-register.

References: [VentureBeat 6 steps][venturebeat], [Elastic response][elastic],
[Phoenix Security][phoenix].

---

## 7. Why this script doesn't auto-remove persistence

Two reasons:

1. **Wiper risk:** any wrong move while persistence is still running can
   trigger `rm -rf $HOME`. The auditor's contract is *find, don't fight*.
2. **Forensics:** if you may need to file an incident report (employer,
   regulator, customer disclosure), you want the artefacts quarantined, not
   shredded.

`scripts/triage-linux.sh` is therefore **read-only**. It lists what to do; the
human runs the destructive commands deliberately.

---

## References

- [Wiz — Mini Shai-Hulud Strikes Again][wiz]
- [Snyk — TanStack npm Packages Compromised][snyk]
- [Expel — Mini Shai-Hulud cross-ecosystem worm][expel]
- [Arctic Wolf — Mini Shai-Hulud Supply Chain Malware Attack][arctic]
- [Phoenix Security — Mini Shai-Hulud / TeamPCP analysis][phoenix]
- [Picus Security — Mini Shai-Hulud explainer][picus]
- [Elastic — Shai-Hulud Worm 2.0 response][elastic]
- [VentureBeat — six actionable steps][venturebeat]
- [Carthage Electronics — May 2026 crisis brief][carthage]
- [Intrudify — open-source Mini Shai-Hulud scanner][scanner]
- [Borecraft / NewMaxx — CVE-2026-45321 response guide][newmaxx]
- [Datadog Security Labs — Shai-Hulud goes open source][datadog]
- [Orca Security — TanStack worm overview][orca]
- [Guardz — Shai-Hulud strikes again][guardz]
- [Socprime — Shai-Hulud by TeamPCP][socprime]
- [Corgea — TanStack supply-chain analysis][corgea]

[wiz]:        https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
[snyk]:       https://snyk.io/blog/tanstack-npm-packages-compromised/
[expel]:      https://expel.com/blog/mini-shai-hulud-cross-ecosystem-supply-chain-worm-targeting-npm-pypi/
[arctic]:     https://arcticwolf.com/resources/blog/mini-shai-hulud-supply-chain-malware-attack/
[phoenix]:    https://phoenix.security/mini-shai-hulud-teampcp-tanstack/
[picus]:      https://www.picussecurity.com/resource/blog/mini-shai-hulud-the-npm-supply-chain-worm-explained
[elastic]:    https://www.elastic.co/blog/shai-hulud-worm-2-0-updated-response
[venturebeat]:https://venturebeat.com/security/shai-hulud-worm-172-npm-pypi-packages-valid-provenance-ci-cd-audit
[carthage]:   https://carthageelectronics.com/npm-supply-chain-crisis-mini-shai-hulud-may-2026/
[scanner]:    https://github.com/Intrudify/mini-shai-hulud-scanner
[newmaxx]:    https://borecraft.com/news/tanstack-mini-shai-hulud-cve-2026-45321-guide.html
[datadog]:    https://www.hendryadrian.com/shai-hulud-goes-open-source-datadog-security-labs/
[orca]:       https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/
[guardz]:     https://guardz.com/blog/shai-hulud-strikes-again/
[socprime]:   https://socprime.com/active-threats/shai-hulud-here-we-go-again-worm-by-teampcp-hits-npm-and-pypi/
[corgea]:     https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud
