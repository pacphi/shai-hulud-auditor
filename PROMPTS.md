# PROMPTS — Reusable Prompts for AI-Assisted Shai-Hulud Triage

Copy-pasteable prompts you can hand to a code-aware AI assistant (Claude
Code, Cursor, Aider, Copilot Workspace, etc.) to drive the same checks
this repo's docs walk through. Each prompt is self-contained — paste it,
replace the bracketed placeholders, and let the assistant work.

These prompts assume the assistant has shell access and can read files in
your working directory. If you're driving a chat-only assistant, drop the
prompt into a session where you can paste back command output by hand.

## Conventions

- `<…>` = placeholder you replace before sending.
- Prompts deliberately reference the auditor's own files (`audit.js`,
  `scripts/triage-*.sh`, `MACOS.md`, etc.) so the assistant has authoritative
  context.
- Prompts use **plain instructions, no agentic flourishes**. They work the
  same whether your assistant has 1 tool or 50.
- The **watchdog warning** appears in every prompt that touches credentials
  or persistence. Don't strip it.

---

## 1. Audit a single repo / workspace

> I want to check `<absolute-path-to-repo>` for compromise by the Mini
> Shai-Hulud / Shai-Hulud 2.0 npm worm (CVE-2026-45321, Snyk
> GHSA-g7cv-rxg3-hmpx, active 29 April – 13 May 2026). The auditor lives
> at `<absolute-path-to-shai-hulud-auditor>/audit.js` (zero-dependency Node
> script).
>
> Please:
> 1. Run `node <path>/audit.js <repo-path>` and report the exit code plus
>    the full Summary block.
> 2. If `Compromised projects > 0`, list each compromised path and the
>    flagged packages with their declared ranges and the IOC versions.
> 3. If `Informational notes > 0`, explain that those are "name in IOC list
>    but declared range cannot reach a compromised version" — they're safe.
> 4. Do **not** delete `node_modules`, regenerate any lockfile, or run any
>    install commands. I will decide remediation in a follow-up.
>
> Reply in under 300 words.

---

## 2. Triage the host for persistence (macOS or Linux)

> Run the read-only persistence triage script for my OS and report what
> was found:
>
> ```sh
> # macOS
> bash <path>/shai-hulud-auditor/scripts/triage-macos.sh
> # Linux
> bash <path>/shai-hulud-auditor/scripts/triage-linux.sh
> ```
>
> If the script exits 0 with "No persistence IOCs detected", confirm that
> in one sentence.
>
> If anything is FOUND:
> - List each artefact with its absolute path.
> - **STOP. Do not delete anything, do not stop any systemd unit /
>   LaunchAgent, and do not revoke any credentials.** The Mini Shai-Hulud
>   worm watchdog wipes `$HOME` when it detects token revocation.
> - Print the exact next-step commands from `MACOS.md §1d` (macOS) or
>   `LINUX.md §1d` (Linux) for me to run manually after I've taken a
>   filesystem snapshot.
>
> Reply in under 200 words.

---

## 3. Pin compromised packages past the IOCs and refresh the lockfile

> The auditor flagged `<repo-path>` for the following packages and IOC
> versions:
>
> ```
> <paste the package-json: lines from `audit.js` output>
> ```
>
> Please:
> 1. For each flagged package, find the **latest stable** version on npm
>    that is above all IOC versions. Use `npm view <pkg> dist-tags` and
>    `npm view <pkg> time --json | tail -20`.
> 2. Show me the proposed package.json diff (caret-pinned to the new
>    version) **before** editing anything.
> 3. Once I approve, edit the package.json, then:
>    ```sh
>    rm -rf node_modules .next .turbo dist build .cache
>    rm -f package-lock.json pnpm-lock.yaml yarn.lock
>    <pnpm|npm|yarn> install --ignore-scripts
>    ```
>    Use `--ignore-scripts` for the first install so postinstall payloads
>    can't execute even by accident.
> 4. Re-run `node <path>/audit.js <repo-path>` and confirm
>    `Compromised projects: 0`.
>
> Reply with the proposed package.json diff first. Don't run any
> destructive commands until I say "go".

---

## 4. Audit GitHub workflows for OIDC / secrets exposure

> For each repo in `<list-of-repo-paths>`, check whether the GitHub Actions
> workflows could have leaked secrets or OIDC tokens during the Mini
> Shai-Hulud exposure window (29 April – 13 May 2026). Specifically:
>
> 1. List every workflow file under `.github/workflows/`.
> 2. For each workflow, extract:
>    - top-level and job-level `permissions:` blocks
>    - any `id-token: write` declaration (= OIDC federation in use)
>    - every `secrets.*` reference
>    - every `uses:` line (third-party actions — note if pinned to a SHA
>      vs floating tag like `@v4`)
>    - the install command (`npm ci`, `npm install`, `pnpm install`,
>      `pnpm install --frozen-lockfile`, `yarn install`)
> 3. Summarise risk per repo:
>    - **id-token: write** present → cloud OIDC tokens could be minted →
>      audit AWS / GCP / Azure trust policies.
>    - **non-`GITHUB_TOKEN` secrets referenced** → identify which secrets
>      were exposed to which job; assume in-scope for rotation if any
>      compromised version of a worm-targeted package could have run a
>      preinstall/postinstall hook.
>    - **Floating-tag actions** (`@v4`, `@main`) → hardening gap; recommend
>      SHA pinning.
>    - **Plain `pnpm install` / `npm install`** (no `--frozen-lockfile` /
>      `npm ci`) → could resolve newer compromised versions during a CI run.
>
> Do not modify any files. Output a table per repo. Cite line numbers.

---

## 5. Check GitHub run history in the exposure window

> Using the `gh` CLI (already authenticated), pull the workflow run history
> for `<owner>/<repo>` between **2026-04-29** and **2026-05-13** and
> highlight runs that could have installed compromised packages.
>
> 1. Run:
>    ```sh
>    gh run list --repo <owner>/<repo> \
>      --created 2026-04-29..2026-05-13 --limit 100 \
>      --json databaseId,workflowName,event,conclusion,createdAt,headBranch
>    ```
> 2. Filter for runs whose workflow does `npm install` / `pnpm install`
>    (not `--frozen-lockfile`). Cross-reference against the workflow audit
>    from prompt 4.
> 3. For any Dependabot or manual PR that touched a worm-targeted package
>    name (any `@tanstack/*` route/router/start package, `@mistralai/*`,
>    `@uipath/*`, `@opensearch-project/*` — see `audit.js` COMPROMISED map
>    for the full list), check whether the resulting lockfile commit
>    introduced one of the IOC versions:
>    ```sh
>    cd <repo>
>    git log --all --oneline -p -- <lockfile-path> \
>      | grep -oE "@tanstack/react-router@1\.16[789]\.[0-9]+" | sort -u
>    ```
> 4. Cross-check: also confirm the lockfile **never** contained the IOC
>    versions listed in `audit.js` for that package name.
>
> Report which runs (if any) could have executed worm code at install
> time, distinguishing "lockfile drifted to a bad version" from "lockfile
> stayed safe".

---

## 6. Lockfile-history forensics on a remediated repo

> I just bumped dependencies in `<repo-path>` to remediate Mini Shai-Hulud.
> Before I commit, prove the worm never ran in this repo's history.
>
> 1. Run:
>    ```sh
>    cd <repo-path>
>    git log --all --oneline -p -- <lockfile-path> 2>/dev/null \
>      | grep -oE "@tanstack/react-router@1\.[0-9]+\.[0-9]+" | sort -u
>    ```
>    Repeat for each worm-targeted name in `audit.js`'s COMPROMISED map
>    that appears anywhere in this repo's package.json files.
> 2. Compare the resolved versions ever pinned in the lockfile against the
>    IOC version list. Output a table:
>
>    | Package | IOC versions | Versions ever in lockfile | Intersect? |
>
> 3. If any row's "Intersect?" is yes, that's a real install that
>    happened — flag it, identify the commit, and recommend that I:
>    a) Treat the developer machine that produced that commit as
>       potentially compromised (run `triage-{macos,linux}.sh` on it).
>    b) Treat any CI run from that commit as in-scope for credential
>       rotation per the build-agent env-var scoping rule.
> 4. If no row intersects, confirm the repo is historically clean.

---

## 7. GitHub repo secret / variable inventory

> Using the `gh` CLI (already authenticated), inventory the secret and
> variable surface for `<owner>/<repo>`:
>
> ```sh
> gh secret list   --repo <owner>/<repo>
> gh variable list --repo <owner>/<repo>
> gh api -X GET repos/<owner>/<repo>/actions/secrets       --jq '.secrets[].name'        # belt-and-suspenders
> gh api -X GET repos/<owner>/<repo>/environments          --jq '.environments[].name'   # env-scoped secrets
> ```
>
> For each environment listed, also pull its secrets and variables:
>
> ```sh
> gh api -X GET repos/<owner>/<repo>/environments/<env>/secrets   --jq '.secrets[].name'
> gh api -X GET repos/<owner>/<repo>/environments/<env>/variables --jq '.variables[].name'
> ```
>
> Cross-reference the inventory against the `secrets.*` references in the
> workflow files (from prompt 4). Output:
> - **Used and configured** — likely in scope for rotation if any run
>   in the exposure window could have executed worm code.
> - **Configured but unused** — should be deleted.
> - **Referenced but not configured** — workflow bug; flag separately.
>
> Do not print any secret values, only names. (`gh secret list` doesn't
> reveal values anyway, but be explicit about it.)

---

## 8. Pre-commit safety check before pushing remediations

> I'm about to commit and push dependency-pin updates that remediate Mini
> Shai-Hulud findings in `<repo-path>`. Run these final checks:
>
> 1. `git status` and `git diff --stat` — confirm only the expected files
>    changed (package.json, lockfile, optionally `.github/workflows/*.yml`
>    for `--frozen-lockfile` hardening).
> 2. `git diff` — flag any unexpected modifications (e.g. accidental
>    changes to source files, CI workflows beyond `--frozen-lockfile`,
>    `.env*` files, secrets).
> 3. Re-run `node <path>/audit.js <repo-path>` and confirm exit 0 with
>    `Compromised projects: 0`.
> 4. Re-run `bash <path>/scripts/triage-<os>.sh` on the host and confirm
>    no persistence IOCs.
> 5. List any other modified or untracked files **outside** the repo so I
>    can decide whether they belong in this commit or a different one.
>
> If any of 1–4 fail, **STOP and report** rather than proceeding. Only
> proceed to suggest a commit message if everything is green.

---

## 9. Build a CI hardening PR

> Based on `HARDENING.md` in this repo, draft a single PR against
> `<owner>/<repo>` that applies the highest-leverage CI controls. The PR
> should:
>
> 1. Change every `npm install` → `npm ci --ignore-scripts`, every
>    `pnpm install` → `pnpm install --frozen-lockfile`.
> 2. Add `permissions:` blocks scoped to the minimum each job needs
>    (`contents: read` by default; `id-token: write` only on jobs that
>    genuinely federate to a cloud).
> 3. Pin every third-party action in `uses:` lines to a commit SHA, with
>    a comment indicating the previously-floating tag (e.g.
>    `# was @v6`). Use `gh api /repos/<owner>/<action-repo>/commits/<tag>`
>    to resolve tags to SHAs.
> 4. (Optional) Add a job that runs `node tools/shai-hulud-auditor/audit.js .`
>    on every PR.
>
> Before writing the PR, list the proposed diff for me to approve.

---

## 10. Stakeholder comms drafting

> A repo I work on has compromised dependency pins (Mini Shai-Hulud).
> Using `TEMPLATES.md` as a starting point, draft me:
>
> a) A **3-sentence Slack post** for the eng team telling them what to
>    run and what to reply with — based on TEMPLATES.md §2.
> b) A **release-deferral note** for leadership explaining the delay
>    without alarming anyone — based on TEMPLATES.md §1.
> c) A **single-paragraph status update** for the security IR channel
>    summarising scope as I currently understand it — based on
>    TEMPLATES.md §3.
>
> Fill in placeholders with the following:
> - Repos affected: `<list>`
> - Window I'm running CI installs in: `<dates>`
> - Persistence hits on dev machines: `<count>`
> - Custom GitHub secrets configured: `<count>`
>
> Don't editorialise. Match the templates' tone exactly.

---

## 11. Post-incident retrospective

> Using `TEMPLATES.md §5` as the structure, draft a retrospective for our
> Mini Shai-Hulud response. Use the conversation history / git log in this
> session to fill in the timeline. Surface:
>
> 1. **What worked** — controls that limited blast radius (e.g.
>    `--frozen-lockfile` keeping the lockfile pinned; Dependabot's vuln
>    DB suppressing compromised versions; the auditor catching at-risk
>    ranges before install).
> 2. **What didn't** — controls that were missing or only partial (e.g.
>    floating-tag actions; CI installs without `--frozen-lockfile`;
>    optional dependency caret ranges floating into IOC versions).
> 3. **Action items** — at least 5 concrete items with owner placeholders.
>    Cross-reference HARDENING.md §1–§5.
>
> Don't include any incident-specific details that I haven't pasted into
> this thread. If a field is unknown, leave a `<TBD: ...>` placeholder.

---

## 12. Re-audit on a schedule

> Set up a recurring local check that runs the auditor and triage script
> every Monday morning, surfaces a notification if anything turns red, and
> logs results to `~/.shai-hulud-audit/log/`.
>
> macOS: write a LaunchAgent plist at
> `~/Library/LaunchAgents/local.shai-hulud-weekly.plist`.
> Linux: write a systemd user timer at
> `~/.config/systemd/user/shai-hulud-weekly.{service,timer}`.
>
> Both should:
> 1. Run `node <path>/audit.js ~ > ~/.shai-hulud-audit/log/$(date +%F).log`.
> 2. Run `bash <path>/scripts/triage-<os>.sh >> ~/.shai-hulud-audit/log/$(date +%F).log`.
> 3. Use `osascript -e 'display notification ...'` (macOS) or `notify-send`
>    (Linux) on non-zero exit.
> 4. Rotate logs older than 90 days.
>
> Print the plist / unit files; do not install them. I'll review before
> enabling.

---

## How to use these effectively

- **Sequence:** if you're starting cold on a possibly-affected machine,
  run **prompts 1 + 2** first. If both come back clean, you're done. If
  either is red, follow the prompt's "stop" guidance before doing
  anything else.
- **Don't merge prompts.** Each one is calibrated to do one thing. If you
  paste two at once your assistant will skim and miss the watchdog
  warning.
- **Diff before destructive actions.** Prompts 3, 8, 9, 10 explicitly ask
  the assistant to show you the diff before running anything. Keep that
  discipline — it's a hard lesson learned from the watchdog mechanic.
- **Replay-friendly.** All prompts are idempotent except 3 (mutates
  package.json + lockfile) and 9 (drafts a PR). The rest you can run
  daily without consequence.

## Maintenance

When npm/PyPI publish new IOCs:

1. Update the `COMPROMISED` map at the top of `audit.js`.
2. Re-run **prompts 1 + 6** across your fleet.
3. If anything new turns up, run **prompts 4 + 5 + 7** for the affected
   repos and the new exposure window.
4. Update the exposure window dates referenced in prompts 1, 5, 6 to
   the new wave's publication window before re-using them.
