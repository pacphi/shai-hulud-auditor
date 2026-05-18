# Hardening Guide — Preventing the Next Shai-Hulud Wave

Audience: **platform engineers, SREs, CI/build administrators, security
reviewers.** If you've already cleaned a compromise, read [MACOS.md](MACOS.md)
or [LINUX.md](LINUX.md) first; this guide is what you do *after* the incident
is contained, to stop the next wave from reaching production.

This guide consolidates preventive controls drawn from the May 2026
Mini Shai-Hulud / Shai-Hulud 2.0 response writeups (StepSecurity, Snyk,
Wiz, Carthage, Phoenix Security, Elastic, VentureBeat) and the
Orkastrate pre-release audit checklist.

---

## 1. CI build agents — non-negotiable settings

These are the controls that would have prevented installation of the
Mini Shai-Hulud payload on a CI runner.

### 1a. Globally disable lifecycle scripts on CI

```sh
# As part of the runner image / Dockerfile / cloud-init:
npm  config set ignore-scripts true --location=global
pnpm config set ignore-scripts true   # pnpm 8+
yarn config set enableScripts false   # Yarn Berry
```

**Why:** every observed payload in the Shai-Hulud family executes via
`preinstall` / `postinstall` / `prepare`. Setting `ignore-scripts=true` at
the agent level neutralises that vector for every build, even when a
compromised version is pulled. Apps that genuinely need a postinstall step
(node-gyp builds, esbuild platform binaries) should run those as **explicit
build steps** in the pipeline, not as install-time side effects.

### 1b. Use `npm ci` (or `pnpm install --frozen-lockfile`), never `npm install`

`npm install` rewrites the lockfile and accepts any version inside a caret
range. `npm ci` refuses to run unless the lockfile is consistent and only
installs the exact versions pinned there.

```yaml
- run: npm ci --ignore-scripts        # belt-and-suspenders even with 1a
- run: pnpm install --frozen-lockfile --ignore-scripts
```

### 1c. Pin third-party GitHub Actions to commit SHAs, not floating tags

```yaml
# Bad — `v4` resolves whatever the action publisher last pushed.
- uses: actions/checkout@v4

# Good — locked to an audited revision.
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

The Mini Shai-Hulud campaign relied on an attacker pivoting from an OIDC
token in a CI runner. Pinned action SHAs limit which actions can run, so a
hijacked tag does not silently update your pipeline.

### 1d. Restrict GitHub Actions `permissions` to the minimum

```yaml
permissions:
  contents: read
  id-token: write    # only on jobs that genuinely need OIDC federation
```

Any job that does *not* need to publish, push, or federate OIDC should drop
those scopes. The default `permissions: write-all` is the worst case.

### 1e. Scope OIDC trust policies tightly

In AWS / GCP / Azure trust conditions, require not just the repo but also
the branch, environment, and (where possible) the workflow file path:

```hcl
# AWS example — trust only main-branch deploys from a specific workflow.
"sub" = "repo:your-org/your-repo:ref:refs/heads/main:workflow:deploy.yml"
```

The TanStack compromise pivoted on an orphaned OIDC trust still configured
on an old branch.

### 1f. Network egress controls on runners

Most CI runners need outbound HTTPS to package registries and the cloud
provider, and nothing else. Block everything else at the runner network
boundary:

- Allowlist `registry.npmjs.org`, `registry.yarnpkg.com`,
  `npm.pkg.github.com`, your cloud's package mirror, and your artifact
  store.
- Block known Shai-Hulud C2 domains as a tripwire:
  `git-tanstack.com`, `*.getsession.org`, `83.142.209.194`.
  ([Wiz][wiz])

If an outbound connection to those domains ever fires, your monitoring
should page on it — that's a high-fidelity signal that something on the
runner is trying to talk to the worm's C2.

---

## 2. Lockfile and dependency discipline

### 2a. Pin direct dependencies to exact versions for production-bound packages

```json
{
  "dependencies": {
    "@tanstack/react-router": "1.170.4",
    "react": "19.2.6"
  }
}
```

`^1.170.4` was sufficient to dodge the May 11 wave once 1.169.x was
published, but exact pins are the only way to make `npm ci` deterministic
against *future* compromises that may target patches you'd otherwise float
into.

Transitive deps stay pinned via the lockfile — you don't need to flatten
the whole tree.

### 2b. Commit the lockfile. Always.

`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` must be in version
control on every branch that builds. Without it, `npm ci` can't run and
you've lost the determinism `--frozen-lockfile` was supposed to give you.

### 2c. Treat `.npmrc` as code

Production `.npmrc` should be checked in (without tokens) and contain:

```ini
ignore-scripts=true
audit-level=high
fund=false
```

Token-bearing `.npmrc` files belong only in build-agent secret stores, not
in developer dotfiles. Audit `~/.npmrc` for stale tokens periodically.

---

## 3. Continuous monitoring

### 3a. Scope Dependabot / Renovate to the riskiest namespaces

Enable supply-chain alerting on **every namespace you depend on directly**,
but prioritise the ones the Shai-Hulud family has demonstrably targeted:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "daily" }
    allow:
      - dependency-name: "@tanstack/*"
      - dependency-name: "@mistralai/*"
      - dependency-name: "@uipath/*"
      - dependency-name: "@opensearch-project/*"
```

Renovate equivalent: a `packageRules` block matching those scopes with
`prCreation: "immediate"`.

### 3b. Run the auditor in CI

```yaml
- name: Mini Shai-Hulud audit
  run: node tools/shai-hulud-auditor/audit.js .
```

Exit code 1 fails the pipeline the instant a known-bad version appears in
your lockfile. Keep `audit.js` updated when StepSecurity / Snyk publish new
IOCs (the `COMPROMISED` map at the top of the file).

### 3c. Subscribe to authoritative IOC feeds

- **Snyk** advisory `GHSA-g7cv-rxg3-hmpx` + Snyk Disclosed mailing list
- **StepSecurity** blog (first responders for the original 29 April wave)
- **Microsoft Security Response Center** advisories
- **Unit 42** Palo Alto threat intel
- **Socket** weekly newsletter

When any of these announce a new wave, regenerate the `COMPROMISED` map and
run `audit.js` across your fleet within the same business day.

### 3d. Audit-log review cadence

Build a recurring weekly check (calendar reminder, runbook, or scheduled
Action) to review:

- GitHub **org audit log** for unexpected workflow runs, especially any job
  that touches `id-token: write` or publishes to a registry.
- **npm publish events** (`npm whoami`, `npm token list`) on any account
  with publish rights.
- Cloud audit trails (CloudTrail / Cloud Audit Logs / Azure Activity) for
  unexpected `AssumeRoleWithWebIdentity` events.

---

## 4. Developer workstation baseline

Even with hardened CI, an infected laptop can re-poison the team. Apply
these baselines to every dev machine:

- `npm config set ignore-scripts true` — at user scope. Run `npm rebuild`
  when you genuinely need native module builds.
- Editor extensions: audit `~/.vscode/extensions/`, `~/.cursor/extensions/`,
  and Claude Code's `~/.claude/` directory after every major update; the
  worm targets these as long-lived persistence locations.
- Browser keychain / OS keychain: never store npm or GitHub tokens in
  shell rc files. Use `1Password CLI` or `gh auth` so secrets live in an
  OS-protected store, not in plaintext `~/.npmrc` / `~/.netrc`.
- Run [scripts/triage-macos.sh](scripts/triage-macos.sh) or
  [scripts/triage-linux.sh](scripts/triage-linux.sh) weekly as a cron job
  / launchd plist. Both are read-only and exit 0 when clean.

---

## 5. Release process checklist

Before any production release whose dependency tree includes a package in
the Shai-Hulud target list (TanStack, Mistral, UiPath, OpenSearch, and
others — see `audit.js` IOC map):

- [ ] `node audit.js .` passes with exit 0.
- [ ] Lockfile has been regenerated *after* `package.json` pins were
      tightened to exact versions.
- [ ] CI workflow uses `npm ci --ignore-scripts` (or pnpm equivalent).
- [ ] All third-party Actions are pinned to commit SHAs.
- [ ] No `permissions: write-all`. `id-token: write` only on jobs that need it.
- [ ] Build-agent OS image fingerprint hasn't drifted since last clean state.
- [ ] GitHub org audit log shows no unexpected workflow runs in the last
      reporting window (default: 7 days; widen to 29 April 2026 → now for
      this specific incident).
- [ ] Outbound traffic from build agents to `git-tanstack.com` and
      `*.getsession.org` is **DROP**, monitored, and paging.

If any item is unchecked, **defer the release** rather than working around
it. See [TEMPLATES.md](TEMPLATES.md) for stakeholder communication patterns.

---

## References

- [Wiz — Mini Shai-Hulud Strikes Again][wiz]
- [Snyk — TanStack npm Packages Compromised (GHSA-g7cv-rxg3-hmpx)][snyk]
- [StepSecurity — supply-chain attack response][stepsec]
- [VentureBeat — six actionable steps][venturebeat]
- [Carthage Electronics — May 2026 crisis brief][carthage]
- [Phoenix Security — TeamPCP analysis][phoenix]
- [Elastic — Shai-Hulud Worm 2.0 response][elastic]
- [Microsoft Security — supply-chain advisories (search)][msrc]
- [Unit 42 — Palo Alto threat intel][unit42]
- [Socket — npm/PyPI supply-chain intel feed][socket]

[wiz]:        https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
[snyk]:       https://snyk.io/blog/tanstack-npm-packages-compromised/
[stepsec]:    https://www.stepsecurity.io/blog
[venturebeat]:https://venturebeat.com/security/shai-hulud-worm-172-npm-pypi-packages-valid-provenance-ci-cd-audit
[carthage]:   https://carthageelectronics.com/npm-supply-chain-crisis-mini-shai-hulud-may-2026/
[phoenix]:    https://phoenix.security/mini-shai-hulud-teampcp-tanstack/
[elastic]:    https://www.elastic.co/blog/shai-hulud-worm-2-0-updated-response
[msrc]:       https://msrc.microsoft.com/blog/
[unit42]:     https://unit42.paloaltonetworks.com/
[socket]:     https://socket.dev/blog
