# Communication Templates — Shai-Hulud Response

Audience: **engineering managers, tech leads, incident commanders** who need
to brief stakeholders quickly without leaking sensitive incident detail or
oversimplifying the risk.

Copy, edit the bracketed bits, send. Each template is calibrated to the
audience listed; resist the urge to merge "developers" and "executives" into
one note — they need different decisions from you.

---

## 1. Release-deferral note (to leadership / product / customers)

Use when: a planned release is paused because the dependency tree includes a
package in the Shai-Hulud target list and you need to defend the delay.

> **Subject:** [Product/release name] release deferred pending supply-chain audit
>
> We are deferring the **[release name / version]** release of **[product]**
> by **[N business days / until DATE]** while we complete a supply-chain
> audit triggered by the **Mini Shai-Hulud / Shai-Hulud 2.0** npm
> compromise disclosed between **29 April 2026** and **13 May 2026**
> (CVE-2026-45321 / Snyk GHSA-g7cv-rxg3-hmpx).
>
> **Why this matters:** the compromised npm packages carry **valid SLSA
> provenance attestations**, so normal signature checks pass on them. We
> need to audit our lockfile, build agents, and developer machines
> directly — there is no automated "green checkmark" that proves we're
> clear.
>
> **What we are doing:**
> 1. Running an IOC audit against every repo in the release scope and every
>    CI build agent.
> 2. Checking developer machines that have installed dependencies since
>    29 April 2026 for the worm's persistence hooks.
> 3. Rotating any credentials that were reachable from an affected build
>    agent.
>
> **No customer data is known to be exposed.** This is a precautionary
> hold; we will share an all-clear note once the audit completes.
>
> Detail and IOC references on request.

---

## 2. Engineering-team Slack post (internal)

Use when: kicking off the audit and need every developer to take a single
specific action immediately.

> 🚨 **Action required, all eng:**
>
> Mini Shai-Hulud npm compromise (29 Apr – 13 May 2026). We need everyone
> to run this against their local checkouts **today**:
>
> ```sh
> # Clone the auditor (or `git pull` if you already have it)
> git clone https://github.com/your-org/shai-hulud-auditor.git
> cd shai-hulud-auditor
>
> # Audit your laptop's home dir — includes the machine-persistence check
> node audit.js ~
> ```
>
> If you see **"Persistence hits: 0"** → reply ✅ in this thread.
> If you see **anything else** → **stop**, do not revoke any tokens, and
> DM `@security-on-call`. The worm wipes `$HOME` on token revocation, so
> the order of operations matters.
>
> For background:
> - MACOS.md / LINUX.md in the repo have the OS-specific remediation order.
> - The audit script is read-only — it never modifies anything.
>
> Deadline for ✅ replies: **[time, today]**.

---

## 3. Incident-response status update (to security / SRE leadership)

Use when: providing a structured update during an active investigation.

> **Status:** [Investigating / Containing / Eradicating / Recovering /
> Closed]
> **Incident ID:** [INC-NNN]
> **Date / time of update:** [ISO timestamp]
>
> **Scope confirmed so far:**
> - Affected projects: [N], specifically [list]
> - Affected developer machines: [N] (of [M] inventoried)
> - Affected build agents: [N] (of [M] inventoried)
> - Persistence found: [yes / no]; if yes, location: [path]
> - C2 connectivity observed: [yes / no]; if yes, destination: [domain/IP]
>
> **Containment:**
> - [✓ / ✗] All affected machines disconnected from internal networks
> - [✓ / ✗] gh-token-monitor units disarmed and quarantined
> - [✓ / ✗] Worm artefacts preserved for forensics
> - [✓ / ✗] `audit.js ~` returns "Persistence hits: 0" on all hosts
>
> **Eradication / recovery:**
> - [✓ / ✗] Compromised package.json ranges pinned past IOCs
> - [✓ / ✗] Lockfiles regenerated under `--ignore-scripts`
> - [✓ / ✗] CI build agents rebuilt from immutable image
> - [✓ / ✗] Affected dev machines reimaged
>
> **Credential rotation:**
> - [✓ / ✗] npm publish tokens
> - [✓ / ✗] GitHub PATs, fine-grained tokens, OIDC trusts
> - [✓ / ✗] Cloud provider keys (AWS / GCP / Azure)
> - [✓ / ✗] Third-party service keys reachable from CI env
>   (DocuSign, SendGrid, Slack apps, monitoring, etc.)
> - [✓ / ✗] SSH keys regenerated
>
> **Next checkpoint:** [time / event]
> **Blockers:** [list / none]

---

## 4. Customer disclosure (only if data exposure is suspected)

Use when: forensics suggest a customer-reachable secret was in an affected
build-agent env var. Get legal review before sending. Keep it factual.

> **Subject:** Notice of precautionary credential rotation
>
> Between [date] and [date] our build infrastructure was within scope of
> the publicly disclosed Mini Shai-Hulud npm supply-chain compromise
> (CVE-2026-45321). As a precaution we have:
>
> - Rotated all integration credentials shared with your account, including
>   [list specific keys / OAuth grants].
> - Audited access logs to your systems for the period [date] – [date] and
>   identified [no anomalous activity / the following anomalous activity:
>   ...].
> - [Re-issued / asked you to re-issue] [list].
>
> **Action requested from you (if any):** [specific, time-bound].
>
> Technical contact: [name / email / phone].
>
> We will publish a final post-incident report by [date]. We are happy to
> walk your security team through the timeline on request.

---

## 5. Post-incident retrospective skeleton

Use within 5 business days of incident closure.

> **Mini Shai-Hulud incident retrospective**
> **Closed:** [date]
> **Duration:** discovery → containment [hh:mm]; containment → all-clear [hh:mm]
>
> **What happened**
> - [3–5 bullet timeline]
>
> **What worked**
> - [Controls that limited blast radius]
>
> **What didn't**
> - [Controls that failed or were missing]
>
> **Action items**
> | # | Action | Owner | Due | Status |
> |---|---|---|---|---|
> | 1 | Set `ignore-scripts=true` globally on all CI runners | | | |
> | 2 | Pin all third-party Actions to commit SHAs | | | |
> | 3 | Add `audit.js` as a required CI check on every release branch | | | |
> | 4 | Document credential-rotation runbook with the build-agent-env-var scoping rule | | | |
> | 5 | Schedule weekly triage-{macos,linux}.sh run via [cron / launchd / systemd timer] | | | |
>
> **Lessons / patterns we want to keep**
> - [Things to institutionalise]
>
> **References**
> - MACOS.md / LINUX.md / HARDENING.md in this repo
> - External: Wiz, Snyk GHSA-g7cv-rxg3-hmpx, Carthage May 2026 brief,
>   VentureBeat six-step guide

---

## Editing notes

- Replace square-bracket placeholders before sending. Don't ship a template
  with `[N]` still in it; it tells the reader you didn't think about scope.
- For the customer-disclosure template (§4), **always** route through legal
  / privacy / DPA review before sending. Disclosure timing in some
  jurisdictions is regulated (UK ICO, EU GDPR, US state breach-notification
  laws).
- For the leadership / customer notes (§1, §4), the SLSA-provenance point
  is the single most important sentence — it explains *why* the audit is
  manual and *why* the delay is unavoidable. Don't trim it.
