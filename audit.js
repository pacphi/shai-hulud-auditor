#!/usr/bin/env node
/**
 * Mini Shai-Hulud Audit Script
 *
 * Scans one or more npm/pnpm projects for indicators of compromise (IOCs)
 * related to the Mini Shai-Hulud / Shai-Hulud 2.0 supply-chain attacks
 * (Apr-May 2026).
 *
 * Usage:
 *   node audit.js [path-or-git-url]
 *
 * The target may be:
 *   - a single project directory (contains package.json / lockfile),
 *   - a directory containing many repos ("repo of repos"), or
 *   - a git URL (https://, git@, ssh://, git://) — the repo will be
 *     shallow-cloned into a temp dir, scanned, and removed.
 * The scanner walks recursively, skipping node_modules, .git, and common
 * build output directories, and audits every project it finds.
 *
 * Exit codes:
 *   0 = clean
 *   1 = matches found (requires investigation)
 *   2 = script error
 *
 * IMPORTANT: If matches are found, DO NOT immediately revoke npm tokens or
 * delete files. Image the affected machine first. The malware contains
 * a token-monitor watchdog that triggers a home-directory wipe when it
 * detects token revocation.
 *
 * ----------------------------------------------------------------------
 * File layout (top-to-bottom):
 *   1. IOC data           — compromised package@version list, persistence paths
 *   2. Audit primitives   — pure predicates over (name, version)
 *   3. Lockfile parsers   — extract installed packages from lockfiles
 *   4. Project auditor    — runs all checks against one project directory
 *   5. Discovery          — recursively find project directories
 *   6. Reporting / main   — CLI entry, per-project + global summary
 * ----------------------------------------------------------------------
 */

'use strict';

const fs           = require('fs');
const path         = require('path');
const os           = require('os');
const { spawnSync } = require('child_process');

// ==========================================================================
// 1. IOC DATA
// ==========================================================================

// Compromised package@version list.
// Source: StepSecurity, Snyk, Mend.io, OX Security, Socket (May 2026).
// Covers Mini Shai-Hulud waves of 29 April and 11 May 2026.
const COMPROMISED = {
  // TanStack
  '@tanstack/router-utils':                    ['1.161.11', '1.161.14'],
  '@tanstack/router-core':                     ['1.169.5', '1.169.8'],
  '@tanstack/react-router':                    ['1.169.5', '1.169.8'],
  '@tanstack/react-router-devtools':           ['1.166.16', '1.166.19'],
  '@tanstack/react-router-ssr-query':          ['1.166.15', '1.166.18'],
  '@tanstack/react-start':                     ['1.167.68', '1.167.71'],
  '@tanstack/react-start-client':              ['1.166.51', '1.166.54'],
  '@tanstack/react-start-rsc':                 ['0.0.47', '0.0.50'],
  '@tanstack/react-start-server':              ['1.166.55', '1.166.58'],
  '@tanstack/arktype-adapter':                 ['1.166.12', '1.166.15'],
  '@tanstack/eslint-plugin-router':            ['1.161.9', '1.161.12'],
  '@tanstack/eslint-plugin-start':             ['0.0.4', '0.0.7'],
  '@tanstack/history':                         ['1.161.9', '1.161.12'],
  '@tanstack/nitro-v2-vite-plugin':            ['1.154.12', '1.154.15'],
  '@tanstack/router-cli':                      ['1.166.46', '1.166.49'],
  '@tanstack/router-devtools':                 ['1.166.16', '1.166.19'],
  '@tanstack/router-devtools-core':            ['1.167.6', '1.167.9'],
  '@tanstack/router-generator':                ['1.166.45', '1.166.48'],
  '@tanstack/router-plugin':                   ['1.167.38', '1.167.41'],
  '@tanstack/router-ssr-query-core':           ['1.168.3', '1.168.6'],
  '@tanstack/router-vite-plugin':              ['1.166.53', '1.166.56'],
  '@tanstack/solid-router':                    ['1.169.5', '1.169.8'],
  '@tanstack/solid-router-devtools':           ['1.166.16', '1.166.19'],
  '@tanstack/solid-router-ssr-query':          ['1.166.15', '1.166.18'],
  '@tanstack/solid-start':                     ['1.167.65', '1.167.68'],
  '@tanstack/solid-start-client':              ['1.166.50', '1.166.53'],
  '@tanstack/solid-start-server':              ['1.166.54', '1.166.57'],
  '@tanstack/start-client-core':               ['1.168.5', '1.168.8'],
  '@tanstack/start-fn-stubs':                  ['1.161.9', '1.161.12'],
  '@tanstack/start-plugin-core':               ['1.169.23', '1.169.26'],
  '@tanstack/start-server-core':               ['1.167.33', '1.167.36'],
  '@tanstack/start-static-server-functions':   ['1.166.44', '1.166.47'],
  '@tanstack/start-storage-context':           ['1.166.38', '1.166.41'],
  '@tanstack/valibot-adapter':                 ['1.166.12', '1.166.15'],
  '@tanstack/virtual-file-routes':             ['1.161.10', '1.161.13'],
  '@tanstack/vue-router':                      ['1.169.5', '1.169.8'],
  '@tanstack/vue-router-devtools':             ['1.166.16', '1.166.19'],
  '@tanstack/vue-router-ssr-query':            ['1.166.15', '1.166.18'],
  '@tanstack/vue-start':                       ['1.167.61', '1.167.64'],
  '@tanstack/vue-start-client':                ['1.166.46', '1.166.49'],
  '@tanstack/vue-start-server':                ['1.166.50', '1.166.53'],
  '@tanstack/zod-adapter':                     ['1.166.12', '1.166.15'],

  // Mistral AI
  '@mistralai/mistralai':         ['2.2.3', '2.2.4'],
  '@mistralai/mistralai-azure':   ['1.7.2', '1.7.3'],
  '@mistralai/mistralai-gcp':     ['1.7.2', '1.7.3'],

  // OpenSearch
  '@opensearch-project/opensearch': ['3.6.2'],

  // UiPath (subset of large list)
  '@uipath/docsai-tool':                              ['1.0.1'],
  '@uipath/packager-tool-apiworkflow':                ['0.0.19'],
  '@uipath/packager-tool-workflowcompiler-browser':   ['0.0.34'],
  '@uipath/packager-tool-functions':                  ['0.1.1'],
  '@uipath/agent.sdk':                                ['0.0.18'],
  '@uipath/agent-sdk':                                ['1.0.2'],
  '@uipath/agent-tool':                               ['1.0.1'],
  '@uipath/filesystem':                               ['1.0.1'],
  '@uipath/admin-tool':                               ['0.1.1'],
  '@uipath/llmgw-tool':                               ['1.0.1'],
  '@uipath/access-policy-sdk':                        ['0.3.1'],
  '@uipath/access-policy-tool':                       ['0.3.1'],
  '@uipath/aops-policy-tool':                         ['0.3.1'],
  '@uipath/ap-chat':                                  ['1.5.7'],
  '@uipath/api-workflow-tool':                        ['1.0.1'],
  '@uipath/apollo-core':                              ['5.9.2'],
  '@uipath/apollo-react':                             ['4.24.5'],
  '@uipath/apollo-wind':                              ['2.16.2'],
  '@uipath/auth':                                     ['1.0.1'],
  '@uipath/case-tool':                                ['1.0.1'],
  '@uipath/cli':                                      ['1.0.1'],
  '@uipath/codedagent-tool':                          ['1.0.1'],
  '@uipath/codedagents-tool':                         ['0.1.12'],
  '@uipath/codedapp-tool':                            ['1.0.1'],
  '@uipath/common':                                   ['1.0.1'],
  '@uipath/context-grounding-tool':                   ['0.1.1'],
  '@uipath/data-fabric-tool':                         ['1.0.2'],
  '@uipath/flow-tool':                                ['1.0.2'],
  '@uipath/functions-tool':                           ['1.0.1'],
  '@uipath/gov-tool':                                 ['0.3.1'],
  '@uipath/identity-tool':                            ['0.1.1'],
  '@uipath/insights-sdk':                             ['1.0.1'],
  '@uipath/insights-tool':                            ['1.0.1'],
  '@uipath/integrationservice-sdk':                   ['1.0.2'],
  '@uipath/integrationservice-tool':                  ['1.0.2'],
  '@uipath/maestro-sdk':                              ['1.0.1'],
  '@uipath/maestro-tool':                             ['1.0.1'],
  '@uipath/orchestrator-tool':                        ['1.0.1'],
  '@uipath/packager-tool-bpmn':                       ['0.0.9'],
  '@uipath/packager-tool-case':                       ['0.0.9'],
  '@uipath/packager-tool-connector':                  ['0.0.19'],
  '@uipath/packager-tool-flow':                       ['0.0.19'],
  '@uipath/packager-tool-webapp':                     ['1.0.6'],
  '@uipath/packager-tool-workflowcompiler':           ['0.0.16'],
  '@uipath/platform-tool':                            ['1.0.1'],
  '@uipath/project-packager':                         ['1.1.16'],
  '@uipath/resource-tool':                            ['1.0.1'],
  '@uipath/resourcecatalog-tool':                     ['0.1.1'],
  '@uipath/resources-tool':                           ['0.1.11'],
  '@uipath/robot':                                    ['1.3.4'],
  '@uipath/rpa-legacy-tool':                          ['1.0.1'],
  '@uipath/rpa-tool':                                 ['0.9.5'],
  '@uipath/solution-packager':                        ['0.0.35'],
  '@uipath/solution-tool':                            ['1.0.1'],
  '@uipath/solutionpackager-sdk':                     ['1.0.11'],
  '@uipath/solutionpackager-tool-core':               ['0.0.34'],
  '@uipath/tasks-tool':                               ['1.0.1'],
  '@uipath/telemetry':                                ['0.0.7'],
  '@uipath/test-manager-tool':                        ['1.0.2'],
  '@uipath/tool-workflowcompiler':                    ['0.0.12'],
  '@uipath/traces-tool':                              ['1.0.1'],
  '@uipath/ui-widgets-multi-file-upload':             ['1.0.1'],
  '@uipath/uipath-python-bridge':                     ['1.0.1'],
  '@uipath/vertical-solutions-tool':                  ['1.0.1'],
  '@uipath/vss':                                      ['0.1.6'],
  '@uipath/widget.sdk':                               ['1.2.3'],

  // DraftLab
  '@draftauth/client':       ['0.2.1', '0.2.2'],
  '@draftauth/core':         ['0.13.1', '0.13.2'],
  '@draftlab/auth':          ['0.24.1', '0.24.2'],
  '@draftlab/auth-router':   ['0.5.1', '0.5.2'],
  '@draftlab/db':            ['0.16.1', '0.16.2'],

  // Squawk (aviation)
  '@squawk/airways':            ['0.4.2', '0.4.3', '0.4.5'],
  '@squawk/airport-data':       ['0.7.4', '0.7.5', '0.7.7'],
  '@squawk/airports':           ['0.6.2', '0.6.3', '0.6.5'],
  '@squawk/airspace':           ['0.8.1', '0.8.2', '0.8.4'],
  '@squawk/airspace-data':      ['0.5.3', '0.5.4', '0.5.6'],
  '@squawk/airway-data':        ['0.5.4', '0.5.5', '0.5.7'],
  '@squawk/fix-data':           ['0.6.4', '0.6.5', '0.6.7'],
  '@squawk/fixes':              ['0.3.2', '0.3.3', '0.3.5'],
  '@squawk/flight-math':        ['0.5.4', '0.5.5', '0.5.7'],
  '@squawk/flightplan':         ['0.5.2', '0.5.3', '0.5.5'],
  '@squawk/geo':                ['0.4.4', '0.4.5', '0.4.7'],
  '@squawk/icao-registry':      ['0.5.2', '0.5.3', '0.5.5'],
  '@squawk/icao-registry-data': ['0.8.4', '0.8.5', '0.8.7'],
  '@squawk/mcp':                ['0.9.1', '0.9.2', '0.9.4'],
  '@squawk/navaid-data':        ['0.6.4', '0.6.5', '0.6.7'],
  '@squawk/navaids':            ['0.4.2', '0.4.3', '0.4.5'],
  '@squawk/notams':             ['0.3.6', '0.3.7', '0.3.9'],
  '@squawk/procedure-data':     ['0.7.3', '0.7.4', '0.7.6'],
  '@squawk/procedures':         ['0.5.2', '0.5.3', '0.5.5'],
  '@squawk/types':              ['0.8.1', '0.8.2', '0.8.4'],
  '@squawk/units':              ['0.4.3', '0.4.4', '0.4.6'],
  '@squawk/weather':            ['0.5.6', '0.5.7', '0.5.9'],

  // TallyUI
  '@tallyui/components':            ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/connector-medusa':      ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/connector-shopify':     ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/connector-vendure':     ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/connector-woocommerce': ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/core':                  ['0.2.1', '0.2.2', '0.2.3'],
  '@tallyui/database':              ['1.0.1', '1.0.2', '1.0.3'],
  '@tallyui/pos':                   ['0.1.1', '0.1.2', '0.1.3'],
  '@tallyui/storage-sqlite':        ['0.2.1', '0.2.2', '0.2.3'],
  '@tallyui/theme':                 ['0.2.1', '0.2.2', '0.2.3'],

  // Mesa
  '@mesadev/rest':    ['0.28.3'],
  '@mesadev/saguaro': ['0.4.22'],
  '@mesadev/sdk':     ['0.28.3'],

  // Misc
  '@taskflow-corp/cli':     ['0.1.24', '0.1.25', '0.1.26', '0.1.27', '0.1.28', '0.1.29'],
  '@tolka/cli':             ['1.0.2', '1.0.3', '1.0.4', '1.0.6'],
  '@supersurkhet/cli':      ['0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.0.7'],
  '@supersurkhet/sdk':      ['0.0.2', '0.0.3', '0.0.4', '0.0.5', '0.0.6', '0.0.7'],
  '@beproduct/nestjs-auth': ['0.1.2', '0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7', '0.1.8',
                             '0.1.9', '0.1.10', '0.1.11', '0.1.12', '0.1.13', '0.1.14',
                             '0.1.15', '0.1.16', '0.1.17', '0.1.19'],
  '@dirigible-ai/sdk':         ['0.6.2', '0.6.3'],
  '@ml-toolkit-ts/preprocessing': ['1.0.2', '1.0.3'],
  '@ml-toolkit-ts/xgboost':       ['1.0.3', '1.0.4'],
  'ml-toolkit-ts':                ['1.0.4', '1.0.5'],
  'agentwork-cli':                ['0.1.4', '0.1.5'],
  'safe-action':                  ['0.8.3', '0.8.4'],
  'cmux-agent-mcp':               ['0.1.3', '0.1.4', '0.1.5', '0.1.6', '0.1.7', '0.1.8'],
  'git-git-git':                  ['1.0.8', '1.0.9', '1.0.10', '1.0.12'],
  'git-branch-selector':          ['1.3.3', '1.3.4', '1.3.5', '1.3.7'],
  'nextmove-mcp':                 ['0.1.3', '0.1.4', '0.1.5', '0.1.7'],
  'wot-api':                      ['0.8.1', '0.8.2', '0.8.4'],
  'cross-stitch':                 ['1.1.3', '1.1.4', '1.1.6'],
  'ts-dna':                       ['3.0.1', '3.0.2', '3.0.4'],
};

// Machine-level persistence IOCs (Microsoft, StepSecurity, Unit 42).
function persistencePaths () {
  const home = os.homedir();
  return [
    path.join(home, '.claude', 'setup.mjs'),
    path.join(home, '.claude', 'router_runtime.js'),
    path.join(home, '.claude', 'setup_bun.js'),
    path.join(home, '.claude', 'bun_environment.js'),
    path.join(home, '.vscode', 'setup.mjs'),
    path.join(home, '.vscode', 'tasks.json'),       // check for modifications
    '/etc/systemd/system/gh-token-monitor.service',
    path.join(home, 'Library', 'LaunchAgents', 'com.github.token-monitor.plist'),
  ];
}

// ==========================================================================
// 2. AUDIT PRIMITIVES (pure)
// ==========================================================================

function isCompromised (name, version) {
  return !!(COMPROMISED[name] && COMPROMISED[name].includes(version));
}

// Names appearing in IOC list, regardless of version. Used for declared-range
// warnings since semver ranges may resolve to a compromised version later.
function isAtRiskName (name) {
  return Object.prototype.hasOwnProperty.call(COMPROMISED, name);
}

// ==========================================================================
// 3. LOCKFILE PARSERS
// Each parser returns a flat array of { name, version, location? } records
// representing every resolved package the lockfile pins.
// ==========================================================================

function parseNpmLock (text) {
  const lock = JSON.parse(text);
  const out  = [];
  const seen = new Set();

  // npm v7+ (lockfileVersion 2/3): "packages" keyed by install path.
  for (const [pkgPath, info] of Object.entries(lock.packages || {})) {
    if (!pkgPath.startsWith('node_modules/')) continue;
    const name    = pkgPath.replace(/^.*node_modules\//, '');
    const version = info && info.version;
    if (!name || !version) continue;
    const key = name + '@' + version;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name, version, location: pkgPath });
  }

  // npm v6 (lockfileVersion 1): nested "dependencies".
  if (lock.dependencies) {
    (function walk (deps, parent) {
      for (const [name, info] of Object.entries(deps)) {
        if (info && info.version) {
          const key = name + '@' + info.version;
          if (!seen.has(key)) {
            seen.add(key);
            out.push({ name, version: info.version, location: 'v1:' + parent });
          }
        }
        if (info && info.dependencies) walk(info.dependencies, name);
      }
    })(lock.dependencies, 'root');
  }

  return out;
}

// pnpm key shapes across versions:
//   v5/v6:  /@scope/name/1.2.3:        or  /name/1.2.3:
//           /@scope/name/1.2.3(peer@x): or  /name/1.2.3(peer@x):
//   v9+:    '@scope/name@1.2.3':       or  name@1.2.3:
function parsePnpmPackageKey (rawKey) {
  let k = rawKey.trim().replace(/^['"]|['"]$/g, '').replace(/\(.*\)$/, '');

  // v9
  let m = k.match(/^((?:@[^/]+\/)?[^@/][^@]*)@([0-9][^@]*)$/);
  if (m) return { name: m[1], version: m[2] };

  // v5/v6
  m = k.match(/^\/((?:@[^/]+\/)?[^/]+)\/([0-9][^/]*)$/);
  if (m) return { name: m[1], version: m[2] };

  return null;
}

function parsePnpmLock (text) {
  // No YAML dep: we only need package keys, which live one level under
  // top-level `packages:` or `snapshots:` blocks.
  const PKG_SECTIONS = new Set(['packages', 'snapshots']);
  const out  = [];
  const seen = new Set();
  let inSection = false;

  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const indent = line.match(/^ */)[0].length;

    if (indent === 0) {
      const top = line.match(/^([A-Za-z_][\w-]*):\s*$/);
      inSection = !!(top && PKG_SECTIONS.has(top[1]));
      continue;
    }
    if (!inSection || indent !== 2) continue;

    const keyMatch = line.match(/^\s+(.+?):\s*(?:\{\s*\})?\s*$/);
    if (!keyMatch) continue;

    const parsed = parsePnpmPackageKey(keyMatch[1]);
    if (!parsed) continue;

    const key = parsed.name + '@' + parsed.version;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(parsed);
  }
  return out;
}

// ==========================================================================
// 4. PROJECT AUDITOR
// Runs all checks against a single project directory. Returns a structured
// result rather than printing — reporting is the caller's responsibility.
// ==========================================================================

/**
 * @typedef {Object} Finding
 * @property {'lockfile'|'package-json'|'orphan-commit'|'router-init'} kind
 * @property {string}  message
 * @property {string}  [name]
 * @property {string}  [version]
 */

/**
 * @typedef {Object} ProjectAudit
 * @property {string}   dir            absolute path to project
 * @property {string[]} managers       e.g. ['npm'], ['pnpm'], ['npm','pnpm']
 * @property {number}   packagesScanned total resolved packages inspected
 * @property {Finding[]} findings
 * @property {string[]} warnings       parse errors etc.
 */

function auditProject (dir) {
  /** @type {ProjectAudit} */
  const result = {
    dir,
    managers: [],
    packagesScanned: 0,
    findings: [],
    warnings: [],
  };

  auditNpmLockfile(dir, result);
  auditPnpmLockfile(dir, result);
  auditDeclaredRanges(dir, result);
  auditNodeModulesForOrphanIOC(dir, result);

  return result;
}

function auditLockfileEntries (entries, kind, result) {
  for (const { name, version, location } of entries) {
    result.packagesScanned++;
    if (isCompromised(name, version)) {
      result.findings.push({
        kind,
        name,
        version,
        message: name + '@' + version + (location ? ' (' + location + ')' : ''),
      });
    }
  }
}

function auditNpmLockfile (dir, result) {
  const lockPath = path.join(dir, 'package-lock.json');
  if (!fs.existsSync(lockPath)) return;
  result.managers.push('npm');

  let entries;
  try {
    entries = parseNpmLock(fs.readFileSync(lockPath, 'utf8'));
  } catch (err) {
    result.warnings.push('package-lock.json parse error: ' + err.message);
    return;
  }
  auditLockfileEntries(entries, 'lockfile', result);
}

function auditPnpmLockfile (dir, result) {
  const lockPath = path.join(dir, 'pnpm-lock.yaml');
  if (!fs.existsSync(lockPath)) return;
  result.managers.push('pnpm');

  let entries;
  try {
    entries = parsePnpmLock(fs.readFileSync(lockPath, 'utf8'));
  } catch (err) {
    result.warnings.push('pnpm-lock.yaml read error: ' + err.message);
    return;
  }
  auditLockfileEntries(entries, 'lockfile', result);
}

function auditDeclaredRanges (dir, result) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (err) {
    result.warnings.push('package.json parse error: ' + err.message);
    return;
  }

  const buckets = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  for (const bucket of buckets) {
    const deps = pkg[bucket] || {};
    for (const [name, range] of Object.entries(deps)) {
      if (isAtRiskName(name)) {
        result.findings.push({
          kind: 'package-json',
          name,
          message: 'at-risk name "' + name + '" declared in ' + bucket + ' ("' + range +
                   '") — compromised versions: ' + COMPROMISED[name].join(', '),
        });
      }
    }
  }
}

// The "orphan commit" IOC: a sub-package on disk declares
// optionalDependencies['@tanstack/setup'] pointing at a tarball/commit, or
// ships a router_init.js at its root.
function auditNodeModulesForOrphanIOC (dir, result) {
  const nm = path.join(dir, 'node_modules');
  if (!fs.existsSync(nm)) return;

  let top;
  try { top = fs.readdirSync(nm); }
  catch { return; }

  for (const entry of top) {
    const entryPath = path.join(nm, entry);
    const pkgJsons = [];

    if (entry.startsWith('@')) {
      try {
        for (const sub of fs.readdirSync(entryPath)) {
          pkgJsons.push(path.join(entryPath, sub, 'package.json'));
        }
      } catch { continue; }
    } else {
      pkgJsons.push(path.join(entryPath, 'package.json'));
    }

    for (const pp of pkgJsons) {
      if (!fs.existsSync(pp)) continue;

      let j;
      try { j = JSON.parse(fs.readFileSync(pp, 'utf8')); }
      catch { continue; }

      const od = j.optionalDependencies;
      if (od && od['@tanstack/setup']) {
        result.findings.push({
          kind: 'orphan-commit',
          message: pp + ' has @tanstack/setup optionalDependency: ' + od['@tanstack/setup'],
        });
      }
      const routerInit = path.join(path.dirname(pp), 'router_init.js');
      if (fs.existsSync(routerInit)) {
        result.findings.push({
          kind: 'router-init',
          message: 'router_init.js present in ' + path.dirname(pp),
        });
      }
    }
  }
}

// ==========================================================================
// 5. DISCOVERY
// Walk a root and yield every directory that looks like an npm/pnpm project.
// A "project" = directory containing package.json, package-lock.json, or
// pnpm-lock.yaml. We still recurse into projects so that monorepo workspaces
// (which contain their own package.json children) are discovered too.
// ==========================================================================

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg',
  'dist', 'build', 'out', '.next', '.nuxt', '.turbo',
  '.cache', 'coverage', '.pnpm-store', '.yarn', '.venv', 'venv', '__pycache__',
]);

function isProjectDir (entries) {
  return entries.has('package.json') ||
         entries.has('package-lock.json') ||
         entries.has('pnpm-lock.yaml');
}

function findProjects (root) {
  const found = [];

  (function walk (dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    const fileNames = new Set(entries.filter(e => e.isFile()).map(e => e.name));
    if (isProjectDir(fileNames)) found.push(dir);

    for (const e of entries) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (SKIP_DIRS.has(e.name)) continue;
      if (e.name.startsWith('.')) continue;
      // Avoid following symlinks to dodge cycles.
      if (e.isSymbolicLink()) continue;
      walk(path.join(dir, e.name));
    }
  })(root);

  return found;
}

// ==========================================================================
// 5b. GIT URL SUPPORT
// Recognise common git URL shapes (GitHub, GitLab, Bitbucket, generic SSH /
// HTTPS / git://). When the CLI argument is a URL, shallow-clone it into a
// temp dir, scan, and clean up.
// ==========================================================================

function isGitUrl (s) {
  if (!s) return false;
  // scp-style: git@host:owner/repo(.git)
  if (/^[\w.-]+@[\w.-]+:[\w./~-]+$/.test(s)) return true;
  // protocol-prefixed
  if (/^(https?|ssh|git):\/\//i.test(s)) {
    return /\.git(\/?)$|github\.com|gitlab\.com|bitbucket\.org|@/.test(s) || s.endsWith('.git');
  }
  return false;
}

function repoNameFromUrl (url) {
  const m = url.match(/([^/:]+?)(?:\.git)?\/?$/);
  return (m && m[1]) || 'repo';
}

function cloneToTempDir (url) {
  const which = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (which.status !== 0) {
    throw new Error('git is not available on PATH; cannot clone ' + url);
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'shai-hulud-audit-'));
  const dest    = path.join(tmpRoot, repoNameFromUrl(url));

  console.log('  Cloning ' + url + ' -> ' + dest);
  const res = spawnSync('git', ['clone', '--depth', '1', '--quiet', url, dest], {
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  if (res.status !== 0) {
    rmrf(tmpRoot);
    throw new Error('git clone failed (exit ' + res.status + ') for ' + url);
  }
  return { dir: dest, tmpRoot };
}

function rmrf (p) {
  try { fs.rmSync(p, { recursive: true, force: true }); }
  catch { /* best-effort */ }
}

// ==========================================================================
// 6. REPORTING / MAIN
// ==========================================================================

const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN  = '\x1b[32m';
const BLUE   = '\x1b[34m';
const BOLD   = '\x1b[1m';
const RESET  = '\x1b[0m';

function header (s) {
  console.log('\n' + BOLD + BLUE + s + RESET);
  console.log(BLUE + '-'.repeat(s.length) + RESET);
}

function reportProject (audit, root) {
  const rel = path.relative(root, audit.dir) || '.';
  const mgr = audit.managers.length ? audit.managers.join('+') : 'package.json-only';
  const tag = audit.findings.length
    ? RED + BOLD + 'COMPROMISED' + RESET
    : GREEN + 'clean' + RESET;

  console.log('  [' + tag + '] ' + BOLD + rel + RESET +
              '  (' + mgr + ', ' + audit.packagesScanned + ' pkgs)');

  for (const w of audit.warnings) {
    console.log('      ' + YELLOW + 'warn: ' + w + RESET);
  }
  for (const f of audit.findings) {
    const colour = (f.kind === 'package-json') ? YELLOW : RED;
    console.log('      ' + colour + f.kind + ': ' + f.message + RESET);
  }
}

function reportPersistence () {
  header('Machine-level persistence hooks');
  let hits = 0;
  for (const p of persistencePaths()) {
    if (fs.existsSync(p)) {
      hits++;
      console.log('  ' + RED + BOLD + 'PRESENT: ' + RESET + RED + p + RESET);
    }
  }

  const npmCache = path.join(os.homedir(), '.npm', '_cacache', 'tmp');
  if (fs.existsSync(npmCache)) {
    try {
      const tmps = fs.readdirSync(npmCache).filter(e => e.startsWith('git-clone'));
      if (tmps.length > 0) {
        console.log('  ' + YELLOW + 'INFO: ' + RESET + tmps.length +
                    ' git-clone tmp dirs in ' + npmCache);
        console.log('         (Inspect for orphan commit refs such as tanstack/router#79ac49ee...)');
      }
    } catch { /* ignore */ }
  }

  if (hits === 0) console.log(GREEN + '  No known persistence hooks detected.' + RESET);
  return hits;
}

function main () {
  const arg = process.argv[2];

  console.log(BOLD + 'Mini Shai-Hulud Audit' + RESET);
  console.log('Date:    ' + new Date().toISOString());
  console.log('IOC set: ' + Object.keys(COMPROMISED).length + ' package names, ' +
              Object.values(COMPROMISED).reduce((a, b) => a + b.length, 0) + ' versions');

  let root;
  let cleanup = null;

  if (arg && isGitUrl(arg)) {
    header('Cloning git URL');
    try {
      const { dir, tmpRoot } = cloneToTempDir(arg);
      root    = dir;
      cleanup = () => rmrf(tmpRoot);
    } catch (err) {
      console.error(RED + err.message + RESET);
      process.exit(2);
    }
    console.log('Source:  ' + arg);
    console.log('Root:    ' + root + '  (temporary clone)');
  } else {
    root = path.resolve(arg || process.cwd());
    console.log('Root:    ' + root);
    if (!fs.existsSync(root)) {
      console.error(RED + 'Path does not exist (and not a recognised git URL): ' + root + RESET);
      process.exit(2);
    }
  }

  // Ensure clone is always removed even on uncaught errors / signals.
  if (cleanup) {
    process.on('exit',  cleanup);
    process.on('SIGINT',  () => { cleanup(); process.exit(130); });
    process.on('SIGTERM', () => { cleanup(); process.exit(143); });
  }

  header('Discovering projects');
  const projects = findProjects(root);
  if (projects.length === 0) {
    console.log(YELLOW + '  No npm/pnpm projects found under ' + root + RESET);
    reportPersistence();
    process.exit(0);
  }
  console.log('  Found ' + projects.length + ' project director' +
              (projects.length === 1 ? 'y' : 'ies') + '.');

  header('Per-project audit');
  const audits = projects.map(p => auditProject(p));
  for (const a of audits) reportProject(a, root);

  const persistenceHits = reportPersistence();

  header('Summary');
  const dirty       = audits.filter(a => a.findings.length > 0);
  const totalFinds  = audits.reduce((n, a) => n + a.findings.length, 0);
  const totalPkgs   = audits.reduce((n, a) => n + a.packagesScanned, 0);
  const byManager   = countByManager(audits);

  console.log('  Projects scanned:     ' + audits.length +
              '  (npm: ' + byManager.npm + ', pnpm: ' + byManager.pnpm +
              ', other: ' + byManager.other + ')');
  console.log('  Resolved packages:    ' + totalPkgs);
  console.log('  Compromised projects: ' + dirty.length);
  console.log('  Total findings:       ' + totalFinds);
  console.log('  Persistence hits:     ' + persistenceHits);

  if (dirty.length === 0 && persistenceHits === 0) {
    console.log('\n' + GREEN + BOLD + 'CLEAN: no matches against current IOC set.' + RESET);
    console.log('Re-run after each install and whenever new IOCs are published.');
    process.exit(0);
  }

  console.log('\n' + RED + BOLD + 'ATTENTION REQUIRED.' + RESET);
  console.log(BOLD + 'DO NOT immediately revoke npm tokens or wipe files.' + RESET);
  console.log('The malware contains a token-monitor watchdog that triggers a home');
  console.log('directory wipe when revocation is detected. Image the affected machine');
  console.log('first, then rotate credentials from a clean environment.');
  process.exit(1);
}

function countByManager (audits) {
  const out = { npm: 0, pnpm: 0, other: 0 };
  for (const a of audits) {
    if (a.managers.includes('npm'))  out.npm++;
    if (a.managers.includes('pnpm')) out.pnpm++;
    if (a.managers.length === 0)     out.other++;
  }
  return out;
}

main();
