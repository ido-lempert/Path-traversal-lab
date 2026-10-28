import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Probe } from './lib/probe.js';
import { loadRules, evaluate } from './analyzers/risk-rules.js';
import { buildNextSteps } from './analyzers/recommendations.js';

const COLLECTORS = ['runtime', 'environment', 'filesystem', 'linux-capabilities', 'mounts', 'network', 'aws-identity', 'installed-tools'];
const RULES_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'rules', 'security-rules.json');

const EXPOSURE_AREAS = [
  { area: 'AWS identity & permissions', categories: ['aws-identity'], summary: 'Which AWS credential sources and endpoints code running here can reach (presence only, never values).' },
  { area: 'Secrets & sensitive files', categories: ['environment', 'filesystem'], summary: 'Environment variable names, credential files, and their permission bits.' },
  { area: 'OS & runtime', categories: ['runtime'], summary: 'Process user, Linux capabilities, and system posture.' },
  { area: 'Network & internal services', categories: ['network'], summary: 'Listening sockets, established connections, DNS, routes, and proxy settings (passive only).' },
  { area: 'Infrastructure mutation potential', categories: ['mutation-potential'], summary: 'Sockets, mounts, and tooling that could let code change infrastructure. Presence is a lead, not proof of permission.' },
];

export async function runAudit({ fixture = null, live = false } = {}) {
  const root = fixture ?? '/';
  const probe = new Probe(root, { live: live && !fixture });
  const facts = {};
  for (const name of COLLECTORS) {
    const mod = await import(`./collectors/${name}.js`);
    await mod.collect(probe, facts);
  }
  const rules = loadRules(RULES_FILE);
  const findings = evaluate(facts, rules);
  const counts = findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {});
  const exposure_map = EXPOSURE_AREAS.map((a) => {
    const rel = findings.filter((f) => a.categories.includes(f.category));
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return { ...a, count: rel.length, max: rel.length ? order[Math.min(...rel.map((f) => order.indexOf(f.severity)))] : null };
  });
  return {
    meta: {
      tool: 'container-security-inspector',
      version: '0.1.0',
      generated_at: new Date().toISOString(),
      mode: fixture ? 'fixture (synthetic demo data)' : 'live (this container)',
      target_label: fixture ? `synthetic fixture: ${path.basename(fixture)}` : 'this container',
      caveat: 'This report is read-only: it changes no settings and sends nothing externally. Credential, token, password, and private-key values are never retained or exported: secret-looking variables are never read, private keys are never opened, allowlisted files are parsed in memory with secret values masked before anything is written to the report. Secret material appears by name, path, and permission bits only. It cannot see full IAM permissions from inside a container, and a container does not necessarily see host processes, interfaces, or connections. Untrusted code sharing this container could read or tamper with this report; sensitive environments need a separate authorized external AWS/IAM/VPC/CloudTrail review. In fixture mode, any sample values or file contents shown are SYNTHETIC and invented for the demo - they are not real secrets and were not read from any real environment.',
    },
    summary: { total: findings.length, counts },
    exposure_map,
    findings,
    next_steps: buildNextSteps(findings, facts),
    facts,
  };
}
