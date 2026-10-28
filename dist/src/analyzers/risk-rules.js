import fs from 'node:fs';
import { get } from '../lib/probe.js';

// Minimal condition engine over collected facts. Rules live in
// rules/security-rules.json so ECS/EKS/Docker checks extend without
// touching this engine.
function test(facts, cond) {
  if (cond.any) return cond.any.some((c) => test(facts, c));
  if (cond.not) return !test(facts, cond.not);
  const v = get(facts, cond.fact);
  switch (cond.op) {
    case 'eq': return v === cond.value;
    case 'truthy': return !!v;
    case 'nonEmpty': return Array.isArray(v) && v.length > 0;
    case 'includes': return Array.isArray(v) && v.includes(cond.value);
    case 'anyMatch': return Array.isArray(v) && v.some((item) => Object.entries(cond.match).every(([k, val]) => get(item, k) === val));
    default: throw new Error('unknown op ' + cond.op);
  }
}
function interpolate(evidence, facts) {
  const out = {};
  for (const [k, v] of Object.entries(evidence ?? {})) {
    let missing = false;
    const rendered = String(v).replace(/\{\{([^}]+)\}\}/g, (_, p) => {
      const val = get(facts, p.trim());
      if (val == null) { missing = true; return ''; } // e.g. fixture-only sample fields in live mode
      if (Array.isArray(val) && val.every((x) => typeof x !== 'object')) return val.join('; ');
      return typeof val === 'object' ? JSON.stringify(val) : String(val);
    });
    if (!missing) out[k] = rendered;
  }
  return out;
}
export function loadRules(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
export function evaluate(facts, rules) {
  const findings = [];
  for (const rule of rules) {
    if (rule.when.every((c) => test(facts, c))) {
      findings.push({
        id: rule.id, category: rule.category, severity: rule.severity,
        title: rule.title, evidence: interpolate(rule.evidence, facts), risk: rule.risk,
        unverified: rule.unverified ?? null, verify: rule.verify ?? null,
        recommendation: rule.recommendation,
      });
    }
  }
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return findings;
}
