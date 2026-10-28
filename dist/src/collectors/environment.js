// Environment exposure. Secret-looking variables: NAMES only - their values
// are never read, stored, or printed in ANY mode. LIVE mode: non-secret values
// are shown (masked at the value level for embedded credentials) so the report
// reflects the real configuration. FIXTURE mode: the synthetic fixture carries
// invented sample values, clearly labeled.
import { liveEnvLine } from '../lib/redact.js';

const CLASSES = [
  { type: 'secret-like', re: /(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE|CREDENTIAL|SESSION|AUTH)/i },
  { type: 'aws', re: /^AWS_/i },
  { type: 'proxy', re: /^(HTTP|HTTPS|NO|ALL)_PROXY$/i },
  { type: 'kubernetes', re: /^KUBERNETES/i },
  { type: 'database', re: /^(DB_|DATABASE_|POSTGRES|MYSQL|MONGO|REDIS)/i },
];
export function classify(name) {
  for (const c of CLASSES) if (c.re.test(name)) return c.type;
  return 'standard';
}
export async function collect(probe, facts) {
  let names, sampleLines = null, liveLines = null;
  if (probe.live) {
    names = Object.keys(process.env);
    // Live values: secret-looking names are never dereferenced (redact.js),
    // everything else is shown with value-level masking applied.
    liveLines = names.map((n) => liveEnvLine(process.env, n));
  } else {
    const raw = JSON.parse(probe.read('env.json') ?? '[]');
    names = raw.map((e) => (typeof e === 'string' ? e : e.name));
    // Fixture only: invented demo values from the synthetic fixture, labeled.
    sampleLines = raw.filter((e) => typeof e === 'object' && e.value != null)
      .map((e) => `${e.name} = ${e.value}`);
  }
  const classified = names.sort().map((name) => ({ name, class: classify(name) }));
  const linesFor = (cls) => sampleLines ? sampleLines.filter((l) => classify(l.split(' = ')[0]) === cls).join('\n') : null;
  const liveFor = (cls) => liveLines ? liveLines.filter((l) => classify(l.split(' = ')[0]) === cls).join('\n') : null;
  facts.environment = {
    total: classified.length,
    by_class: classified.reduce((m, v) => ((m[v.class] = (m[v.class] ?? 0) + 1), m), {}),
    variables: classified,
    secret_like_names: classified.filter((v) => v.class === 'secret-like').map((v) => v.name),
    proxy_names: classified.filter((v) => v.class === 'proxy').map((v) => v.name),
    values_read: liveLines != null,
    values_note: liveLines != null
      ? 'Live run: non-secret values shown; secret-looking variables were never read and appear as [REDACTED - value not collected].'
      : 'Fixture demo: values below are SYNTHETIC and invented, not from any real environment.',
    live_values: liveLines ? liveLines.join('\n') : null,
    live_secret_lines: liveFor('secret-like'),
    live_aws_lines: liveFor('aws'),
    live_proxy_lines: liveFor('proxy'),
    sample_values_synthetic: sampleLines,
    sample_secret_lines: linesFor('secret-like'),
    sample_aws_lines: linesFor('aws'),
    sample_proxy_lines: linesFor('proxy'),
  };
}
