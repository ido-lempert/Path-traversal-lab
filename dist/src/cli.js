import { runAudit } from './engine.js';
import { writeJson } from './reporters/json.js';
import { writeHtml } from './reporters/html.js';

function parseArgs(argv) {
  const args = { fixture: null, out: 'csi-report', live: false };
  const rest = [...argv];
  if (rest[0] === 'audit') rest.shift();
  while (rest.length) {
    const a = rest.shift();
    if (a === '--fixture') args.fixture = rest.shift();
    else if (a === '--live') args.live = true;
    else if (a === '--out') args.out = rest.shift();
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

const HELP = `Container Security Inspector - local read-only container audit

Usage:
  csi audit --fixture DIR [--out DIR]   audit a synthetic fixture tree (demo/tests)
  csi audit --live [--out DIR]          audit the container this process runs in

Guarantees in every mode:
  - read-only: no settings changed, nothing sent externally
  - secret-looking variables and private keys are NEVER read: they are
    reported by name, path, and permissions only, shown as [REDACTED]
  - non-secret configuration values are shown with value-level masking
  - no AWS metadata/SDK/STS calls; no network probing
  - hidden (eye-toggle) sections are a visual convenience, NOT encryption:
    the report file still contains the non-secret text it displays
`;

export async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) { console.log(HELP); return 0; }
  if (!args.fixture && !args.live) { console.error(HELP); return 2; }

  const report = await runAudit({ fixture: args.fixture, live: args.live });
  const jsonFile = writeJson(report, args.out);
  const htmlFile = writeHtml(report, args.out);

  const c = report.summary.counts;
  console.log(`Container Security Inspector - audit complete (${report.meta.mode})`);
  console.log(`Findings: ${report.summary.total}  [critical:${c.critical ?? 0} high:${c.high ?? 0} medium:${c.medium ?? 0} low:${c.low ?? 0} info:${c.info ?? 0}]`);
  for (const f of report.findings) {
    console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.id} - ${f.title}`);
  }
  console.log(`JSON report: ${jsonFile}`);
  console.log(`HTML report: ${htmlFile}`);
  console.log('Note: secret values are never collected ([REDACTED]); no active network probes; see report caveats for scope limits.');
  return 0;
}
