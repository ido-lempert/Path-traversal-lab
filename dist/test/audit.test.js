import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit } from '../src/engine.js';
import { decodeCapEff } from '../src/collectors/linux-capabilities.js';
import { classify } from '../src/collectors/environment.js';
import { parseProcNetTcp } from '../src/collectors/network.js';
import { writeJson, } from '../src/reporters/json.js';
import { renderHtml } from '../src/reporters/html.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = path.join(ROOT, 'demo', 'fixtures', 'sample-container');

function makeVariant(mutate) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csi-fixture-'));
  fs.cpSync(BASE, dir, { recursive: true });
  // cpSync cannot copy the unix-socket placeholder; recreate it.
  const sock = path.join(dir, 'var/run/docker.sock');
  if (!fs.existsSync(sock)) {
    execFileSync('python3', ['-c', `import socket; s=socket.socket(socket.AF_UNIX); s.bind(${JSON.stringify(sock)}); s.close()`]);
    fs.chmodSync(sock, 0o755);
  }
  mutate(dir);
  return dir;
}
const setUid = (dir, uid) => {
  const f = path.join(dir, 'proc/self/status');
  fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(/Uid:\t\d+\t\d+\t\d+\t\d+/, `Uid:\t${uid}\t${uid}\t${uid}\t${uid}`).replace(/Gid:\t\d+\t\d+\t\d+\t\d+/, `Gid:\t${uid}\t${uid}\t${uid}\t${uid}`));
};

test('capability decoding', () => {
  assert.deepEqual(decodeCapEff('0000000000000001'), ['CHOWN']);
  assert.ok(decodeCapEff('00000000a82425fb').includes('SYS_ADMIN'));
});

test('environment classification uses names only', () => {
  assert.equal(classify('DB_PASSWORD'), 'secret-like');
  assert.equal(classify('AWS_REGION'), 'aws');
  assert.equal(classify('HTTP_PROXY'), 'proxy');
  assert.equal(classify('PATH'), 'standard');
});

test('proc/net/tcp parsing', () => {
  const rows = parseProcNetTcp('  sl  local_address rem_address   st\n   0: 00000000:1F90 00000000:0000 0A\n');
  assert.equal(rows[0].local_port, 8080);
  assert.equal(rows[0].state, 'LISTEN');
});

test('demo fixture audit: expected findings, no invented criticals', async () => {
  const report = await runAudit({ fixture: BASE });
  const ids = report.findings.map((f) => f.id);
  for (const expected of ['INFRA-DOCKER-SOCKET-001', 'INFRA-HOST-MOUNT-001', 'AWS-IDENTITY-001', 'AWS-IDENTITY-002', 'SECRETS-ENV-001', 'SECRETS-FILE-001', 'SYSTEM-ROOT-001', 'SYSTEM-CAPS-001', 'NET-LISTEN-001', 'NET-INTERNAL-001', 'TOOLS-AWS-001']) {
    assert.ok(ids.includes(expected), `missing finding ${expected}`);
  }
  assert.ok(!report.findings.some((f) => f.severity === 'critical'), 'no critical may fire on presence-only evidence');
  assert.equal(report.meta.mode.startsWith('fixture'), true);
});

test('root + socket: mode-bits estimate allows (high); non-root + 0755 socket: estimate denies (medium)', async () => {
  const asRoot = await runAudit({ fixture: BASE });
  assert.ok(asRoot.findings.some((f) => f.id === 'INFRA-DOCKER-SOCKET-001' && f.severity === 'high' && /estimate, untested/.test(f.title)));

  const nonRoot = await runAudit({ fixture: makeVariant((d) => setUid(d, 1000)) });
  const ids = nonRoot.findings.map((f) => f.id);
  assert.ok(ids.includes('INFRA-DOCKER-SOCKET-002'), 'non-root 0755 socket: permission estimate denies, medium');
  assert.ok(!ids.includes('INFRA-DOCKER-SOCKET-001'));
  assert.ok(!ids.includes('SYSTEM-ROOT-001'));
});

test('non-root + world-writable socket: mode-bits estimate allows (high)', async () => {
  const report = await runAudit({ fixture: makeVariant((d) => { setUid(d, 1000); fs.chmodSync(path.join(d, 'var/run/docker.sock'), 0o666); }) });
  assert.ok(report.findings.some((f) => f.id === 'INFRA-DOCKER-SOCKET-001'));
});

test('benign AWS config only: no credentials-available finding', async () => {
  const report = await runAudit({ fixture: makeVariant((d) => {
    fs.rmSync(path.join(d, 'root/.aws/credentials'));
    fs.writeFileSync(path.join(d, 'env.json'), JSON.stringify(['PATH', 'HOME', 'NODE_ENV']));
    const tcp = path.join(d, 'proc/net/tcp');
    fs.writeFileSync(tcp, fs.readFileSync(tcp, 'utf8').split('\n').filter((l) => !l.includes('02AAFEA9')).join('\n'));
  }) });
  const ids = report.findings.map((f) => f.id);
  assert.ok(!ids.includes('AWS-IDENTITY-001'));
  assert.ok(!ids.includes('AWS-IDENTITY-002'));
});

test('credential provider configured but endpoint not in use: presence finding only', async () => {
  const report = await runAudit({ fixture: makeVariant((d) => {
    const f = path.join(d, 'proc/net/tcp');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').split('\n').filter((l) => !l.includes('02AAFEA9')).join('\n'));
  }) });
  const ids = report.findings.map((f) => f.id);
  assert.ok(ids.includes('AWS-IDENTITY-001'));
  assert.ok(!ids.includes('AWS-IDENTITY-002'));
});

test('private connection: low severity, business need explicitly not assessed', async () => {
  const report = await runAudit({ fixture: BASE });
  const f = report.findings.find((x) => x.id === 'NET-INTERNAL-001');
  assert.equal(f.severity, 'low');
  assert.match(f.title, /business need not assessed/);
});

test('fixture report shows invented sample values, clearly labeled synthetic', async () => {
  const report = await runAudit({ fixture: BASE });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'csi-out-'));
  const file = writeJson(report, out);
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.includes('synthetic-demo-S3cr3t-NOT-REAL'), 'invented demo value present');
  assert.ok(text.includes('SYNTHETIC - invented for demo'), 'sample evidence labeled synthetic');
  assert.ok(text.includes('AKIAIOSFODNN7EXAMPLE'), 'AWS doc placeholder key present');
  assert.match(text, /"real_secret_values_exposed": "false"/);
  fs.rmSync(out, { recursive: true, force: true });
});

test('live mode never emits sample (fixture) values; live content follows redaction policy', async () => {
  const { Probe } = await import('../src/lib/probe.js');
  const fsCol = await import('../src/collectors/filesystem.js');
  const envCol = await import('../src/collectors/environment.js');
  const probe = new Probe(BASE, { live: true });
  const facts = {};
  await envCol.collect(probe, facts);
  assert.equal(facts.environment.sample_values_synthetic, null);
  assert.equal(facts.environment.sample_secret_lines, null);
  await fsCol.collect(probe, facts);
  assert.ok(facts.filesystem.sensitive.length > 0);
  assert.ok(facts.filesystem.sensitive.every((f) => f.sample_content_synthetic === undefined));
  assert.equal(facts.filesystem.sample_contents_block, null);
  // private key class: never opened, even in live mode
  const key = facts.filesystem.sensitive.find((f) => f.path === '/root/.ssh/id_rsa');
  assert.equal(key.contents_read, false);
  assert.equal(key.content_redacted, undefined);
  assert.match(key.content_policy, /never opened/);
  // allowlisted file: shown with secret values redacted
  const dotenv = facts.filesystem.sensitive.find((f) => f.path === '/app/.env');
  assert.equal(dotenv.contents_read, true);
  assert.ok(dotenv.content_redacted.includes('[REDACTED - value not collected]'), 'secret lines redacted');
  assert.ok(!dotenv.content_redacted.includes('synthetic-demo-S3cr3t-NOT-REAL'), 'raw secret value must not survive');
});

test('live environment values: secrets never read, non-secrets shown masked', async () => {
  const { Probe } = await import('../src/lib/probe.js');
  const envCol = await import('../src/collectors/environment.js');
  process.env.CSI_TEST_DB_PASSWORD = 'csi-secret-must-not-appear';
  process.env.CSI_TEST_PROXY = 'http://user:csi-proxy-pass@proxy.local:3128';
  process.env.CSI_TEST_REGION = 'il-central-1';
  try {
    const facts = {};
    await envCol.collect(new Probe(BASE, { live: true }), facts);
    const blob = JSON.stringify(facts.environment);
    assert.ok(!blob.includes('csi-secret-must-not-appear'), 'secret value must never enter the facts');
    assert.ok(!blob.includes('csi-proxy-pass'), 'proxy userinfo password must be masked');
    assert.ok(blob.includes('CSI_TEST_DB_PASSWORD = [REDACTED - value not collected]'));
    assert.ok(blob.includes('http://[credentials-redacted]@proxy.local:3128'));
    assert.ok(blob.includes('CSI_TEST_REGION = il-central-1'), 'non-secret value shown');
    assert.equal(facts.environment.values_read, true);
  } finally {
    delete process.env.CSI_TEST_DB_PASSWORD;
    delete process.env.CSI_TEST_PROXY;
    delete process.env.CSI_TEST_REGION;
  }
});

test('redaction policy unit checks', async () => {
  const { redactText, neverReadEnv, neverOpenPath } = await import('../src/lib/redact.js');
  assert.equal(neverReadEnv('AWS_SECRET_ACCESS_KEY'), true);
  assert.equal(neverReadEnv('DB_PASSWORD'), true);
  assert.equal(neverReadEnv('AWS_REGION'), false);
  assert.equal(neverOpenPath('/root/.aws/credentials'), false);
  assert.equal(neverOpenPath('/root/.ssh/id_ed25519'), true);
  assert.equal(neverOpenPath('/etc/shadow'), true);
  const out = redactText('token = abcdef123456\n-----BEGIN OPENSSH PRIVATE KEY-----\nxyz\n-----END OPENSSH PRIVATE KEY-----\nnormal = ok');
  assert.ok(!out.includes('abcdef123456') && !out.includes('xyz'), 'secret line value and PEM body gone');
  assert.ok(out.includes('normal = ok'));
});

test('HTML escapes all collected text', async () => {
  const dir = makeVariant((d) => {
    const f = path.join(d, 'proc/mounts');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8') + '\n/dev/<img_src=x_onerror=alert(1)> /host/evil ext4 rw 0 0\n');
  });
  const html = renderHtml(await runAudit({ fixture: dir }));
  assert.ok(!html.includes('<img_src=x_onerror'), 'raw injected markup must not survive');
  assert.ok(html.includes('&lt;img_src=x_onerror'), 'escaped form should be present');
});

test('collector source guards: values only via redaction boundary, no network calls', () => {
  const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
  const env = read('src/collectors/environment.js');
  // every live value must pass through redact.js liveEnvLine (neverReadEnv-gated)
  assert.ok(env.includes("import { liveEnvLine } from '../lib/redact.js'"), 'env collector must use the redaction boundary');
  assert.ok(!/process\.env\.\w/.test(env), 'env collector must not dereference process.env members directly');
  const fsc = read('src/collectors/filesystem.js');
  assert.ok(!/readFileSync/.test(fsc), 'filesystem collector must not open files directly');
  assert.ok(fsc.includes('neverOpenPath') && fsc.includes('redactText'), 'filesystem live reads must be policy-gated and redacted');
  assert.ok(fsc.includes('!probe.live'), 'fixture sample reads must be guarded by !probe.live');
  const red = read('src/lib/redact.js');
  const gated = red.slice(red.indexOf('export function liveEnvLine'));
  assert.ok(gated.indexOf('neverReadEnv(name)') < gated.indexOf('env[name]'), 'neverReadEnv check must precede the value read');
  const netFiles = ['src/collectors/network.js', 'src/engine.js', 'src/cli.js'].map(read).join('\n');
  assert.ok(!/net\.connect|createConnection|dns\.lookup|https?\.(request|get)|fetch\(/.test(netFiles), 'no outbound network calls allowed');
});
