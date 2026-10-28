// Passive network posture from /proc/net/*: listening and established sockets,
// DNS resolver, default route, proxy variable names. No active connections,
// no scanning. Active tests require an explicit allowlist and are not in the MVP.
function hexToIp(hex) {
  const b = hex.match(/../g).map((h) => parseInt(h, 16));
  return [b[3], b[2], b[1], b[0]].join('.');
}
export function parseProcNetTcp(text) {
  const out = [];
  for (const line of text.split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 4) continue;
    const [lh, lp] = p[1].split(':');
    const [rh, rp] = p[2].split(':');
    out.push({
      local_ip: hexToIp(lh), local_port: parseInt(lp, 16),
      remote_ip: hexToIp(rh), remote_port: parseInt(rp, 16),
      state: p[3] === '0A' ? 'LISTEN' : p[3] === '01' ? 'ESTABLISHED' : p[3],
    });
  }
  return out;
}
const AWS_LINK_LOCAL = { '169.254.169.254': 'EC2 instance metadata endpoint', '169.254.170.2': 'ECS task metadata / credentials endpoint' };
export async function collect(probe, facts) {
  const sockets = [];
  for (const f of ['proc/net/tcp', 'proc/net/tcp6']) {
    const t = probe.read(f);
    if (t && f.endsWith('tcp')) sockets.push(...parseProcNetTcp(t));
  }
  const resolv = probe.read('etc/resolv.conf') ?? '';
  const dns = [...resolv.matchAll(/^nameserver\s+(\S+)/gm)].map((m) => m[1]);
  const route = probe.read('proc/net/route') ?? '';
  const gwLine = route.split('\n').find((l) => l.split(/\s+/)[1] === '00000000');
  const gateway = gwLine ? hexToIp(gwLine.split(/\s+/)[2]) : null;
  const listening = sockets.filter((s) => s.state === 'LISTEN');
  const established = sockets.filter((s) => s.state === 'ESTABLISHED');
  const awsEndpoints = established.filter((s) => AWS_LINK_LOCAL[s.remote_ip])
    .map((s) => ({ endpoint: s.remote_ip, meaning: AWS_LINK_LOCAL[s.remote_ip] }));
  facts.network = {
    listening, established, dns, default_gateway: gateway,
    listening_summary: listening.map((s) => `${s.local_ip}:${s.local_port}`),
    established_summary: established.map((s) => `${s.local_ip}:${s.local_port} -> ${s.remote_ip}:${s.remote_port}`),
    aws_link_local_endpoints_in_use: awsEndpoints,
    aws_link_local_summary: awsEndpoints.map((e) => `${e.meaning} (${e.endpoint})`),
    active_probes_performed: false,
    note: 'Passive read of socket tables only. A container sees its own network namespace, not necessarily host interfaces or other containers. Active connection tests run only against explicitly pre-approved targets and none ran here.',
  };
}
