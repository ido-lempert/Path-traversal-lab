import { octalMode } from '../lib/probe.js';
import { neverOpenPath, redactText } from '../lib/redact.js';

// Presence and permission bits of sensitive paths. Private keys, shadow files
// and service-account tokens are NEVER opened in any mode. LIVE mode: other
// allowlisted files are shown with secret values redacted line-by-line.
// FIXTURE mode: the synthetic fixture's invented contents, clearly labeled.
const CANDIDATES = [
  { id: 'docker-socket', path: 'var/run/docker.sock', kind: 'socket', label: 'Docker socket' },
  { id: 'docker-socket-run', path: 'run/docker.sock', kind: 'socket', label: 'Docker socket' },
  { id: 'dotenv-app', path: 'app/.env', kind: 'file', label: 'app/.env file' },
  { id: 'dotenv-srv', path: 'srv/app/.env', kind: 'file', label: 'srv/app/.env file' },
  { id: 'aws-credentials', path: 'root/.aws/credentials', kind: 'file', label: 'AWS credentials file' },
  { id: 'aws-config', path: 'root/.aws/config', kind: 'file', label: 'AWS config file' },
  { id: 'ssh-private-key', path: 'root/.ssh/id_rsa', kind: 'file', label: 'SSH private key' },
  { id: 'ssh-private-key-ed', path: 'root/.ssh/id_ed25519', kind: 'file', label: 'SSH private key' },
  { id: 'etc-shadow', path: 'etc/shadow', kind: 'file', label: 'etc/shadow' },
  { id: 'kube-serviceaccount', path: 'var/run/secrets/kubernetes.io/serviceaccount/token', kind: 'file', label: 'Kubernetes service account token file' },
];
export async function collect(probe, facts) {
  const found = [];
  for (const c of CANDIDATES) {
    const st = probe.stat(c.path);
    if (!st) continue;
    const mode = octalMode(st);
    const otherBits = st.mode & 0o007;
    const groupBits = st.mode & 0o070;
    const entry = {
      id: c.id, path: '/' + c.path, label: c.label,
      is_socket: st.isSocket(), is_directory: st.isDirectory(),
      mode, world_readable: !!(otherBits & 0o4), world_writable: !!(otherBits & 0o2),
      group_readable: !!(groupBits & 0o40),
      contents_read: false,
    };
    if (!probe.live && !entry.is_socket && !entry.is_directory) {
      // Fixture only: invented demo content, labeled.
      const text = probe.read(c.path);
      if (text != null) {
        entry.sample_content_synthetic = text.trim().slice(0, 2000);
      }
    } else if (probe.live && !entry.is_socket && !entry.is_directory) {
      if (neverOpenPath(entry.path)) {
        entry.content_policy = 'never opened (private key/token class - presence and permissions only)';
      } else {
        // Live: show real content, secrets redacted before anything is stored.
        const text = probe.read(c.path);
        if (text != null) {
          entry.contents_read = true;
          entry.content_redacted = redactText(text.slice(0, 32000)).trim().slice(0, 4000);
        }
      }
    }
    found.push(entry);
  }
  const desc = (f) => `${f.label} at ${f.path} (${f.is_socket ? 'socket' : 'file'}, mode ${f.mode}${f.world_readable ? ', readable by all users' : ''})`;
  facts.filesystem = {
    sensitive: found,
    sensitive_summary: found.map(desc),
    world_readable_summary: found.filter((f) => f.world_readable && !f.is_socket).map(desc),
    sockets_summary: found.filter((f) => f.is_socket).map(desc),
    live_contents_block: (() => {
      if (!probe.live) return null;
      const withContent = found.filter((f) => f.content_redacted != null);
      if (!withContent.length) return null;
      return 'Real contents; secret values replaced with [REDACTED - value not collected]; private keys/tokens never opened.\n\n'
        + withContent.map((f) => `${f.path}\n${'-'.repeat(f.path.length)}\n${f.content_redacted}`).join('\n\n');
    })(),
    sample_contents_block: (() => {
      const withContent = found.filter((f) => f.sample_content_synthetic != null);
      return withContent.length
        ? withContent.map((f) => `${f.path}\n${'-'.repeat(f.path.length)}\n${f.sample_content_synthetic}`).join('\n\n')
        : null;
    })(),
    note: 'Private keys, shadow files and service-account tokens are never opened in any mode - presence and permission bits only. Live mode parses allowlisted files (.env-style, AWS config/credentials) in memory and masks secret values before anything is stored; masked bytes are never retained in or exported to the report. Fixture mode shows invented sample contents from the synthetic fixture, clearly labeled.',
  };
}
