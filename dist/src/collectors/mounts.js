// Parse /proc/mounts: volumes, shared directories, host paths, writable sensitive mounts.
const HOST_LIKE = /^\/dev\/|\/host|\/var\/lib\/kubelet|\/etc\/kubernetes/;
const SENSITIVE_TARGETS = [/docker\.sock$/, /^\/host/, /^\/etc$/, /^\/root$/];
const VIRTUAL_FS = new Set(['proc', 'sysfs', 'tmpfs', 'devpts', 'cgroup', 'cgroup2', 'overlay', 'mqueue', 'shm']);
export function parseMounts(text) {
  const mounts = [];
  for (const line of text.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;
    const [device, target, fstype, opts] = parts;
    mounts.push({
      device, target, fstype,
      writable: opts.split(',').includes('rw'),
      host_like_source: HOST_LIKE.test(device),
      sensitive_target: SENSITIVE_TARGETS.some((re) => re.test(target)) && !VIRTUAL_FS.has(fstype),
    });
  }
  return mounts;
}
export async function collect(probe, facts) {
  const text = probe.read('proc/mounts');
  const mounts = text ? parseMounts(text) : [];
  facts.mounts = {
    all: mounts,
    host_like: mounts.filter((m) => m.host_like_source),
    writable_sensitive: mounts.filter((m) => m.writable && (m.host_like_source || m.sensitive_target)),
    writable_sensitive_summary: mounts.filter((m) => m.writable && (m.host_like_source || m.sensitive_target))
      .map((m) => `${m.device} mounted at ${m.target} (${m.fstype}, writable)`),
    source: text ? 'proc/mounts' : 'unavailable',
  };
}
