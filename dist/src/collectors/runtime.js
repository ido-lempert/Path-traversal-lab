import os from 'node:os';

// OS / kernel / architecture / process identity. No values beyond metadata.
export async function collect(probe, facts) {
  let meta = {};
  if (!probe.live) {
    meta = JSON.parse(probe.read('meta.json') ?? '{}');
  }
  const osRelease = probe.read('etc/os-release') ?? '';
  const pretty = /PRETTY_NAME="([^"]+)"/.exec(osRelease)?.[1] ?? null;
  const status = probe.read('proc/self/status');
  let uid = null, gid = null;
  if (status) {
    uid = Number(/\nUid:\t(\d+)/.exec('\n' + status)?.[1]);
    gid = Number(/\nGid:\t(\d+)/.exec('\n' + status)?.[1]);
  } else if (probe.live) {
    uid = process.getuid?.() ?? null;
    gid = process.getgid?.() ?? null;
  }
  facts.runtime = {
    os_pretty_name: probe.live ? `${os.type()} ${os.release()}` : (meta.os ?? pretty),
    kernel: probe.live ? os.release() : meta.kernel,
    arch: probe.live ? os.arch() : meta.arch,
    platform: probe.live ? os.platform() : meta.platform,
    node_version: process.version,
    pid: probe.live ? process.pid : null,
    uid, gid,
    runs_as_root: uid === 0,
    source: probe.live ? 'live container' : 'synthetic fixture',
  };
}
