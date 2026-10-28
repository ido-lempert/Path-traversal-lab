// Decode effective Linux capabilities from /proc/self/status CapEff.
export const CAPS = ['CHOWN','DAC_OVERRIDE','DAC_READ_SEARCH','FOWNER','FSETID','KILL','SETGID','SETUID','SETPCAP','LINUX_IMMUTABLE','NET_BIND_SERVICE','NET_BROADCAST','NET_ADMIN','NET_RAW','IPC_LOCK','IPC_OWNER','SYS_MODULE','SYS_RAWIO','SYS_CHROOT','SYS_PTRACE','SYS_PACCT','SYS_ADMIN','SYS_BOOT','SYS_NICE','SYS_RESOURCE','SYS_TIME','SYS_TTY_CONFIG','MKNOD','LEASE','AUDIT_WRITE','AUDIT_CONTROL','SETFCAP','MAC_OVERRIDE','MAC_ADMIN','SYSLOG','WAKE_ALARM','BLOCK_SUSPEND','AUDIT_READ','PERFMON','BPF','CHECKPOINT_RESTORE'];
const NOTABLE = new Set(['SYS_ADMIN','NET_ADMIN','SYS_PTRACE','DAC_READ_SEARCH','DAC_OVERRIDE','SYS_MODULE','SYS_RAWIO','BPF','SYS_BOOT']);
export function decodeCapEff(hex) {
  const bits = BigInt('0x' + hex.replace(/^0x/i, ''));
  const out = [];
  for (let i = 0; i < CAPS.length; i++) if (bits & (1n << BigInt(i))) out.push(CAPS[i]);
  return out;
}
export async function collect(probe, facts) {
  const status = probe.read('proc/self/status');
  let caps = [];
  if (status) {
    const hex = /CapEff:\s*([0-9a-fA-F]+)/.exec(status)?.[1];
    if (hex) caps = decodeCapEff(hex);
  } else if (probe.live) {
    caps = null; // unreadable here; report as unknown, never guess
  }
  facts.linux_capabilities = {
    effective: caps,
    notable: caps ? caps.filter((c) => NOTABLE.has(c)) : [],
    source: status ? 'proc/self/status CapEff' : 'unavailable',
  };
}
