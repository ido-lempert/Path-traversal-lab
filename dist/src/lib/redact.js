// Redaction policy for LIVE runs. The tool shows the real state while never
// collecting credential, token, password or private-key values:
//  - secret-looking environment variables: the value is NEVER read, the report
//    shows [REDACTED - value not collected]
//  - non-secret values/files: shown, but value-level patterns (PEM blocks,
//    URL userinfo, AWS key ids, JWTs, bearer tokens) are masked first
//  - private keys, shadow files, service-account tokens: NEVER opened

export const REDACTED = '[REDACTED - value not collected]';
const SECRET_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE[_-]?KEY|CREDENTIAL|SESSION|AUTH|API[_-]?KEY|ACCESS[_-]?KEY)/i;
const NEVER_READ_EXACT = new Set(['AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN']);

// true = the collector must not even read this variable's value
export function neverReadEnv(name) {
  return NEVER_READ_EXACT.has(name) || SECRET_NAME.test(name);
}

// Paths whose contents are never opened in any mode (presence + mode bits only)
const NEVER_OPEN_PATH = /(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem$|\.key$|\.p12$|\.pfx$|\/shadow$|\/gshadow$|serviceaccount\/(token|ca\.crt)$|kubeconfig$)/i;
export function neverOpenPath(p) {
  return NEVER_OPEN_PATH.test(p);
}

// Mask value-level secret patterns inside otherwise showable text.
export function redactText(text) {
  let t = String(text);
  // PEM / private-key blocks: elide entirely
  t = t.replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[PEM/key block elided - not collected]');
  // KEY=value / key: value / ini key = value lines with secret-looking keys
  t = t.replace(/^([ \t]*[A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE[_-]?KEY|CREDENTIAL|SESSION|AUTH|API[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_.-]*)([ \t]*[=:][ \t]*)(\S.*)$/gim,
    (_, k, sep) => `${k}${sep}${REDACTED}`);
  // URL userinfo: scheme://user:pass@host -> scheme://[credentials-redacted]@host
  t = t.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi, '$1[credentials-redacted]@');
  // AWS access key ids anywhere: keep the AKIA prefix, mask the rest
  t = t.replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '$1****************[masked]');
  // JWTs
  t = t.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g, REDACTED);
  // Bearer tokens
  t = t.replace(/(Bearer\s+)\S+/gi, '$1' + REDACTED);
  // Stripe-style keys
  t = t.replace(/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]+\b/g, '$1_$2_[masked]');
  return t;
}

// One "NAME = value" report line for a live environment variable. Secret-looking
// names are never dereferenced: the value read happens only on the safe branch.
export function liveEnvLine(env, name) {
  if (neverReadEnv(name)) return `${name} = ${REDACTED}`;
  const raw = env[name];
  if (raw == null) return `${name} = (unset)`;
  const v = redactText(String(raw).slice(0, 500));
  return `${name} = ${v}`;
}
