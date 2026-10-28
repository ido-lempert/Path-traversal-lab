// AWS identity posture: platform hints and credential-provider PRESENCE.
// No keys, tokens, or metadata/STS/SDK calls. Presence is not proof of permission.
export async function collect(probe, facts) {
  const envNames = new Set((facts.environment?.variables ?? []).map((v) => v.name));
  const cgroup = probe.read('proc/self/cgroup') ?? '';
  const hints = [];
  if (probe.exists('.dockerenv') || /docker|containerd/i.test(cgroup)) hints.push('docker');
  if (envNames.has('KUBERNETES_SERVICE_HOST') || probe.exists('var/run/secrets/kubernetes.io/serviceaccount')) hints.push('kubernetes');
  if (envNames.has('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI') || envNames.has('ECS_CONTAINER_METADATA_URI_V4')) hints.push('ecs');
  if (envNames.has('AWS_EXECUTION_ENV')) hints.push('aws-execution-env');
  const providers = [];
  if (envNames.has('AWS_ACCESS_KEY_ID')) providers.push({ source: 'static env credential names (AWS_ACCESS_KEY_ID/SECRET)', values_exposed: false });
  if (envNames.has('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')) providers.push({ source: 'container credential provider (task role via 169.254.170.2)', values_exposed: false });
  if (envNames.has('AWS_WEB_IDENTITY_TOKEN_FILE')) providers.push({ source: 'web identity token file (IRSA)', values_exposed: false });
  if (probe.exists('root/.aws/credentials')) providers.push({ source: 'AWS credentials file present on disk', values_exposed: false });
  const inUse = (facts.network?.aws_link_local_endpoints_in_use ?? []).map((e) => e.meaning);
  facts.aws_identity = {
    platform_hints: hints,
    credential_providers_present: providers,
    credential_providers_summary: providers.map((p) => p.source),
    credential_endpoints_in_use: inUse,
    region_variable_present: envNames.has('AWS_REGION') || envNames.has('AWS_DEFAULT_REGION'),
    caveat: 'Full IAM permissions cannot be inferred from inside the container alone. Credential-provider presence shows a role may be available to code running here; confirming what that role can do requires an authorized IAM/CloudTrail review from outside.',
  };
}
