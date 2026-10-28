// Cross-cutting guidance layered on top of per-finding recommendations.
export function buildNextSteps(findings, facts) {
  const steps = [];
  const cats = new Set(findings.map((f) => f.category));
  if (cats.has('aws-identity')) {
    steps.push('Container-internal evidence cannot show what the available AWS role allows. Run a separate authorized external review (read-only audit account over IAM, VPC, and CloudTrail) before treating cloud permissions as known.');
  }
  if (cats.has('mutation-potential')) {
    steps.push('Treat tool and socket presence as leads, not proof: validate actual change permissions from outside the container before prioritizing remediation.');
  }
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
    steps.push('Address critical and high findings before running untrusted Git-sourced code in this container.');
  }
  steps.push('Untrusted code running in the same container can read or tamper with this report. In sensitive environments, treat the report as a local lead and verify externally.');
  return steps;
}
