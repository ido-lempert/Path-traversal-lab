// Presence of tooling that could be used to interact with cloud or container
// infrastructure. Tool presence alone does not prove usable permissions.
const TOOLS = [
  { name: 'aws', label: 'AWS CLI', relevance: 'cloud control plane' },
  { name: 'kubectl', label: 'kubectl', relevance: 'Kubernetes API' },
  { name: 'docker', label: 'Docker CLI', relevance: 'container control (with socket access)' },
  { name: 'curl', label: 'curl', relevance: 'HTTP to metadata/internal endpoints' },
  { name: 'nc', label: 'netcat', relevance: 'raw TCP probing' },
  { name: 'npm', label: 'npm', relevance: 'package execution (npx)' },
];
const BIN_DIRS = ['usr/local/bin', 'usr/bin', 'bin'];
export async function collect(probe, facts) {
  const found = [];
  for (const t of TOOLS) {
    for (const d of BIN_DIRS) {
      if (probe.exists(`${d}/${t.name}`)) {
        found.push({ ...t, path: '/' + d + '/' + t.name });
        break;
      }
    }
  }
  facts.installed_tools = {
    found,
    found_summary: found.map((t) => `${t.label} at ${t.path} (${t.relevance})`),
    note: 'Presence of a tool does not prove the identity available to it can change resources; actual permissions need validation from outside the container.',
  };
}
