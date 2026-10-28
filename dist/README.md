# Container Security Inspector

Node.js · read-only audit · JSON + HTML report

A local diagnostic that runs **inside** a container and shows what code running
there can see and do: AWS identities and permission sources, accessible
secrets, OS structure, network connections, internal services, and the
potential to change infrastructure. Built for reviewing containers that run
code pulled from Git, which is not necessarily trustworthy.

## Guarantees

- **Read-only.** No settings changed, nothing sent outside the machine.
- **Secret values are never collected.** Secret-looking environment variables
  (names matching SECRET/TOKEN/PASSWORD/KEY/CREDENTIAL/AUTH patterns, plus
  AWS secret/session variables) are never even read - the report shows the
  name with `[REDACTED - value not collected]`. Private keys, shadow files and
  service-account tokens are never opened - presence and permission bits only.
- **Real configuration shown, masked.** Non-secret values and allowlisted file
  contents (.env-style files, AWS config/credentials) are shown as found, with
  value-level masking for embedded credentials (URL userinfo, PEM blocks,
  AWS key ids, JWTs, bearer tokens).
- **No network probing.** Network posture comes from passive reads of socket
  tables. Active connection tests run only against explicitly pre-approved
  targets and are not part of this MVP.
- **No cloud API calls.** No AWS metadata, SDK, or STS requests.

## Usage

```sh
# audit the container this process runs in
node bin/csi.js audit --live --out report/

# demo / test against a synthetic fixture tree (no host access)
node bin/csi.js audit --fixture demo/fixtures/sample-container --out report/
```

Both modes write `report.json` and a self-contained `report.html` (open it in
a browser). Value/content blocks are hidden behind an eye toggle by default so
the report can be shown on screen; **this hiding is visual only, not
encryption** - the HTML file still contains the non-secret text it displays,
so share the file itself only with people allowed to see that configuration.

### What a live run needs

Node.js 18+ on the machine or inside the container being audited. The audit
reports what the process it runs as can see: run it inside the target
container (for example `docker exec` / `kubectl exec`, or as a one-off job)
for a container view, or directly on a host for that host's view. It never
needs network access and writes only to its `--out` directory. Findings carry id, category, severity, evidence, risk, and a
recommendation; severity levels are critical / high / medium / low / info.

## Structure

```
src/collectors/   runtime, environment, filesystem, linux-capabilities,
                  mounts, network, aws-identity, installed-tools
src/analyzers/    risk-rules engine (rules in rules/security-rules.json),
                  recommendations
src/reporters/    json, html
src/cli.js        argument parsing and console summary
rules/            security-rules.json - extend ECS/EKS/Docker checks without
                  changing the engine
demo/fixtures/    synthetic container tree used by the demo and tests
```

## How to read findings

Evidence shows **confirmed facts only** (presence, permission bits, socket
tables, mount tables, capability sets). Risk text describes **possible
consequences** and each finding lists what was **not verified** - container
code cannot confirm daemon authorization, credential validity or contents,
or business need for a connection from the inside, and this tool never makes
connections or cloud calls to try. No finding is raised to critical on
presence-only evidence; severities reflect confirmed facts, with conditional
impact stated explicitly.

## Limits

**Platform scope: Linux.** Collectors read `/proc` (process status,
capability sets, mount table, socket tables, cgroups), the process
environment, permission bits of conventional sensitive paths, and binary
presence on PATH. Other platforms are not supported.

In `--live` mode, secret-looking environment variables are never read (name
only, shown as `[REDACTED - value not collected]`), and private keys, shadow
files and service-account tokens are never opened. Allowlisted files
(.env-style, AWS config/credentials) are parsed in memory and secret values
are masked **before anything is stored or written**; the masked bytes are
never retained or exported. Everything else shown is real, as-found
configuration with value-level masking (URL userinfo, PEM blocks, AWS key
ids, JWTs, bearer tokens). Tests assert these guarantees behaviorally and
statically. HTML output escapes all collected text.

The fixture demo report shows **invented sample values and file contents**,
each labeled as synthetic, so the report illustrates what the tool surfaces
without touching real secrets.

A container cannot see full IAM permissions from the inside; presence of a
credential provider shows a role *may* be available, and confirming what it
allows needs an authorized external IAM/CloudTrail review (planned as a
separate phase with a read-only audit account). A container also does not
necessarily see host processes, interfaces, or connections. Untrusted code
sharing the container can read or tamper with this report - treat it as a
local lead and verify externally in sensitive environments.

## Development

```sh
npm test          # node --test unit + fixture end-to-end tests
npm run demo      # run the fixture audit into demo/out/
```
