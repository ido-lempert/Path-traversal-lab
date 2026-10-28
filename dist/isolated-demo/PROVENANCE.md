# Provenance: measured facts vs. planted setup

This package demonstrates the Container Security Inspector running in `--live`
mode inside an **isolated test environment**: a Linux user+mount+pid+network
namespace with a minimal root filesystem (`/home/sandbox/live-rootfs`) built
only for this test. **No real host, container, cloud account or network was
inspected.** The tool made zero network connections during the run.

Every secret-looking value in the environment (database password, AWS keys,
proxy credentials, SSH private key) is an **invented string planted for the
test**. None of these values is real, and their validity was never tested.

## Per-finding breakdown

### INFRA-DOCKER-SOCKET-001 (high) - Docker socket present
- **Measured (real tool output):** a socket-type file exists at
  `/var/run/docker.sock` with mode `0666`; the workload runs as uid 65534.
- **Planted:** the socket file was created by the test setup. **No Docker
  daemon was running** and no connection to it was attempted. This finding
  shows the tool detects socket presence and permission bits - it is not
  evidence of a reachable Docker daemon.

### AWS-IDENTITY-001 (high) - AWS credential sources present
- **Measured:** `/root/.aws/credentials` and `/root/.aws/config` exist on
  disk; the non-secret region value `il-central-1` was read.
- **Planted:** both files and all key values were invented for the test.
  The tool never opened the secret values (they appear as
  `[REDACTED - value not collected]`) and made no AWS API calls, so nothing
  about validity is claimed.

### SECRETS-FILE-001 (high) - sensitive-looking files readable by all users
- **Measured:** `/app/.env`, `/root/.aws/credentials`, `/root/.aws/config`
  and `/root/.ssh/id_rsa` exist with mode `0644`. Non-secret contents were
  read; secret-pattern values were redacted before storage; the private key
  file was never opened.
- **Planted:** all four files and their contents were created for the test.
  Mode bits were set deliberately. Readability by a specific other uid was
  not separately tested (no parent-directory traversal check).

### SECRETS-ENV-001 (medium) - secret-like environment variable names present
- **Measured:** the process environment contained the variables
  `DB_PASSWORD` and `AWS_SECRET_ACCESS_KEY`. Their values were never
  dereferenced or stored.
- **Planted:** both variables and their values were invented for the test.

### NET-PROXY-001 (info) - proxy environment variables configured
- **Measured:** `HTTP_PROXY` was set; the value was shown with credentials
  stripped (`http://[credentials-redacted]@proxy.internal:3128`).
- **Planted:** the variable was invented for the test and points at a
  nonexistent proxy; no connection was attempted.

## Redaction-boundary verification

All 7 planted secret strings appear **0 times** in report.json and
report.html. This was verified for this specific run and these 7 values; it
is not a universal guarantee for arbitrary inputs.

## What this package does NOT show

- No audit of any real user system was performed or authorized.
- These findings do not represent vulnerabilities in anyone's real
  environment. A credible evaluation against a real environment requires a
  future, explicitly authorized run there.
