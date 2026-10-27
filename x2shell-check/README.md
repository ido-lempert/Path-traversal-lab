# x2shell-check

A local, inventory-only exposure checker for the October 2026 "X2Shell" family:

- **PHP2Shell** - CVE-2026-109618 and CVE-2026-109619, two critical PHP-core
  vulnerabilities allowing unauthenticated remote code execution. Name used by
  CISA ("php2shell"); the PHP project's own advisory uses only the CVE/GHSA IDs.
- **Node2Shell / HTTP2Shell / Broccoli2Shell** - nicknames in secondary sources
  for CVE-2026-111497, an out-of-bounds write in Google's Brotli C decoder.
  Node.js's own advisory names only the CVE and rates it HIGH; NVD/GHSA score it
  9.2 CRITICAL (CVSS 4.0). "HTTP2Shell" has nothing to do with the HTTP/2
  protocol - the bug is in body decompression.

## What it does

Runs entirely on the machine where you execute it. It reads local command
output only (`php -v` / `php -i`, `node -v`, `pip show Brotli/brotlicffi`,
`brotli --version`, or values you pass in with flags). It sends **no network
requests** and contains **no exploit code**. You can read the whole thing
before running it; it is one Python file with no dependencies.

```bash
python3 x2shell_check.py            # human-readable
python3 x2shell_check.py --json     # machine-readable
python3 x2shell_check.py --php-ini-file phpinfo.txt --brotli-version "1.2.0"
```

Exit code 1 if any checked version falls in a vulnerable range, else 0.

## What the results mean

- `VULNERABLE by version` - the detected version is below the vendor-fixed
  release. Update. For distro/LTS packages (Ubuntu, Debian, RHEL...), vendors
  backport fixes **without changing the version number**, so also check your
  vendor changelog for the CVE IDs before concluding either way.
- `patched by version` - the detected version is at or above the fixed release.
- `exposure reduced` / `mitigation NOT applied` - partial mitigations the PHP
  project lists (e.g. `memory_limit=-1`, `session.upload_progress.enabled=0`).
  These reduce specific attack paths only; **they do not make an unpatched
  install safe.** PHP's advisory: "There are no complete mitigations, updating
  is the only safe choice."
- `not detected` - that runtime was not found here. Absence is not proof of
  safety: software can embed a private copy of Brotli (static binaries,
  containers, vendored extensions) that inventory like this cannot see.

## Fixed versions (verified against the sources below on 2026-10-27)

| Component | Affected | Fixed |
|---|---|---|
| PHP 8.5 | < 8.5.12 | 8.5.12 |
| PHP 8.4 | < 8.4.27 | 8.4.27 |
| PHP 8.3 | < 8.3.36 | 8.3.36 |
| PHP 8.2 | < 8.2.35 | 8.2.35 (EOL 2026-12-31) |
| PHP <= 8.1 | all | no upstream fix; vendor backports or upgrade |
| Node.js 22.x | < 22.23.4 | 22.23.4 |
| Node.js 24.x | < 24.22.1 | 24.22.1 |
| Node.js 26.x | < 26.12.1 | 26.12.1 |
| Node.js <= 20.x | all | end-of-life, no fix - move to 22+ |
| libbrotli | 1.0.3-<1.0.10, 1.1.0, 1.2.0 | 1.0.10 / 1.1.1 / 1.2.1 |
| Python Brotli | >= 1.0.3, < 1.2.1 | 1.2.1 |
| Python brotlicffi | >= 1.0.3, < 1.2.1.0 | 1.2.1.0 |

PHP on Windows: the PHP project shipped rebuilt `*-1` packages bundling Brotli
1.2.1 for CVE-2026-111497 (reachable via the cURL extension when automatic
decompression is enabled; disabled by default).

## Exposure notes (from the primary advisories)

- PHP2Shell: affects "all PHP installations serving web requests, including
  PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed"; PHP rates
  mod_php highest, with RCE demonstrated pre-application-code. CISA added both
  CVEs to its Known Exploited Vulnerabilities catalog on 2026-10-26.
- CVE-2026-111497: reached when a process decompresses attacker-controlled
  Brotli - an inbound `Content-Encoding: br` request body, or an outbound
  `fetch()`/HTTP client response. Node's advisory scopes its description to
  `node:zlib` on the 22/24/26 lines. Python `requests`/`httpx`/`aiohttp` reach
  it when the Brotli package is installed.

## Verification

`run_fixtures.py` runs 32 synthetic cases (fake php/node binaries and saved
`php -i` output) covering every fixed boundary, unsupported lines and both
mitigation states. Latest run: see `results/fixture-run.txt` (ALL PASS).
These fixtures validate the checker's version/config logic only. They do not
prove any real system vulnerable or safe, and this repository intentionally
contains no exploit or proof-of-concept payload.

## Review notes

Before publication the version logic was independently re-read against the php.net and nodejs.org pages (fixed versions and CVE IDs match). Fixes made: patched libbrotli 1.1.2 to 1.1.9 was reported as "review" (now patched), brotlicffi 1.2.1.0 was compared as a 3-part version and would have been reported vulnerable (now 4-part), Node majors newer than 26 are "review" instead of vulnerable, the PHP 8.6 note now matches the php.net text (8.6.0 RC4 has the fixes), and the PHP memory_limit and upload_progress checks are reported only as partial measures (memory_limit is skipped on a version already patched). The fixtures cover each of these.

## Sources (all fetched and quoted 2026-10-27)

- PHP advisory + releases: https://www.php.net/archive/2026.php
- PHP Foundation background: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- CISA alert (revised 2026-10-26, KEV): https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Node.js security releases: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- google/brotli security releases: https://github.com/google/brotli/releases
- Python package advisory: https://github.com/advisories/GHSA-9v8h-qqgm-4m35
- Alias mapping (Node2Shell/HTTP2Shell), JPCERT/CC: https://www.jpcert.or.jp/at/2026/at260034.html

License: deliberately unspecified. No license has been chosen for this code yet; the repository owner decides. Until then, default copyright applies. Use it to check systems you own or are authorized to assess.
