# Source provenance (all pages fetched 2026-10-27 ~17:50-17:52 IST, HTTP fetch OK)

## 1. PHP project - 2026 news archive (PRIMARY for PHP scope/fixes)
URL: https://www.php.net/archive/2026.php
Title: "PHP: News Archive - 2026"
Decisive excerpts (verbatim):
- "PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 fix two critical vulnerabilities that can allow unauthenticated remote code execution."
- "Who is at risk: all PHP installations serving web requests, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. We consider the risk highest for mod_php, with a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs."
- "RCE via OOM corruption, CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)" / "RCE via stale global state, CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)"
- "There are no complete mitigations, updating is the only safe choice."
- "PHP 8.1 and older no longer receive updates from the PHP project. Some distributions and LTS vendors provide backported fixes... the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1."
- Partial mitigations listed: memory_limit=-1 / low post_max_size / cgroup limits (CVE-2026-109618); session.upload_progress.enabled=0, PHP 8.5 fatal_error_backtraces=0 (CVE-2026-109619). All labeled as not making an installation safe.
- Windows: "updated Windows builds: PHP 8.5.12-1, 8.4.27-1, 8.3.36-1 and 8.2.35-1. These builds include Brotli 1.2.1, which fixes CVE-2026-111497... reachable through the cURL extension when automatic HTTP response decompression is enabled. This is disabled by default."
- PHP 8.2 EOL: "PHP 8.2 reaches end of life on 31 December 2026."
- Note: php.net uses only CVE/GHSA IDs, never the name "PHP2Shell".

## 2. CISA alert (PRIMARY government; name "php2shell" attributed here)
URL: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
Title: "Critical Vulnerabilities in PHP Require Immediate Patching" (Last Revised October 26, 2026)
Decisive excerpts:
- 'vulnerabilities in PHP, CVE-2026-109618 and CVE-2026-109619. These vulnerabilities, known as "php2shell," allow for unauthenticated remote code execution in PHP.'
- "CISA added CVE-2026-109618 and CVE-2026-109619 to its KEV Catalog on Oct. 26, 2026." (Known Exploited Vulnerabilities - active exploitation confirmed)
- "Apply the patch immediately, prioritizing internet-facing systems. Organizations that cannot update immediately, or that continue to use PHP 8.1 or earlier unsupported versions, should take PHP-based systems offline until they can be patched."

## 3. PHP Foundation (PRIMARY ecosystem account; impact detail)
URL: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
Title: "Today's PHP Security Release, and How We're Strengthening PHP Security" (Oct 21, 2026)
Decisive excerpts:
- CVE-2026-109618: "On Apache with mod_php, an unauthenticated request can trigger this before any application code runs, and full remote code execution was demonstrated with default settings. Remote code execution was also confirmed on PHP-FPM through application-level code paths."
- CVE-2026-109619: "A use-after-free and worker crash were confirmed, and the reporter demonstrated remote code execution against a real-world application running on Apache with mod_php."
- Actual CVSS v4.0 score is 9.2 (pre-disclosure rumor of 10.0 was wrong).

## 4. Node.js project - October 21, 2026 Security Releases (PRIMARY for Node/Brotli-in-Node)
URL: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
Title: "Wednesday, October 21, 2026 Security Releases"
Decisive excerpts:
- "Node.js Brotli decoder out-of-bounds write permits remote code execution (CVE-2026-111497) - (high)" [Node's own rating: HIGH; NVD/GHSA score 9.2 CRITICAL under CVSS 4.0 - preserve the distinction]
- "An attacker who can supply Brotli data that an application decompresses with node:zlib can corrupt process memory, which can lead to a crash, disclosure of process memory, or remote code execution."
- "This vulnerability affects Node.js 26.x, 24.x, and 22.x." Fixed in v22.23.4 / v24.22.1 / v26.12.1.
- "End-of-Life versions are always affected" - Node 20.x and older get no fix.

## 5. google/brotli releases (PRIMARY for upstream library)
URL: https://github.com/google/brotli/releases
Title: "Releases - google/brotli"
Decisive excerpts: v1.2.1, v1.1.1, v1.0.10 (all 2026-10-21) each carry "SECURITY - CVE-2026-111497: out-of-bounds write permits remote code execution".

## 6. GitHub Advisory Database GHSA-9v8h-qqgm-4m35 (reviewed advisory; Python packages + severity)
URL: https://github.com/advisories/GHSA-9v8h-qqgm-4m35
Title: 'Brotli: Out-of-bounds write in the Brotli decoder ("Node2Shell") also affects the PyPI Brotli package' (published Oct 22, 2026, reviewed Oct 23)
Decisive facts: pip brotli affected >= 1.0.3, < 1.2.1 (patched 1.2.1); brotlicffi >= 1.0.3, < 1.2.1.0 (patched 1.2.1.0). Severity Critical 9.2 CVSS 4.0 (AV Network, AC Low, PR None, UI None; C/I/A High).

## 7. JPCERT/CC notice JPCERT-AT-2026-0034 (government CERT; alias mapping)
URL: https://www.jpcert.or.jp/at/2026/at260034.html (2026-10-26)
Decisive facts: CVE-2026-111497 was called "Node2Shell" after Node.js's disclosure and "HTTP2Shell" because the root cause is the Brotli C implementation used across HTTP software. Affected: Brotli >= 1.2.0 < 1.2.1, >= 1.1.0 < 1.1.1, >= 1.0.3 < 1.0.10. Google provides no mitigation; update only.

## 8. Hacker News discussion (COMMUNITY, untrusted; not advisory)
URL: https://news.ycombinator.com/item?id=50167754
Title: "Tell HN: 2x PHP RCE CVEs with CVSS 10.0 Incoming"
Status: pre-disclosure rumor; its CVSS 10.0 claim was wrong (actual 9.2 per PHP Foundation). Used only as the HN signal the user watches, never as a technical source.

## Secondary guides (leads only, not relied on for facts)
- https://docs.dollardeploy.com/blog/node2shell-http2shell-and-php-vulnerabilities/ (deployment instructions for that platform)
- https://www.fastly.com/blog/how-fastly-detected-and-built-a-coordinated-response-to-php2shell (detection engineering observations)
- Imperva lab RCE demonstration reported by The Hacker News: https://thehackernews.com/2026/10/researchers-demonstrate-node2shell-rce.html (lab-only, single build/arch, no in-the-wild exploitation as of Oct 22; contrast with PHP2Shell which IS in CISA KEV)

## Validation status of this package
Checker logic was validated ONLY against synthetic fixtures (fake php/node
binaries, saved `php -i` text, manually supplied version strings): 19/19 cases
pass in results/fixture-run.txt. No exploit was reproduced, no real system was
scanned, and no proof-of-concept payload is included. Version/config checks
cannot detect distro backports (fixed code under an old version number) or
statically embedded copies of Brotli; the tool output and README say so.
