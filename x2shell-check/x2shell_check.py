#!/usr/bin/env python3
"""
x2shell-check - inventory-only exposure checker for PHP2Shell (CVE-2026-109618,
CVE-2026-109619) and the Brotli decoder flaw CVE-2026-111497 (aka Node2Shell /
HTTP2Shell / Broccoli2Shell).

DEFENSIVE USE ONLY. This script:
  * inspects ONLY the local machine it is run on, or files you point it at;
  * sends no network requests and contains no exploit code;
  * reports version- and configuration-based exposure from public advisories.

A "patched" result means the detected version matches a vendor-fixed release.
A "not detected" result does NOT prove a system is safe: distro/LTS backports
can fix an old version number without changing it, and software can embed a
private copy of a library that simple inventory cannot see.

Sources (verify before relying; see README):
  https://www.php.net/archive/2026.php
  https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
  https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
  https://github.com/google/brotli/releases
  https://github.com/advisories/GHSA-9v8h-qqgm-4m35
"""
import argparse, json, os, re, subprocess, sys

def parse_version(s, parts=3):
    m = re.search(r'(\d+)' + r'\.(\d+)' * (parts - 1), s or '')
    return tuple(int(x) for x in m.groups()) if m else None

def at_least(v, fixed):
    return v is not None and v >= fixed

# PHP fixed-in map: (major, minor) -> fixed patch version, from php.net 2026-10-21 advisory
PHP_FIXED = {(8,5):(8,5,12),(8,4):(8,4,27),(8,3):(8,3,36),(8,2):(8,2,35)}
# Node fixed-in map: major -> fixed version, from nodejs.org 2026-10-21 advisory
NODE_FIXED = {22:(22,23,4),24:(24,22,1),26:(26,12,1)}
BROTLI_RANGES = [((1,0,3),(1,0,10)),((1,1,0),(1,1,1)),((1,2,0),(1,2,1))]  # (affected_from, fixed_in)

def in_range(v, lo, hi):
    return v is not None and lo <= v < hi

def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (out.stdout + out.stderr).strip()
    except Exception:
        return ''

def check_php(ini_text=None, binary='php'):
    r = {'name':'php2shell','cves':['CVE-2026-109618','CVE-2026-109619'],'checks':[]}
    raw = run([binary,'-v'])
    v = parse_version(raw)
    if v is None:
        r['checks'].append({'check':'php binary','status':'not detected','detail':'php not found in PATH'})
    else:
        mm = (v[0],v[1])
        if mm in PHP_FIXED:
            fixed = PHP_FIXED[mm]
            st = 'patched by version' if at_least(v,fixed) else 'VULNERABLE by version'
            r['checks'].append({'check':'php version','status':st,
                'detail':'PHP %d.%d.%d; fixed in %s (php.net 2026-10-21). Distro backports may differ - verify vendor changelog for CVE-2026-109618/109619.'%(v[0],v[1],v[2],'.'.join(map(str,fixed)))})
        elif (v[0],v[1]) >= (8,6):
            r['checks'].append({'check':'php version','status':'review',
                'detail':'PHP %d.%d.%d is a newer line than the fixed 8.2-8.5 releases. php.net (2026-10-26 archive) says 8.6.0 RC4 contains the fixes; earlier 8.6 builds do not. Check the exact build.'%v})
        else:
            r['checks'].append({'check':'php version','status':'VULNERABLE unless vendor backport',
                'detail':'PHP %d.%d.%d is at/below the last fixed minor line (8.2.35) or unsupported (<=8.1 has no upstream fix). Check your vendor for backported patches.'%v})
    php_patched = any(c['status'] == 'patched by version' for c in r['checks'])
    ini = ini_text
    if ini is None and v is not None:
        ini = run([binary,'-i'])
    if ini:
        ml = re.search(r'memory_limit\s*=>\s*([^\s]+)', ini) or re.search(r'(?im)^\s*memory_limit\s*=\s*(\S+)', ini)
        up = re.search(r'session\.upload_progress\.enabled\s*=>\s*([^\s]+)', ini) or re.search(r'(?im)^\s*session\.upload_progress\.enabled\s*=\s*(\S+)', ini)
        if ml and not php_patched:
            val = ml.group(1)
            st = 'exposure reduced' if val == '-1' else 'mitigation NOT applied'
            r['checks'].append({'check':'php memory_limit','status':st,
                'detail':'memory_limit=%s. php.net lists memory_limit=-1 as a partial measure for CVE-2026-109618 only (an underlying allocation failure can still reach the path; updating is the only complete fix). Removing the memory limit has availability costs; this tool does not recommend it over updating.'%val})
        if up:
            val = up.group(1)
            off = val.lower() in ('off','0','')
            st = 'exposure reduced' if off else 'mitigation NOT applied'
            r['checks'].append({'check':'php session.upload_progress.enabled','status':st,
                'detail':'session.upload_progress.enabled=%s. php.net lists =0 as a partial measure for one confirmed path of CVE-2026-109619; it does not make an unpatched install safe. The php.net 2026-10-26 news item also suggests setting it to 0 on updated builds until the next bugfix release.'%val})
    return r

def check_node():
    r = {'name':'node2shell (brotli in node:zlib)','cves':['CVE-2026-111497'],'checks':[]}
    raw = run(['node','-v'])
    v = parse_version(raw)
    if v is None:
        r['checks'].append({'check':'node binary','status':'not detected','detail':'node not found in PATH'})
        return r
    fixed = NODE_FIXED.get(v[0])
    if fixed:
        st = 'patched by version' if at_least(v,fixed) else 'VULNERABLE by version'
        r['checks'].append({'check':'node version','status':st,
            'detail':'Node %d.%d.%d; fixed in %s (nodejs.org 2026-10-21, rated HIGH by Node).'% (v[0],v[1],v[2],'.'.join(map(str,fixed)))})
    elif v[0] > 26:
        r['checks'].append({'check':'node version','status':'review',
            'detail':'Node %d.%d.%d is newer than the lines named in the advisory (22/24/26). Check the nodejs.org advisory for this line.'%v})
    else:
        r['checks'].append({'check':'node version','status':'VULNERABLE / unsupported',
            'detail':'Node %d.%d.%d: only 22.x/24.x/26.x received the CVE-2026-111497 fix; older lines are end-of-life.'%v})
    return r

def check_brotli_pkg(version_text, source):
    r = {'name':'brotli library','cves':['CVE-2026-111497'],'checks':[]}
    v = parse_version(version_text)
    if v is None:
        r['checks'].append({'check':'brotli version','status':'not detected','detail':'no brotli version found via %s'%source})
        return r
    for lo,hi in BROTLI_RANGES:
        if in_range(v,lo,hi):
            r['checks'].append({'check':'brotli version (%s)'%source,'status':'VULNERABLE by version',
                'detail':'brotli %d.%d.%d is in the affected range %s - %s; fixed in %s (google/brotli releases).'%(
                    v[0],v[1],v[2],'.'.join(map(str,lo)),'.'.join(map(str,hi)),'.'.join(map(str,hi)))})
            return r
    patched = v >= (1,2,1) or (1,1,1) <= v < (1,2,0) or (1,0,10) <= v < (1,1,0)
    st = 'patched by version' if patched else 'review'
    r['checks'].append({'check':'brotli version (%s)'%source,'status':st,
        'detail':'brotli %d.%d.%d. Fixed releases are 1.0.10 / 1.1.1 / 1.2.1 (google/brotli releases, 2026-10-21).'%v})
    return r

def check_python(manual=None):
    r = {'name':'python brotli packages (HTTP2Shell)','cves':['CVE-2026-111497'],'checks':[]}
    manual = manual or {}
    for pkg, fixed in (('Brotli',(1,2,1)),('brotlicffi',(1,2,1,0))):
        out = ('Version: ' + manual[pkg]) if pkg in manual else run([sys.executable,'-m','pip','show',pkg])
        m = re.search(r'(?im)^Version:\s*(\S+)', out)
        if not m:
            r['checks'].append({'check':'pip %s'%pkg,'status':'not detected','detail':'%s not installed for this interpreter'%pkg})
            continue
        v = parse_version(m.group(1), len(fixed))
        if v is None:
            r['checks'].append({'check':'pip %s'%pkg,'status':'review','detail':'could not parse version %s'%m.group(1)}); continue
        # affected: >= 1.0.3 and below the fixed version (GHSA-9v8h-qqgm-4m35)
        affected = v >= (1,0,3) and v < fixed
        st = 'VULNERABLE by version' if affected else ('patched by version' if v >= fixed else 'review')
        r['checks'].append({'check':'pip %s'%pkg,'status':st,
            'detail':'%s %s; fixed in %s (GHSA-9v8h-qqgm-4m35).'%(pkg,m.group(1),'.'.join(map(str,fixed)))})
    return r

def main():
    ap = argparse.ArgumentParser(description='Local-only exposure checker for PHP2Shell / Node2Shell / HTTP2Shell. No network, no exploit code.')
    ap.add_argument('--php-ini-file', help='parse this php -i output instead of invoking php')
    ap.add_argument('--brotli-version', help='manually supplied libbrotli version string to evaluate')
    ap.add_argument('--pip-brotli-version', help='manually supplied PyPI Brotli version to evaluate')
    ap.add_argument('--pip-brotlicffi-version', help='manually supplied PyPI brotlicffi version to evaluate')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    ini_text = open(args.php_ini_file).read() if args.php_ini_file else None
    manual = {}
    if args.pip_brotli_version: manual['Brotli'] = args.pip_brotli_version
    if args.pip_brotlicffi_version: manual['brotlicffi'] = args.pip_brotlicffi_version
    results = [check_php(ini_text=ini_text), check_node(), check_python(manual)]
    if args.brotli_version:
        results.append(check_brotli_pkg(args.brotli_version,'manual'))
    else:
        out = run(['brotli','--version'])
        if out:
            results.append(check_brotli_pkg(out,'brotli CLI'))
    overall = 'review'
    if any(c['status'].startswith('VULNERABLE') for r in results for c in r['checks']):
        overall = 'VULNERABLE by version (see details; verify vendor backports before concluding either way)'
    elif any(c['status'] in ('review','mitigation NOT applied') for r in results for c in r['checks']):
        overall = 'review needed'
    elif any(c['status'] in ('patched by version','exposure reduced') for r in results for c in r['checks']):
        overall = 'no vulnerable versions detected on this machine (not a guarantee; see caveats)'
    report = {'overall':overall,'results':results}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print('Overall:', overall)
        for r in results:
            print('\n[%s] %s'%(r['name'], ','.join(r['cves'])))
            for c in r['checks']:
                print('  - %s: %s'%(c['check'],c['status']))
                print('      %s'%c['detail'])
    sys.exit(1 if overall.startswith('VULNERABLE') else 0)

if __name__ == '__main__':
    main()
