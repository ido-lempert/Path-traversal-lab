import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'x2shell_check.py')
BIN = os.path.join(HERE, 'bin')

def run_case(name, php_version=None, node_version=None, ini=None, brotli=None, pipb=None, pipc=None, expect=()):
    env = dict(os.environ)
    env['PATH'] = BIN + os.pathsep + env['PATH']
    if php_version: env['FAKE_PHP_VERSION'] = php_version
    if node_version: env['FAKE_NODE_VERSION'] = node_version
    if ini: env['FAKE_PHP_INI'] = os.path.join(HERE, 'fixtures', ini)
    cmd = [sys.executable, SCRIPT, '--json']
    if brotli: cmd += ['--brotli-version', brotli]
    if pipb: cmd += ['--pip-brotli-version', pipb]
    if pipc: cmd += ['--pip-brotlicffi-version', pipc]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    data = json.loads(p.stdout)
    statuses = [c['status'] for r in data['results'] for c in r['checks']]
    failures = []
    for frag, want in expect:
        if not any(frag in s and want in s for s in statuses):
            failures.append('missing: %s -> %s' % (frag, want))
    ok = not failures
    print(('PASS' if ok else 'FAIL'), name, '|', p.returncode, '|', '; '.join(statuses))
    for f in failures: print('   ', f)
    return ok

cases = [
    ('php 8.3.36 patched', dict(php_version='8.3.36'), [('patched by version','patched')]),
    ('php 8.3.20 vulnerable', dict(php_version='8.3.20'), [('VULNERABLE by version','VULNERABLE')]),
    ('php 8.1.5 unsupported', dict(php_version='8.1.5'), [('VULNERABLE unless vendor backport','VULNERABLE')]),
    ('php 8.5.12 patched', dict(php_version='8.5.12'), [('patched by version','patched')]),
    ('php 8.5.11 vulnerable', dict(php_version='8.5.11'), [('VULNERABLE by version','VULNERABLE')]),
    ('php 8.2.34 vulnerable', dict(php_version='8.2.34'), [('VULNERABLE by version','VULNERABLE')]),
    ('php 8.2.35 patched', dict(php_version='8.2.35'), [('patched by version','patched')]),
    ('node 24.22.1 patched', dict(node_version='24.22.1'), [('patched by version','patched')]),
    ('node 24.22.0 vulnerable', dict(node_version='24.22.0'), [('VULNERABLE by version','VULNERABLE')]),
    ('node 22.23.4 patched', dict(node_version='22.23.4'), [('patched by version','patched')]),
    ('node 20.9.0 unsupported', dict(node_version='20.9.0'), [('VULNERABLE / unsupported','VULNERABLE')]),
    ('brotli 1.2.0 vulnerable', dict(brotli='brotli 1.2.0'), [('VULNERABLE by version','VULNERABLE')]),
    ('brotli 1.2.1 patched', dict(brotli='brotli 1.2.1'), [('patched by version','patched')]),
    ('brotli 1.0.5 vulnerable', dict(brotli='brotli 1.0.5'), [('VULNERABLE by version','VULNERABLE')]),
    ('brotli 1.0.10 patched', dict(brotli='brotli 1.0.10'), [('patched by version','patched')]),
    ('brotli 1.1.0 vulnerable', dict(brotli='1.1.0'), [('VULNERABLE by version','VULNERABLE')]),
    ('brotli 1.1.1 patched', dict(brotli='1.1.1'), [('patched by version','patched')]),
    ('ini unmitigated on a VULNERABLE version', dict(php_version='8.3.20', ini='ini-unmitigated.txt'), [('mitigation NOT applied','mitigation NOT applied'),('VULNERABLE by version','VULNERABLE')]),
    ('ini mitigated on a VULNERABLE version is still vulnerable', dict(php_version='8.3.20', ini='ini-mitigated.txt'), [('exposure reduced','exposure reduced'),('VULNERABLE by version','VULNERABLE')]),
    ('patched php, upload_progress still on (php.net 10-26 advice)', dict(php_version='8.3.36', ini='ini-unmitigated.txt'), [('mitigation NOT applied','mitigation NOT applied')]),
    ('patched php, upload_progress off', dict(php_version='8.3.36', ini='ini-mitigated.txt'), [('exposure reduced','exposure reduced')]),
    ('php 8.6.0 line needs review', dict(php_version='8.6.0'), [('review','review')]),
    ('node 28.0.0 newer than advisory lines: review', dict(node_version='28.0.0'), [('review','review')]),
    ('brotli 1.1.2 patched (above 1.1.1)', dict(brotli='1.1.2'), [('patched by version','patched')]),
    ('brotli 1.0.2 below affected range: review', dict(brotli='1.0.2'), [('review','review')]),
    ('brotli 1.0.9 vulnerable', dict(brotli='1.0.9'), [('VULNERABLE by version','VULNERABLE')]),
    ('pip Brotli 1.2.0 vulnerable', dict(pipb='1.2.0'), [('VULNERABLE by version','VULNERABLE')]),
    ('pip Brotli 1.2.1 patched', dict(pipb='1.2.1'), [('patched by version','patched')]),
    ('pip brotlicffi 1.2.0.0 vulnerable', dict(pipc='1.2.0.0'), [('VULNERABLE by version','VULNERABLE')]),
    ('pip brotlicffi 1.2.1.0 patched', dict(pipc='1.2.1.0'), [('patched by version','patched')]),
    ('pip brotlicffi 1.2.1.1 patched', dict(pipc='1.2.1.1'), [('patched by version','patched')]),
]
allok = True
for name, kw, expect in cases:
    allok &= run_case(name, expect=expect, **kw)
print('ALL PASS' if allok else 'FAILURES PRESENT')
sys.exit(0 if allok else 1)
