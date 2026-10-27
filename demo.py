"""Starts the app twice (vulnerable, then fixed) on localhost and shows the difference."""
import os, subprocess, sys, time, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__))
def get(port, path):
    # http.client keeps ".." as written; urllib does too for a plain path
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}"); return r.status, r.read().decode().strip()
    except urllib.error.HTTPError as e: return e.code, e.read().decode().strip()
for fixed, port in ((False, 8765), (True, 8766)):
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "vulnerable_app.py")], env={**os.environ, "PORT": str(port), "FIXED": "1" if fixed else "0"})
    time.sleep(0.6)
    print("fixed" if fixed else "vulnerable", "| /hello.txt ->", get(port, "/hello.txt"))
    print("fixed" if fixed else "vulnerable", "| /../secret.txt ->", get(port, "/../secret.txt"))
    p.terminate(); p.wait()
