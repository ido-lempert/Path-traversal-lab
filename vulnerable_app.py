"""A deliberately vulnerable file server for LOCAL learning only (binds to 127.0.0.1).
Run it on your own machine. Never expose it to a network."""
import http.server, os, urllib.parse

PUBLIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
FIXED = os.environ.get("FIXED") == "1"

def resolve(name: str) -> str:
    if FIXED:
        full = os.path.realpath(os.path.join(PUBLIC, name))
        if os.path.commonpath([full, os.path.realpath(PUBLIC)]) != os.path.realpath(PUBLIC):
            raise PermissionError(name)
        return full
    return os.path.join(PUBLIC, name)  # BUG: ".." in name escapes PUBLIC

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = urllib.parse.unquote(urllib.parse.urlparse(self.path).path.lstrip("/"))
        try:
            with open(resolve(name), "rb") as f:
                body = f.read()
            self.send_response(200)
        except PermissionError:
            body = b"forbidden"; self.send_response(403)
        except OSError:
            body = b"not found"; self.send_response(404)
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8765"))), H).serve_forever()
