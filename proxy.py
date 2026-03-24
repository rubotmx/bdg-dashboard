#!/usr/bin/env python3
"""
Servidor proxy local para bdg-dashboard.
Sirve archivos estáticos en / y hace proxy a Shopify Admin API en /api/shopify.
Uso: python3 proxy.py
"""
import http.server
import os
import urllib.request
import urllib.error
import urllib.parse

PORT = int(os.environ.get("PORT", 3000))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
SHOPIFY_STORE = os.environ.get("SHOPIFY_STORE", "baladigalamx.myshopify.com")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN", "")

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/shopify"):
            self._proxy_shopify()
        else:
            super().do_GET()

    def _proxy_shopify(self):
        # /api/shopify?title=PENNY+CLOGS  →  Shopify Admin API products
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        title = params.get("title", [""])[0]
        url = (
            f"https://{SHOPIFY_STORE}/admin/api/2024-01/products.json"
            f"?title={urllib.parse.quote(title)}&fields=id,title,variants&limit=10"
        )
        try:
            req = urllib.request.Request(url, headers={
                "X-Shopify-Access-Token": SHOPIFY_TOKEN,
                "Content-Type": "application/json"
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._cors()
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(data)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        print(f"[bdg-proxy] {fmt % args}")

if __name__ == "__main__":
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    with http.server.ThreadingHTTPServer(("", PORT), ProxyHandler) as httpd:
        print(f"BDG Dashboard corriendo en http://localhost:{PORT}")
        httpd.serve_forever()
