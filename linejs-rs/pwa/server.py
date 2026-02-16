#!/usr/bin/env python3
"""
Local dev server for LINEJS WASM PWA.
Serves static files and proxies API requests to LINE servers.
"""

import http.server
import socketserver
import urllib.request
import ssl
import sys

LINE_HOST = "legy.line-apps.com"
LINE_PATHS = ["/S4", "/SYNC4", "/acct/"]

PORT = 8080


class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        '.wasm': 'application/wasm',
        '.js': 'application/javascript',
        '.json': 'application/json',
    }

    def do_POST(self):
        # Check if this is a LINE API request
        is_line_api = any(self.path.startswith(p) for p in LINE_PATHS)
        if not is_line_api:
            self.send_error(404, "Not Found")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        target_url = f"https://{LINE_HOST}{self.path}"

        # Forward relevant headers
        forward_headers = {}
        for header in ['Content-Type', 'Accept', 'User-Agent',
                       'x-line-application', 'x-line-access',
                       'x-lal', 'x-lpv', 'x-lhm', 'x-lst']:
            val = self.headers.get(header)
            if val:
                forward_headers[header] = val

        forward_headers['Host'] = LINE_HOST

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                target_url,
                data=body,
                headers=forward_headers,
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=200, context=ctx) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                self.send_header('Content-Type', resp.getheader('Content-Type', 'application/x-thrift'))
                self.send_header('Content-Length', str(len(resp_body)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(resp_body)
        except Exception as e:
            error_msg = str(e).encode()
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(error_msg)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(error_msg)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def end_headers(self):
        if self.command == 'GET':
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('', PORT), ProxyHandler) as httpd:
        print(f"LINEJS PWA server at http://localhost:{PORT}")
        print(f"Proxying API requests to https://{LINE_HOST}")
        httpd.serve_forever()
