#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import json

class WGHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/keygen':
            priv = subprocess.check_output(['wg', 'genkey']).decode().strip()
            pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode()).decode().strip()
            self.send_json(200, {'privateKey': priv, 'publicKey': pub})

        elif self.path == '/status':
            try:
                raw = subprocess.check_output(
                    ['wg', 'show', 'wg0'], stderr=subprocess.STDOUT
                ).decode()
                connected = 'latest handshake' in raw
            except subprocess.CalledProcessError as e:
                raw = e.output.decode()
                connected = False
            except Exception as e:
                raw = str(e)
                connected = False
            self.send_json(200, {'connected': connected, 'raw': raw})

        else:
            self.send_json(404, {'error': 'not found'})


if __name__ == '__main__':
    print('[wg-api] Listening on :8080', flush=True)
    HTTPServer(('0.0.0.0', 8080), WGHandler).serve_forever()
