#!/usr/bin/env python3
"""
VCNext Production Licensing & Authority Server
Domain: vc.huxa.xyz (TLS port 443 via Let's Encrypt)
Authority: RSA-3072 (server_private_key.pem)
"""

import sys
import os
import json
import uuid
import time
import ssl
import base64
import hashlib
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "server_private_key.pem")
DB_PATH = os.path.join(BASE_DIR, "licenses.db")

APP_TEXT_DIGEST = "4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2"
CAMERA_TEXT_DIGEST = "d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943"

REQUIRED_CAPABILITIES = [
    "camera.fake-frame",
    "camera.obs",
    "media.import",
    "camera.controls",
    "camera.color-sync"
]

# Load RSA-3072 Private Key
with open(KEY_PATH, "rb") as f:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        device_id TEXT PRIMARY KEY,
        username TEXT,
        thumbprint TEXT,
        access_token TEXT,
        renewal_token TEXT,
        current_nonce TEXT,
        expires_at INTEGER,
        created_at INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        challenge_id TEXT PRIMARY KEY,
        device_id TEXT,
        username TEXT,
        thumbprint TEXT,
        nonce TEXT,
        expires_at INTEGER
    )
    """)
    conn.commit()
    conn.close()

init_db()

def sign_json_payload(payload: dict) -> str:
    signed_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    sig = SERVER_PRIVATE_KEY.sign(
        signed_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode('ascii')

class VCNextRequestHandler(BaseHTTPRequestHandler):

    def _send_json(self, status_code: int, data: dict):
        response_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_HEAD(self):
        # The app sends a HEAD request to / upon becoming active
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]
        # Download deb trực tiếp từ trình duyệt Safari hoặc Sileo
        if path in ["/VCNext-custom-roothide.deb", "/download"]:
            deb_path = os.path.join(BASE_DIR, "VCNext-custom-roothide.deb")
            if os.path.exists(deb_path):
                with open(deb_path, "rb") as f:
                    deb_data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.debian.binary-package")
                self.send_header("Content-Disposition", 'attachment; filename="VCNext-custom-roothide.deb"')
                self.send_header("Content-Length", str(len(deb_data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(deb_data)
                return
        # Decoy routes
        if path in ["/api/v1/bootstrap", "/api/v1/config", "/api/v1/events", "/api/v2/session"]:
            return self._send_json(200, {})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            body = {}

        path = self.path.split('?')[0]
        device_id = self.headers.get("X-Device-ID", body.get("device_id", "4A9F21B3-8D12-4E56-91A2-F02BCDE91044"))

        # 1. Decoy routes
        if path in ["/api/v1/bootstrap", "/api/v1/config", "/api/v1/events", "/api/v2/session"]:
            return self._send_json(200, {})

        now = int(time.time())

        # 2. POST /api/v2/auth/challenge
        if path == "/api/v2/auth/challenge":
            username = (body.get("username") or "admin").lower()
            pubkey_b64 = body.get("device_public_key", "")
            if pubkey_b64:
                try:
                    pubkey_raw = base64.b64decode(pubkey_b64)
                    thumbprint = hashlib.sha256(pubkey_raw).hexdigest()
                except Exception:
                    thumbprint = "273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572"
            else:
                thumbprint = "273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572"

            challenge_id = str(uuid.uuid4())
            nonce = hashlib.sha256(uuid.uuid4().bytes + str(time.time()).encode()).hexdigest()

            challenge_payload = {
                "version": 2,
                "purpose": "auth.challenge",
                "issuer": "vcnext-main",
                "audience": "vcnext-ios",
                "username": username,
                "device_id": str(device_id),
                "device_key_thumbprint": str(thumbprint),
                "build": "37",
                "binary_digest": APP_TEXT_DIGEST,
                "challenge_id": challenge_id,
                "nonce": nonce,
                "issued_at": now,
                "expires_at": now + 90
            }

            sig_b64 = sign_json_payload(challenge_payload)

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO challenges VALUES (?, ?, ?, ?, ?, ?)",
                        (challenge_id, device_id, username, thumbprint, nonce, now + 120))
            conn.commit()
            conn.close()

            print(f"[+] Challenge issued for {username} ({device_id}) -> id={challenge_id}")
            return self._send_json(200, {
                "challenge": challenge_payload,
                "signature": sig_b64
            })

        # 3. POST /api/v2/auth/login or /api/v2/auth/renew or /api/v2/auth/heartbeat
        elif path in ["/api/v2/auth/login", "/api/v2/auth/renew", "/api/v2/auth/heartbeat"]:
            username = (body.get("username") or "admin").lower()

            # Retrieve thumbprint from challenge or existing session
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            challenge_id = body.get("challenge_id", "")
            cur.execute("SELECT thumbprint FROM challenges WHERE challenge_id = ?", (challenge_id,))
            row = cur.fetchone()
            if row:
                thumbprint = row[0]
            else:
                cur.execute("SELECT thumbprint FROM sessions WHERE device_id = ?", (device_id,))
                s_row = cur.fetchone()
                thumbprint = s_row[0] if s_row else "273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572"

            access_token = "at_" + uuid.uuid4().hex + uuid.uuid4().hex
            renewal_token = "rn_" + uuid.uuid4().hex + uuid.uuid4().hex
            next_nonce = hashlib.sha256(uuid.uuid4().bytes).hexdigest()

            # Construct lease payload with SHA256 bindings of the generated tokens
            lease_payload = {
                "version": 2,
                "purpose": "capability.lease",
                "issuer": "vcnext-main",
                "audience": "vcnext-ios",
                "build": "37",
                "device_id": str(device_id),
                "device_key_thumbprint": str(thumbprint),
                "binary_digest": CAMERA_TEXT_DIGEST,
                "session_binding": hashlib.sha256(access_token.encode('utf-8')).hexdigest(),
                "renewal_binding": hashlib.sha256(renewal_token.encode('utf-8')).hexdigest(),
                "next_nonce_hash": hashlib.sha256(next_nonce.encode('utf-8')).hexdigest(),
                "capabilities": REQUIRED_CAPABILITIES,
                "issued_at": now,
                "expires_at": now + 90
            }

            lease_sig = sign_json_payload(lease_payload)

            cur.execute("""
            INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_id, username, thumbprint, access_token, renewal_token, next_nonce, now + 315360000, now))
            conn.commit()
            conn.close()

            res = {
                "access_token": access_token,
                "renewal_token": renewal_token,
                "next_nonce": next_nonce,
                "user": {
                    "username": username,
                    "active_devices": 1,
                    "max_devices": 1,
                    "expires_at": now + 315360000
                },
                "lease": lease_payload,
                "lease_signature": lease_sig
            }
            print(f"[+] {path} success for {username} ({device_id}) -> lease granted (TTL 90s)")
            return self._send_json(200, res)

        # 4. POST /api/v2/auth/logout
        elif path == "/api/v2/auth/logout":
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
            conn.commit()
            conn.close()
            print(f"[+] Logged out {device_id}")
            return self._send_json(200, {"status": "revoked"})

        else:
            return self._send_json(404, {"error": "Not Found", "path": path})

def run():
    server_address = ("0.0.0.0", 443)
    httpd = HTTPServer(server_address, VCNextRequestHandler)

    cert_path = "/etc/letsencrypt/live/vc.huxa.xyz/fullchain.pem"
    priv_path = "/etc/letsencrypt/live/vc.huxa.xyz/privkey.pem"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=priv_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("[+] VCNext Licensing Authority is LIVE on https://vc.huxa.xyz:443")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[*] Server stopped.")

if __name__ == "__main__":
    run()
