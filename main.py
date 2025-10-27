from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
import time

HOST_NAME = "localhost"
SERVER_PORT = 8080
DB_FILENAME = "totally_not_my_privateKeys.db"

# --- Utilities ---

def int_to_base64(value: int) -> str:
    """Convert an integer to a Base64URL-encoded string without padding."""
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def now_epoch() -> int:
    """Return current time as integer seconds since epoch."""
    return int(time.time())


# --- Database helpers ---

def get_db_connection():
    """Open (and create if needed) the SQLite DB, return connection."""
    conn = sqlite3.connect(DB_FILENAME)
    # Ensure rows are returned as tuples
    return conn


def init_db_and_seed_if_needed():
    """
    Ensure DB and table exist. If there are no keys present,
    generate and insert one expired and one valid key (as required).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    # Create table with required schema
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()

    # Check if table already has keys
    cur.execute("SELECT COUNT(*) FROM keys")
    (count,) = cur.fetchone()
    if count == 0:
        # Generate and insert two keys: one expired, one valid
        # Expired key: exp <= now
        # Valid key: exp > now (1 hour ahead)
        for is_expired in (True, False):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            exp_ts = now_epoch() - 3600 if is_expired else now_epoch() + 3600
            # Use parameterized query to avoid SQL injection
            cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_ts))
        conn.commit()

    conn.close()


def fetch_key_from_db(expired: bool = False):
    """
    Fetch a single key (private key PEM and its kid) from DB.
    If expired==False: pick a non-expired key (exp > now).
    If expired==True: pick an expired key (exp <= now).
    Returns tuple (kid (int), pem_bytes (bytes), exp (int)) or None.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    if expired:
        cur.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1", (now_epoch(),))
    else:
        cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1", (now_epoch(),))
    row = cur.fetchone()
    conn.close()
    if row:
        return row  # (kid, key_blob, exp)
    return None


def fetch_all_valid_keys():
    """
    Fetch all non-expired keys from DB.
    Returns list of tuples (kid (int), pem_bytes (bytes), exp (int)).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid", (now_epoch(),))
    rows = cur.fetchall()
    conn.close()
    return rows


# Initialize DB (create file and seed keys if needed)
init_db_and_seed_if_needed()


# --- HTTP server handler ---

class MyServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to reduce noise;
        return

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Check for 'expired' query parameter presence
            expired_flag = "expired" in params

            # Fetch the appropriate key from the DB
            row = fetch_key_from_db(expired=expired_flag)
            if not row:
                # No matching key found
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No matching key found in DB")
                return

            kid, pem_blob, key_exp = row

            # Load private key from PEM bytes
            private_key = serialization.load_pem_private_key(pem_blob, password=None, backend=default_backend())

            # Build token payload;
            exp_time = int(datetime.datetime.utcnow().timestamp()) + 3600  # token expires in 1 hour
            if expired_flag:
                # If requesting an expired-signed token, put an already-expired exp claim
                exp_time = int(datetime.datetime.utcnow().timestamp()) - 3600

            token_payload = {
                "user": "username",
                "exp": exp_time
            }

            headers = {"kid": str(kid)}

            # Sign JWT using RS256 and the private key PEM
            # jwt.encode accepts PEM as bytes or str
            encoded_jwt = jwt.encode(token_payload, pem_blob, algorithm="RS256", headers=headers)

            # Return token
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            # Ensure bytes
            if isinstance(encoded_jwt, str):
                encoded_jwt = encoded_jwt.encode("utf-8")
            self.wfile.write(encoded_jwt)
            return

        # Unsupported POST route
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            # Read all non-expired private keys from DB and build JWKS
            rows = fetch_all_valid_keys()
            jwk_list = []
            for kid, pem_blob, key_exp in rows:
                # Load private key and get public numbers
                priv = serialization.load_pem_private_key(pem_blob, password=None, backend=default_backend())
                pub = priv.public_key()
                numbers = pub.public_numbers()
                n_b64 = int_to_base64(numbers.n)
                e_b64 = int_to_base64(numbers.e)
                jwk = {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": str(kid),
                    "n": n_b64,
                    "e": e_b64,
                }
                jwk_list.append(jwk)

            keys_obj = {"keys": jwk_list}
            payload = json.dumps(keys_obj)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return

        # Unsupported GET route
        self.send_response(405)
        self.end_headers()


# --- Run server ---
if __name__ == "__main__":
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    print(f"Server starting on http://{HOST_NAME}:{SERVER_PORT} ...")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down server (KeyboardInterrupt)")
    finally:
        webServer.server_close()

