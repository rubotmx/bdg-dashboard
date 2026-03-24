#!/usr/bin/env python3
"""
BDG Dashboard — Proxy + Auth Server
Endpoints:
  POST /auth/login         — iniciar sesión
  POST /auth/logout        — cerrar sesión
  GET  /auth/me            — info de sesión activa
  GET  /admin/users        — listar usuarios (admin)
  POST /admin/users        — crear usuario (admin)
  PUT  /admin/users/<id>   — editar usuario (admin)
  DELETE /admin/users/<id> — eliminar usuario (admin)
  GET  /api/shopify        — proxy a Shopify Admin API (requiere sesión)
"""
import http.server
import os
import urllib.request
import urllib.error
import urllib.parse
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta

PORT         = int(os.environ.get("PORT", 3000))
DIRECTORY    = os.path.dirname(os.path.abspath(__file__))
SHOPIFY_STORE= os.environ.get("SHOPIFY_STORE", "baladigalamx.myshopify.com")
SHOPIFY_TOKEN= os.environ.get("SHOPIFY_TOKEN", "")
ADMIN_USER   = os.environ.get("ADMIN_USER", "rdelarosa@baladigala.com")
ADMIN_NAME   = os.environ.get("ADMIN_NAME", "Rubén De La Rosa")
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "4124958AR12h!")
DB_PATH      = os.environ.get("DB_PATH", os.path.join(DIRECTORY, "users.db"))

# ──────────────────────────────────────────────
# BASE DE DATOS
# ──────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    UNIQUE NOT NULL,
            name         TEXT    NOT NULL,
            password_hash TEXT   NOT NULL,
            salt         TEXT    NOT NULL,
            role         TEXT    NOT NULL DEFAULT 'viewer',
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT    PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            created_at TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    # Asegurar que el super admin siempre exista con las credenciales del env
    salt = "bdg_fixed_admin_salt_v2"
    pwd_hash = _hash(ADMIN_PASS, salt)
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USER,)).fetchone()
    if existing:
        conn.execute("UPDATE users SET password_hash=?, salt=?, name=?, role='admin', active=1 WHERE username=?",
                     (pwd_hash, salt, ADMIN_NAME, ADMIN_USER))
    else:
        conn.execute("INSERT INTO users (username, name, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,1,?)",
                     (ADMIN_USER, ADMIN_NAME, pwd_hash, salt, "admin", _now()))
    conn.commit()
    conn.close()
    print(f"[bdg-auth] DB: {DB_PATH}  |  {ADMIN_USER}")

def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()

def _now():
    return datetime.utcnow().isoformat()

def verify_session(token):
    if not token:
        return None
    conn = get_conn()
    row = conn.execute(
        """SELECT u.id, u.username, u.name, u.role
           FROM sessions s JOIN users u ON s.user_id = u.id
           WHERE s.token=? AND s.expires_at>? AND u.active=1""",
        (token, _now())
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ──────────────────────────────────────────────
# HANDLER
# ──────────────────────────────────────────────
class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    # ── CORS preflight ──
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── GET ──
    def do_GET(self):
        if self.path.startswith("/api/shopify"):
            user = verify_session(self._token())
            if not user:
                return self._json(401, {"error": "No autorizado"})
            self._proxy_shopify()
        elif self.path.startswith("/auth/me"):
            user = verify_session(self._token())
            self._json(200, user) if user else self._json(401, {"error": "Sin sesión"})
        elif self.path.startswith("/admin/users"):
            user = verify_session(self._token())
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Acceso denegado"})
            conn = get_conn()
            rows = conn.execute(
                "SELECT id, username, name, role, active, created_at FROM users ORDER BY created_at"
            ).fetchall()
            conn.close()
            self._json(200, {"users": [dict(r) for r in rows]})
        else:
            super().do_GET()

    # ── POST ──
    def do_POST(self):
        if self.path == "/auth/login":
            self._login()
        elif self.path == "/auth/register":
            self._register()
        elif self.path == "/auth/logout":
            self._logout()
        elif self.path == "/admin/users":
            user = verify_session(self._token())
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Acceso denegado"})
            self._create_user()
        else:
            self.send_response(404); self.end_headers()

    # ── PUT ──
    def do_PUT(self):
        if self.path.startswith("/admin/users/"):
            user = verify_session(self._token())
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Acceso denegado"})
            uid = self.path.rstrip("/").split("/")[-1]
            self._update_user(uid)
        else:
            self.send_response(404); self.end_headers()

    # ── DELETE ──
    def do_DELETE(self):
        if self.path.startswith("/admin/users/"):
            user = verify_session(self._token())
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Acceso denegado"})
            uid = self.path.rstrip("/").split("/")[-1]
            conn = get_conn()
            conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            conn.execute("DELETE FROM users WHERE id=? AND username != ?", (uid, ADMIN_USER))
            conn.commit(); conn.close()
            self._json(200, {"ok": True})
        else:
            self.send_response(404); self.end_headers()

    # ── AUTH ──
    def _login(self):
        body = self._body()
        username = body.get("username", "").strip().lower()
        password = body.get("password", "")
        conn = get_conn()
        row = conn.execute(
            "SELECT id, username, name, password_hash, salt, role, active FROM users WHERE username=?",
            (username,)
        ).fetchone()
        if not row or not row["active"] or _hash(password, row["salt"]) != row["password_hash"]:
            conn.close()
            return self._json(401, {"error": "Usuario o contraseña incorrectos"})
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
        conn.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                     (token, row["id"], _now(), expires))
        conn.commit(); conn.close()
        self._json(200, {
            "token": token,
            "user": {"id": row["id"], "username": row["username"],
                     "name": row["name"], "role": row["role"]}
        })

    def _register(self):
        body = self._body()
        username = body.get("username", "").strip().lower()
        name     = body.get("name", "").strip()
        password = body.get("password", "")
        if not username or not name or not password:
            return self._json(400, {"error": "Faltan campos"})
        if len(password) < 6:
            return self._json(400, {"error": "La contraseña debe tener al menos 6 caracteres"})
        salt     = secrets.token_hex(16)
        pwd_hash = _hash(password, salt)
        try:
            conn = get_conn()
            conn.execute(
                "INSERT INTO users (username, name, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,0,?)",
                (username, name, pwd_hash, salt, "viewer", _now())
            )
            conn.commit(); conn.close()
            self._json(201, {"ok": True, "message": "Cuenta creada. Espera a que el administrador la apruebe."})
        except sqlite3.IntegrityError:
            self._json(409, {"error": "Ese usuario ya existe, elige otro"})

    def _logout(self):
        token = self._token()
        if token:
            conn = get_conn()
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit(); conn.close()
        self._json(200, {"ok": True})

    def _create_user(self):
        body = self._body()
        username = body.get("username", "").strip().lower()
        name     = body.get("name", "").strip()
        password = body.get("password", "")
        role     = body.get("role", "viewer")
        if not username or not name or not password:
            return self._json(400, {"error": "Faltan campos"})
        if role not in ("admin", "viewer"):
            return self._json(400, {"error": "Rol inválido"})
        salt     = secrets.token_hex(16)
        pwd_hash = _hash(password, salt)
        try:
            conn = get_conn()
            conn.execute(
                "INSERT INTO users (username, name, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,1,?)",
                (username, name, pwd_hash, salt, role, _now())
            )
            conn.commit(); conn.close()
            self._json(201, {"ok": True})
        except sqlite3.IntegrityError:
            self._json(409, {"error": "El usuario ya existe"})

    def _update_user(self, uid):
        body = self._body()
        conn = get_conn()
        if "password" in body and body["password"]:
            salt     = secrets.token_hex(16)
            pwd_hash = _hash(body["password"], salt)
            conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (pwd_hash, salt, uid))
        if "role" in body:
            conn.execute("UPDATE users SET role=? WHERE id=?", (body["role"], uid))
        if "active" in body:
            conn.execute("UPDATE users SET active=? WHERE id=?", (1 if body["active"] else 0, uid))
        if "name" in body:
            conn.execute("UPDATE users SET name=? WHERE id=?", (body["name"], uid))
        conn.commit(); conn.close()
        self._json(200, {"ok": True})

    # ── SHOPIFY PROXY ──
    def _proxy_shopify(self):
        qs     = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        title  = params.get("title", [""])[0]
        url    = (f"https://{SHOPIFY_STORE}/admin/api/2024-01/products.json"
                  f"?title={urllib.parse.quote(title)}&fields=id,title,variants&limit=10")
        try:
            req = urllib.request.Request(url, headers={
                "X-Shopify-Access-Token": SHOPIFY_TOKEN,
                "Content-Type": "application/json"
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors(); self.end_headers()
            self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self._cors(); self.end_headers()
            self.wfile.write(data)

    # ── HELPERS ──
    def _token(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def _json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors(); self.end_headers()
        self.wfile.write(body)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def log_message(self, fmt, *args):
        print(f"[bdg] {fmt % args}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    with http.server.ThreadingHTTPServer(("", PORT), ProxyHandler) as httpd:
        print(f"[bdg] Servidor corriendo en http://localhost:{PORT}")
        httpd.serve_forever()
