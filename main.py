
import os
import re
import json
import base64
import hmac
import secrets
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request, session, send_from_directory

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)

RAW_URL = os.environ.get("GITHUB_RAW_URL", "").strip()
GH_TOKEN = os.environ.get("GH_TOKEN", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
API = "https://api.github.com"

def headers():
    return {
        "Authorization": "Bearer " + GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

def target():
    if not RAW_URL or not GH_TOKEN:
        raise ValueError("GITHUB_RAW_URL و GH_TOKEN را در Railway تنظیم کن.")

    u = urlparse(RAW_URL)
    if u.scheme != "https" or u.netloc != "raw.githubusercontent.com":
        raise ValueError("Raw URL معتبر نیست.")

    p = [x for x in u.path.split("/") if x]
    if len(p) < 4:
        raise ValueError("لینک باید به یک فایل JSON اشاره کند.")

    owner, repo, branch = p[0], p[1], p[2]
    path = "/".join(p[3:])
    return owner, repo, branch, path

def gh(method, url, **kwargs):
    r = requests.request(
        method, url, headers=headers(), timeout=20, **kwargs
    )
    if not r.ok:
        try:
            error = r.json().get("message", r.text[:200])
        except Exception:
            error = r.text[:200]
        raise RuntimeError(f"GitHub {r.status_code}: {error}")
    return r.json() if r.content else {}

def read_settings():
    owner, repo, branch, path = target()
    url = f"{API}/repos/{owner}/{repo}/contents/{path}"

    r = requests.get(
        url, headers=headers(), params={"ref": branch}, timeout=20
    )

    if r.status_code == 404:
        data = {
            "enabled": True,
            "sha256": "",
            "emergency_stop": False
        }
        result = gh("PUT", url, json={
            "message": "Create MAXO security settings",
            "branch": branch,
            "content": base64.b64encode(
                (json.dumps(data, indent=2) + "\n").encode()
            ).decode()
        })
        return data, result["content"]["sha"], (owner, repo, branch, path)

    if not r.ok:
        raise RuntimeError("خواندن تنظیمات GitHub ناموفق بود: " + r.text[:200])

    item = r.json()
    data = json.loads(base64.b64decode(item["content"]).decode())
    return data, item["sha"], (owner, repo, branch, path)

def save_settings(data, sha, info):
    owner, repo, branch, path = info
    url = f"{API}/repos/{owner}/{repo}/contents/{path}"
    content = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()

    return gh("PUT", url, json={
        "message": "Update MAXO security settings",
        "branch": branch,
        "sha": sha,
        "content": base64.b64encode(content).decode()
    })

def is_admin():
    return session.get("admin") is True

@app.get("/")
def index():
    return send_from_directory(".", "admin.html")

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.post("/api/login")
def login():
    password = str((request.get_json(silent=True) or {}).get("password", ""))
    expected = ADMIN_PASSWORD or GH_TOKEN

    if not expected:
        return jsonify(error="توکن GitHub در Railway تنظیم نشده است."), 503

    if hmac.compare_digest(password, expected):
        session["admin"] = True
        return jsonify(ok=True)

    return jsonify(error="رمز ورود اشتباه است."), 401

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/config")
def public_config():
    try:
        data, _, _ = read_settings()
        return jsonify({
            "enabled": bool(data.get("enabled", True)),
            "sha256": str(data.get("sha256", "")),
            "emergency_stop": bool(data.get("emergency_stop", False))
        })
    except Exception as e:
        return jsonify(error=str(e)), 503

@app.get("/api/admin/config")
def admin_config():
    if not is_admin():
        return jsonify(error="ورود لازم است."), 401

    try:
        data, _, _ = read_settings()
        return jsonify({
            "enabled": bool(data.get("enabled", True)),
            "sha256": str(data.get("sha256", "")),
            "emergency_stop": bool(data.get("emergency_stop", False))
        })
    except Exception as e:
        return jsonify(error=str(e)), 503

@app.post("/api/admin/config")
def update_config():
    if not is_admin():
        return jsonify(error="ورود لازم است."), 401

    body = request.get_json(silent=True) or {}
    enabled = body.get("enabled")
    emergency = body.get("emergency_stop")
    sha = str(body.get("sha256", "")).strip().upper().replace(":", "")

    if not isinstance(enabled, bool) or not isinstance(emergency, bool):
        return jsonify(error="مقادیر تنظیمات نامعتبر هستند."), 400

    if sha and not re.fullmatch(r"[0-9A-F]{64}", sha):
        return jsonify(error="SHA-256 باید شامل ۶۴ رقم هگزادسیمال باشد."), 400

    if sha:
        sha = ":".join(sha[i:i+2] for i in range(0, 64, 2))

    try:
        old, old_sha, info = read_settings()
        old.update({
            "enabled": enabled,
            "sha256": sha,
            "emergency_stop": emergency
        })
        save_settings(old, old_sha, info)

        return jsonify(ok=True, config={
            "enabled": enabled,
            "sha256": sha,
            "emergency_stop": emergency
        })
    except Exception as e:
        return jsonify(error=str(e)), 503

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
    