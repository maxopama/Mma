
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
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "MAXO-SHA-PANEL"
    }


def target():
    if not RAW_URL or not GH_TOKEN:
        raise ValueError(
            "GITHUB_RAW_URL و GH_TOKEN را در Railway تنظیم کن."
        )

    u = urlparse(RAW_URL)

    if u.scheme != "https" or u.netloc != "raw.githubusercontent.com":
        raise ValueError("Raw URL معتبر نیست.")

    p = [x for x in u.path.split("/") if x]

    if len(p) < 4:
        raise ValueError("لینک باید به یک فایل داخل مخزن اشاره کند.")

    owner, repo = p[0], p[1]

    if p[2] == "refs" and len(p) >= 6 and p[3] == "heads":
        branch = p[4]
        path = "/".join(p[5:])
    else:
        branch = p[2]
        path = "/".join(p[3:])

    return owner, repo, branch, path


def gh(method, url, **kwargs):
    r = requests.request(
        method,
        url,
        headers=headers(),
        timeout=20,
        **kwargs
    )

    if not r.ok:
        try:
            message = r.json().get("message", r.text[:250])
        except Exception:
            message = r.text[:250]

        raise RuntimeError(
            "GitHub " + str(r.status_code) + ": " + message
        )

    return r.json() if r.content else {}


def read_settings():
    owner, repo, branch, path = target()

    gh(
        "GET",
        API + "/repos/" + owner + "/" + repo
    )

    url = (
        API + "/repos/" + owner + "/" + repo +
        "/contents/" + path
    )

    r = requests.get(
        url,
        headers=headers(),
        params={"ref": branch},
        timeout=20
    )

    info = (owner, repo, branch, path)

    if r.status_code == 404:
        initial = {
            "enabled": True,
            "sha256": "",
            "emergency_stop": False
        }

        created = gh("PUT", url, json={
            "message": "Create MAXO security settings",
            "branch": branch,
            "content": base64.b64encode(
                (json.dumps(initial, indent=2) + "\n").encode("utf-8")
            ).decode("ascii")
        })

        return initial, created["content"]["sha"], info

    if not r.ok:
        raise RuntimeError(
            "GitHub " + str(r.status_code) + ": " + r.text[:250]
        )

    item = r.json()

    if item.get("type") != "file":
        raise RuntimeError("مسیر انتخاب‌شده فایل نیست.")

    raw_content = item.get("content", "")
    if not raw_content:
        raise RuntimeError(
            "محتوای فایل دریافت نشد؛ فایل JSON را بررسی کن."
        )

    data = json.loads(
        base64.b64decode(raw_content).decode("utf-8")
    )

    if not isinstance(data, dict):
        raise RuntimeError("ساختار JSON باید یک شیء باشد.")

    return data, item["sha"], info


def save_settings(data, sha, info):
    owner, repo, branch, path = info
    url = (
        API + "/repos/" + owner + "/" + repo +
        "/contents/" + path
    )

    content = (
        json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")

    return gh("PUT", url, json={
        "message": "Update MAXO security settings",
        "branch": branch,
        "sha": sha,
        "content": base64.b64encode(content).decode("ascii")
    })


def is_admin():
    return session.get("admin") is True


@app.get("/")
def index():
    return send_from_directory(".", "admin.html")


@app.get("/health")
def health():
    return jsonify(ok=True, service="MAXO SHA Panel")


@app.post("/api/login")
def login():
    if not ADMIN_PASSWORD:
        return jsonify(
            error="متغیر ADMIN_PASSWORD را در Railway تنظیم کن."
        ), 503

    body = request.get_json(silent=True) or {}
    password = str(body.get("password", ""))

    if hmac.compare_digest(password, ADMIN_PASSWORD):
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
            "emergency_stop": bool(
                data.get("emergency_stop", False)
            )
        })

    except Exception as e:
        app.logger.exception("Could not read GitHub settings")
        return jsonify(error=str(e)), 503


@app.get("/api/admin/config")
def admin_config():
    if not is_admin():
        return jsonify(error="ابتدا وارد پنل شو."), 401

    try:
        data, _, _ = read_settings()

        return jsonify({
            "enabled": bool(data.get("enabled", True)),
            "sha256": str(data.get("sha256", "")),
            "emergency_stop": bool(
                data.get("emergency_stop", False)
            )
        })

    except Exception as e:
        app.logger.exception("Could not load admin settings")
        return jsonify(error=str(e)), 503


@app.post("/api/admin/config")
def update_config():
    if not is_admin():
        return jsonify(error="ابتدا وارد پنل شو."), 401

    body = request.get_json(silent=True) or {}

    enabled = body.get("enabled")
    emergency = body.get("emergency_stop")
    sha = str(body.get("sha256", "")).strip().upper().replace(":", "")

    if not isinstance(enabled, bool):
        return jsonify(error="مقدار enabled نامعتبر است."), 400

    if not isinstance(emergency, bool):
        return jsonify(error="مقدار emergency_stop نامعتبر است."), 400

    if sha and not re.fullmatch(r"[0-9A-F]{64}", sha):
        return jsonify(
            error="SHA-256 باید ۶۴ رقم هگزادسیمال باشد."
        ), 400

    if sha:
        sha = ":".join(
            sha[i:i + 2] for i in range(0, len(sha), 2)
        )

    try:
        old, old_sha, info = read_settings()

        old.update({
            "enabled": enabled,
            "sha256": sha,
            "emergency_stop": emergency
        })

        save_settings(old, old_sha, info)

        return jsonify(
            ok=True,
            config={
                "enabled": enabled,
                "sha256": sha,
                "emergency_stop": emergency
            }
        )

    except Exception as e:
        app.logger.exception("Could not save GitHub settings")
        return jsonify(error=str(e)), 503


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080"))
    )
    