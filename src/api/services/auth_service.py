import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta

_PBKDF2_ITERATIONS = 100_000
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_AUTH_SECRET = os.environ.get("KOPO_AUTH_SECRET", "kopo-soc-local-dev-signing-key-v1").encode("utf-8")
ADMIN_INVITE_CODE = os.environ.get("KOPO_ADMIN_INVITE_CODE", "KOPO-ADMIN-2026")
ADMIN_ROLES = {"admin", "lead"}
USER_ROLES = {"tier1", "tier2"}


def validate_email_address(email: str) -> str:
    cleaned = (email or "").strip().lower()
    if not cleaned or not _EMAIL_RE.match(cleaned):
        raise ValueError("Please enter a valid email address (e.g. operator@kopo.defense)")
    return cleaned


def validate_password_strength(password: str, require_complexity: bool = True) -> str:
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long")
    if len(password) > 128:
        raise ValueError("Password must be 128 characters or fewer")
    if require_complexity:
        if not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
            raise ValueError("Password must contain at least one letter and one number")
    return password


def hash_password(password: str) -> str:
    """Hash a password with a per-user random salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), _PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification against a stored PBKDF2 hash."""
    if not password or not stored_hash:
        return False
    try:
        scheme, iter_str, salt, expected_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
    except Exception:
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    ).hex()
    return hmac.compare_digest(derived, expected_hex)


def issue_auth_token(user_id: int, email: str, role: str, portal: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "portal": portal,
        "exp": int((datetime.utcnow() + timedelta(hours=24)).timestamp()),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(_AUTH_SECRET, b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_auth_token(token: str) -> dict:
    if not token or "." not in token:
        raise ValueError("Invalid authentication token")
    b64, sig = token.rsplit(".", 1)
    expected_sig = hmac.new(_AUTH_SECRET, b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid or tampered authentication token")
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Malformed authentication token") from exc
    if int(payload.get("exp", 0)) < int(datetime.utcnow().timestamp()):
        raise ValueError("Session expired — please sign in again")
    return payload
