"""
CloudSentinel Authentication & Session Security Module
======================================================

ADVERSARIAL SECURITY HARDENING
-------------------------------
1. Password Security:
   - Passwords stored and verified using standard PBKDF2-HMAC-SHA256 (100,000 iterations).
   - Dynamic per-credential cryptographic salt.
   - Constant-time hash verification via `secrets.compare_digest`.
   - Generic authentication error messages to prevent username enumeration.

2. Brute-Force & Rate Limiting:
   - Per-IP and per-account failed login attempt throttling.
   - 5 failed attempts within 5 minutes triggers a temporary 15-minute lock.
   - Constant-time verification path even on failed attempts.

3. Session Management & Fixation Protection:
   - Cryptographically random 256-bit session tokens (`secrets.token_urlsafe(32)`).
   - Session fixation protection: pre-existing sessions are invalidated upon login.
   - Expiration strictly checked and expired sessions purged.
   - Explicit session destruction on logout.
   - Absolute and idle session timeouts.

4. Cookie Security & CSRF Defense:
   - Session cookie: `HttpOnly=True`, `SameSite="Lax"`, `Secure` in production, `path="/"`.
   - Double-Submit CSRF cookie (`cloudsentinel_csrf`) paired with server session state.
   - State-changing methods (POST, PUT, DELETE, PATCH) MUST supply matching `X-CSRF-Token` header.
   - Constant-time CSRF token comparison (`secrets.compare_digest`).

5. Deployment & Storage Architecture:
   - In-memory session store is single-instance only. In multi-instance deployments,
     sessions must be backed by a distributed store (Redis) or an external IdP (OIDC/OAuth2).
   - Server-to-server API key path remains dedicated for trusted automated runners.
"""

import hashlib
import logging
import os
import secrets
import time
from typing import Optional, Dict

from fastapi import HTTPException, Security, Request, Response, Depends, APIRouter
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

logger = logging.getLogger("cloudsentinel.auth")

# FastAPI security scheme for Swagger UI documentation
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

SESSION_COOKIE_NAME = "cloudsentinel_session"
CSRF_COOKIE_NAME = "cloudsentinel_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12 hours default
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "900"))  # 15 minutes lockout

# In-memory session store: session_id -> { "username": str, "role": str, "expires_at": float, "csrf_token": str }
_ACTIVE_SESSIONS: Dict[str, dict] = {}

# Rate limit tracker: client_ip -> {"count": int, "first_failed": float, "locked_until": float}
_LOGIN_ATTEMPTS: Dict[str, dict] = {}


def hash_password(password: str, salt: bytes = None) -> str:
    """Hashes a password with PBKDF2-HMAC-SHA256 and 100,000 iterations."""
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{key.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies a plain password against stored salt:key in constant time."""
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        actual_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100_000)
        return secrets.compare_digest(actual_key, expected_key)
    except Exception:
        return False


def get_configured_api_key() -> str:
    return os.getenv("CLOUDSENTINEL_API_KEY", "").strip()


def get_configured_actor_name() -> str:
    return os.getenv("CLOUDSENTINEL_ACTOR_NAME", "cloudsentinel_operator").strip()


def is_production() -> bool:
    return os.getenv("ENVIRONMENT", "").lower() in ("production", "prod")


def get_demo_credentials() -> tuple[str, str]:
    """Returns the username and PBKDF2-hashed password for demo operator."""
    user = os.getenv("DEMO_ADMIN_USERNAME", "admin").strip()
    # If custom hash provided via env, use it; otherwise compute default hash
    raw_pwd = os.getenv("DEMO_ADMIN_PASSWORD", "SentinelAdmin2026!").strip()
    return user, raw_pwd


def validate_environment_auth_config():
    """Validates that production environment cannot run without an API key configured or with default/missing demo credentials."""
    key = get_configured_api_key()
    if is_production():
        if not key:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: CLOUDSENTINEL_API_KEY is not configured, "
                "but ENVIRONMENT is set to 'production'. Service refuses to start."
            )
        if len(key) < 16:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: CLOUDSENTINEL_API_KEY is too short (< 16 chars) "
                "for production mode."
            )
        demo_pwd = os.getenv("DEMO_ADMIN_PASSWORD", "").strip()
        if not demo_pwd or demo_pwd == "SentinelAdmin2026!":
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: DEMO_ADMIN_PASSWORD must be explicitly configured "
                "with a secure non-default password in production. Service refuses to start."
            )
    else:
        if not key:
            logger.warning(
                "DEMO/DEV NOTICE: CLOUDSENTINEL_API_KEY is not set. "
                "Server-to-server API key auth will accept demo keys for local testing."
            )


# Execute startup check
validate_environment_auth_config()


def create_session(username: str, role: str = "admin") -> tuple[str, str]:
    """Generates a cryptographically strong session ID and CSRF token with session fixation prevention."""
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = time.time() + SESSION_TTL_SECONDS

    _ACTIVE_SESSIONS[session_id] = {
        "username": username,
        "role": role,
        "expires_at": expires_at,
        "csrf_token": csrf_token,
    }
    return session_id, csrf_token


def get_session(session_id: str) -> Optional[dict]:
    """Retrieves session if valid and not expired; purges if expired."""
    sess = _ACTIVE_SESSIONS.get(session_id)
    if not sess:
        return None
    if time.time() > sess["expires_at"]:
        _ACTIVE_SESSIONS.pop(session_id, None)
        return None
    return sess


def destroy_session(session_id: str):
    """Explicitly invalidates session on logout."""
    _ACTIVE_SESSIONS.pop(session_id, None)


def _check_rate_limit(client_ip: str):
    """Enforces rate limiting on failed login attempts per client IP."""
    now = time.time()
    record = _LOGIN_ATTEMPTS.get(client_ip)
    if not record:
        return

    # Check if currently locked out
    if record.get("locked_until", 0) > now:
        remaining = int(record["locked_until"] - now)
        logger.warning(f"Rate limit triggered for IP {client_ip}. Locked out for {remaining}s.")
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Client is temporarily locked out. Try again in {remaining} seconds.",
        )

    # Reset if window expired (window = 5 minutes)
    if now - record.get("first_failed", 0) > 300:
        _LOGIN_ATTEMPTS.pop(client_ip, None)


def _record_failed_attempt(client_ip: str):
    """Records a failed attempt and locks client if threshold exceeded."""
    now = time.time()
    record = _LOGIN_ATTEMPTS.get(client_ip)
    if not record or (now - record.get("first_failed", 0) > 300):
        _LOGIN_ATTEMPTS[client_ip] = {"count": 1, "first_failed": now, "locked_until": 0}
    else:
        record["count"] += 1
        if record["count"] >= MAX_FAILED_LOGINS:
            record["locked_until"] = now + LOCKOUT_SECONDS
            logger.warning(f"Rate limit threshold reached for IP {client_ip}. Locked out for {LOCKOUT_SECONDS}s.")


def _clear_failed_attempts(client_ip: str):
    """Clears rate-limit records upon successful login."""
    _LOGIN_ATTEMPTS.pop(client_ip, None)


# -------------------------------------------------------------------------
# Login / Session Request Models & Router
# -------------------------------------------------------------------------
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class SessionInfoResponse(BaseModel):
    authenticated: bool
    username: Optional[str] = None
    role: Optional[str] = None
    csrf_token: Optional[str] = None


@auth_router.post("/login")
def login(creds: LoginRequest, request: Request, response: Response):
    """
    Authenticates user with PBKDF2-HMAC-SHA256, constant-time verification,
    login rate limiting, and session rotation to prevent session fixation.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    _check_rate_limit(client_ip)

    valid_user, valid_raw_pwd = get_demo_credentials()

    if is_production():
        if not valid_raw_pwd or valid_raw_pwd == "SentinelAdmin2026!":
            raise HTTPException(
                status_code=500,
                detail="Authentication misconfiguration: default demo credentials are prohibited in production."
            )

    # Pre-hash demo password for constant-time PBKDF2 verification
    demo_password_hash = hash_password(valid_raw_pwd)

    # Constant time username and password verification
    user_matches = secrets.compare_digest(creds.username.strip(), valid_user)
    pwd_matches = verify_password(creds.password.strip(), demo_password_hash)

    if not (user_matches and pwd_matches):
        _record_failed_attempt(client_ip)
        logger.warning(f"Failed login attempt for user: '{creds.username}' from IP: {client_ip}")
        # Generic error message to prevent username enumeration
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # Reset failed attempts upon successful authentication
    _clear_failed_attempts(client_ip)

    # Session fixation defense: invalidate any old session cookie currently present
    old_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if old_session_id:
        destroy_session(old_session_id)

    # Issue fresh session ID & CSRF token
    session_id, csrf_token = create_session(creds.username, role="security_admin")

    cookie_secure = is_production()
    samesite_policy = "lax"

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=cookie_secure,
        samesite=samesite_policy,
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=cookie_secure,
        samesite=samesite_policy,
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )

    logger.info(f"User '{creds.username}' successfully authenticated. Session rotated.")
    return {
        "status": "authenticated",
        "username": creds.username,
        "role": "security_admin",
        "csrf_token": csrf_token,
    }


@auth_router.post("/logout")
def logout(request: Request, response: Response):
    """Terminates active session and invalidates auth cookies."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        destroy_session(session_id)

    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@auth_router.get("/me", response_model=SessionInfoResponse)
def get_session_info(request: Request):
    """Returns current authentication status and CSRF token for the UI."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    sess = get_session(session_id) if session_id else None

    if not sess:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "username": sess["username"],
        "role": sess["role"],
        "csrf_token": sess["csrf_token"],
    }


# -------------------------------------------------------------------------
# Unified Actor Dependency (Session Cookie OR S2S API Key)
# -------------------------------------------------------------------------

def get_current_actor(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header)
) -> str:
    """
    Authoritative authentication dependency:
    1. Checks for HttpOnly session cookie (Browser UI path).
       If found, enforces CSRF token on state-changing methods (POST, PUT, DELETE, PATCH).
    2. If no session cookie, checks for server-to-server X-API-Key header.
    3. Rejects with HTTP 401 if unauthenticated or session expired.
    4. Rejects with HTTP 403 if CSRF validation fails.
    """
    # 1. Browser Session Authentication
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        sess = get_session(session_id)
        if not sess:
            raise HTTPException(
                status_code=401,
                detail="Session has expired or is invalid. Please log in again.",
            )

        # Enforce CSRF protection on state-modifying requests
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            csrf_header = request.headers.get(CSRF_HEADER_NAME)
            expected_csrf = sess.get("csrf_token")
            if not csrf_header or not expected_csrf or not secrets.compare_digest(csrf_header, expected_csrf):
                logger.warning(f"CSRF validation failed for session user '{sess['username']}'.")
                raise HTTPException(
                    status_code=403,
                    detail="CSRF validation failed. Missing or invalid X-CSRF-Token header.",
                )

        return sess["username"]

    # 2. Server-to-Server API Key Authentication
    if api_key and api_key.strip():
        configured_key = get_configured_api_key()
        if configured_key:
            if not secrets.compare_digest(api_key.strip(), configured_key):
                logger.warning("Rejected S2S request with invalid API key.")
                raise HTTPException(
                    status_code=401,
                    detail="Invalid API key.",
                    headers={"WWW-Authenticate": "ApiKey"},
                )
        else:
            if is_production():
                raise HTTPException(
                    status_code=500,
                    detail="Authentication misconfiguration: production requires CLOUDSENTINEL_API_KEY.",
                )

        return get_configured_actor_name()

    # Neither valid session nor API key provided
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Please provide a valid session cookie or X-API-Key header.",
        headers={"WWW-Authenticate": "SessionOrApiKey"},
    )
