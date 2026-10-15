import os
import json
import time
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from unittest.mock import patch

# Set test API key BEFORE importing auth so the module reads the right value
os.environ.setdefault("CLOUDSENTINEL_API_KEY", "test-api-key-12345")
os.environ.setdefault("CLOUDSENTINEL_ACTOR_NAME", "test_operator")

from backend.database.database import Base, check_db_connection, get_db
from backend.database.models import Remediation, Finding, AuditLog
from backend.services.ai import safety_gate, executor
from backend.services.ai.audit_log import record as audit_record
from backend.auth import get_current_actor
from backend.main import app

# Shared in-memory SQLite engine that preserves tables across connections via URI
TEST_DB_URL = "sqlite:///file:testdb?mode=memory&cache=shared&uri=true"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# Auth-bypassed client for tests that don't exercise auth logic
def override_get_current_actor():
    return "test_operator"

app.dependency_overrides[get_current_actor] = override_get_current_actor
client = TestClient(app)

# Separate client that does NOT bypass auth — used for auth-specific tests
auth_client = TestClient(app, raise_server_exceptions=False)



@pytest.fixture(autouse=True)
def setup_test_database():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


# ==============================================================================
# 1. Database Configuration & Health Check Tests
# ==============================================================================

def test_sqlite_connection_check():
    assert check_db_connection(test_engine) is True

def test_postgresql_driver_format_and_unavailable_db():
    fake_pg_engine = create_engine("postgresql://nonexistent_user:pass@127.0.0.1:54321/fake_db")
    with pytest.raises(Exception):
        check_db_connection(fake_pg_engine)


# ==============================================================================
# 2. Safety Gate & Policy Gate Tests
# ==============================================================================

def test_safety_gate_auto_allowed():
    finding = {
        "finding_id": "s3_enc_1",
        "resource_id": "my-bucket",
        "resource_type": "s3_bucket",
        "finding": "Encryption is disabled",
        "severity": "MEDIUM",
        "category": "DATA_PROTECTION",
        "evidence": {},
        "status": "OPEN"
    }
    decision = safety_gate.gate(finding)
    assert decision["tier"] == safety_gate.AUTO_ALLOWED
    assert decision["implementation_status"] == safety_gate.IMPLEMENTED
    assert decision["can_execute"] is True
    assert decision["requires_approval"] is False

def test_safety_gate_approval_required():
    finding = {
        "finding_id": "s3_pub_1",
        "resource_id": "my-bucket",
        "resource_type": "s3_bucket",
        "finding": "Bucket is publicly accessible",
        "severity": "HIGH",
        "category": "PUBLIC_ACCESS",
        "evidence": {},
        "status": "OPEN"
    }
    decision = safety_gate.gate(finding)
    assert decision["tier"] == safety_gate.APPROVAL_REQUIRED
    assert decision["implementation_status"] == safety_gate.IMPLEMENTED
    assert decision["can_execute"] is True
    assert decision["requires_approval"] is True

def test_safety_gate_never_auto():
    finding = {
        "finding_id": "iam_root_1",
        "resource_id": "root",
        "resource_type": "iam_account",
        "finding": "Root account MFA is not enabled",
        "severity": "CRITICAL",
        "category": "IDENTITY_SECURITY",
        "evidence": {},
        "status": "OPEN"
    }
    decision = safety_gate.gate(finding)
    assert decision["tier"] == safety_gate.NEVER_AUTO
    assert decision["can_execute"] is False

def test_safety_gate_not_implemented():
    finding = {
        "finding_id": "sg_ssh_1",
        "resource_id": "sg-12345",
        "resource_type": "security_group",
        "finding": "SSH open to world",
        "severity": "HIGH",
        "category": "NETWORK_SECURITY",
        "evidence": {},
        "status": "OPEN"
    }
    decision = safety_gate.gate(finding)
    assert decision["implementation_status"] == safety_gate.NOT_IMPLEMENTED
    assert decision["can_execute"] is False


# ==============================================================================
# 3. Remediation Workflow & API Endpoint Tests
# ==============================================================================

def test_legacy_record_refusal():
    db = TestingSessionLocal()
    rem = Remediation(
        title="Remediate: Old finding",
        description="Legacy finding without json",
        finding_id=99,
        finding_json=None,
        status="PENDING",
        approved=False
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    rem_id = rem.id
    db.close()

    response = client.put(f"/platform/remediation/{rem_id}/approve")
    assert response.status_code == 422
    data = response.json()
    assert "Legacy remediation record missing raw finding payload" in data["detail"]

    check_db = TestingSessionLocal()
    updated = check_db.query(Remediation).filter(Remediation.id == rem_id).first()
    assert updated.status == "LEGACY_SCAN_REQUIRED"
    check_db.close()

def test_never_auto_approval_refused():
    db = TestingSessionLocal()
    finding_data = {
        "resource_id": "root",
        "resource_type": "iam_account",
        "finding": "Root account MFA is not enabled",
        "severity": "CRITICAL",
        "category": "IDENTITY_SECURITY",
        "status": "OPEN"
    }
    rem = Remediation(
        title="Remediate Root MFA",
        finding_json=json.dumps(finding_data),
        status="PENDING",
        approved=False
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    rem_id = rem.id
    db.close()

    response = client.put(f"/platform/remediation/{rem_id}/approve")
    assert response.status_code == 422
    assert "NEVER_AUTO" in response.json()["detail"]

    check_db = TestingSessionLocal()
    updated = check_db.query(Remediation).filter(Remediation.id == rem_id).first()
    assert updated.status == "BLOCKED"
    check_db.close()

def test_valid_remediation_approval_and_execution():
    db = TestingSessionLocal()
    finding_data = {
        "finding_id": "test_s3_valid",
        "resource_id": "test-clean-bucket",
        "resource_type": "s3_bucket",
        "finding": "Block Public Access is disabled",
        "severity": "HIGH",
        "category": "PUBLIC_ACCESS",
        "evidence": {},
        "status": "OPEN"
    }
    rem = Remediation(
        title="Remediate Block Public Access",
        finding_json=json.dumps(finding_data),
        status="PENDING",
        approved=False
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    rem_id = rem.id
    db.close()

    with patch("backend.services.ai.executor.apply_remediation") as mock_apply, \
         patch("backend.services.ai.executor.verification.verify_finding") as mock_verify, \
         patch("backend.services.ai.executor.backup.snapshot") as mock_snap:
        mock_snap.return_value = {"state": {}}
        mock_apply.return_value = {"applied": True, "detail": "Success"}
        mock_verify.return_value = {"status": "VERIFICATION_PASSED", "details": "Verified"}

        response = client.put(f"/platform/remediation/{rem_id}/approve")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "EXECUTED"
        assert data["approved_by"] == "test_operator"

        # Verify idempotency: approving an already executed remediation returns 409
        dup_response = client.put(f"/platform/remediation/{rem_id}/approve")
        assert dup_response.status_code == 409

def test_reject_remediation_workflow():
    db = TestingSessionLocal()
    rem = Remediation(
        title="Remediate Test Bucket",
        finding_json=json.dumps({"resource_id": "b1", "resource_type": "s3_bucket", "finding": "Test", "status": "OPEN"}),
        status="PENDING",
        approved=False
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    rem_id = rem.id
    db.close()

    response = client.put(f"/platform/remediation/{rem_id}/reject")
    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"

    db2 = TestingSessionLocal()
    r = db2.query(Remediation).filter(Remediation.id == rem_id).first()
    r.status = "EXECUTED"
    db2.commit()
    db2.close()

    dup_reject = client.put(f"/platform/remediation/{rem_id}/reject")
    assert dup_reject.status_code == 409


# ==============================================================================
# 4. Direct Executor & Bypass Tests (API + Direct Unit)
# ==============================================================================

def test_direct_executor_refuses_never_auto():
    finding = {
        "finding_id": "f_root",
        "resource_id": "root",
        "resource_type": "iam_account",
        "finding": "Root account MFA is not enabled",
        "severity": "CRITICAL",
        "category": "IDENTITY_SECURITY",
        "evidence": {},
        "status": "OPEN"
    }
    # Direct service call bypassing API
    res = executor.execute_remediation(finding, approved_by="admin")
    assert res["executed"] is False
    assert res["tier"] == safety_gate.NEVER_AUTO

def test_direct_executor_requires_approval_when_missing():
    finding = {
        "finding_id": "f_acl",
        "resource_id": "test-bkt",
        "resource_type": "s3_bucket",
        "finding": "Bucket is publicly accessible",
        "severity": "HIGH",
        "category": "PUBLIC_ACCESS",
        "evidence": {},
        "status": "OPEN"
    }
    # Without approved_by
    res = executor.execute_remediation(finding, approved_by=None)
    assert res["executed"] is False
    assert res.get("requires_approval") is True

def test_ai_remediation_apply_api_enforces_safety_gate():
    never_auto_payload = {
        "finding": {
            "finding_id": "f_root",
            "resource_id": "root",
            "resource_type": "iam_account",
            "finding": "Root account MFA is not enabled",
            "severity": "CRITICAL",
            "category": "IDENTITY_SECURITY",
            "evidence": {},
            "status": "OPEN"
        },
        "confirm": True,
        "approved_by": "superadmin"
    }
    # Direct call to /remediation/apply
    response = client.post("/remediation/apply", json=never_auto_payload)
    assert response.status_code == 422
    assert "Identity/access change" in response.json()["detail"]


# ==============================================================================
# 5. Audit Log Credential Masking Tests
# ==============================================================================

def test_audit_log_credential_masking():
    event = {
        "finding_id": "f_secret",
        "action": "remediation_applied",
        "credentials": {
            "aws_secret_access_key": "SUPER_SECRET_VALUE",
            "password": "my_password_123"
        },
        "details": "Authorization: Bearer secret_token_xyz"
    }
    recorded = audit_record(event)
    assert recorded["credentials"]["aws_secret_access_key"] == "******"
    assert recorded["credentials"]["password"] == "******"
    assert "secret_token_xyz" not in recorded["details"]


# ==============================================================================
# 6. Authentication & Authorization Tests
# ==============================================================================

def test_approve_without_auth_returns_401():
    # Use clean app without dependency override for auth
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    try:
        response = auth_client.put("/platform/remediation/1/approve")
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_approve_with_invalid_api_key_returns_401(monkeypatch):
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-secret-key-12345")
    try:
        response = auth_client.put(
            "/platform/remediation/1/approve",
            headers={"X-API-Key": "wrong-key"}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_reject_without_auth_returns_401():
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    try:
        response = auth_client.put("/platform/remediation/1/reject")
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_create_remediation_without_auth_returns_401():
    """Regression: POST /platform/remediation/ must reject unauthenticated callers.
    Fixed during pre-commit review — create endpoint previously lacked get_current_actor."""
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    try:
        response = auth_client.post(
            "/platform/remediation/",
            params={"title": "Unauthorized Task"}
        )
        assert response.status_code == 401, (
            f"Expected 401 for unauthenticated POST /platform/remediation/, got {response.status_code}"
        )
        assert "Authentication required" in response.json()["detail"]
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_auth_success_with_valid_api_key(monkeypatch):
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-secret-key-12345")
    monkeypatch.setenv("CLOUDSENTINEL_ACTOR_NAME", "security_officer")
    try:
        db = TestingSessionLocal()
        rem = Remediation(
            title="Test Rem",
            finding_json=json.dumps({"resource_id": "r1", "resource_type": "s3_bucket", "finding": "Test"}),
            status="PENDING",
            approved=False
        )
        db.add(rem)
        db.commit()
        db.refresh(rem)
        rem_id = rem.id
        db.close()

        response = auth_client.put(
            f"/platform/remediation/{rem_id}/reject",
            headers={"X-API-Key": "test-secret-key-12345"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "REJECTED"
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_session_login_and_authenticated_remediation(monkeypatch):
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    monkeypatch.setenv("DEMO_ADMIN_USERNAME", "secops_admin")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "SecOpsPass123!")
    auth_client.cookies.clear()
    try:
        # 1. Login with bad credentials -> 401
        res_bad = auth_client.post("/auth/login", json={"username": "secops_admin", "password": "wrong"})
        assert res_bad.status_code == 401

        # 2. Login with valid credentials -> 200, sets cookies
        res_ok = auth_client.post("/auth/login", json={"username": "secops_admin", "password": "SecOpsPass123!"})
        assert res_ok.status_code == 200
        csrf_token = res_ok.json()["csrf_token"]
        assert "cloudsentinel_session" in auth_client.cookies
        session_cookie = auth_client.cookies["cloudsentinel_session"]

        # 3. Create a pending remediation
        db = TestingSessionLocal()
        rem = Remediation(
            title="Session Test Rem",
            finding_json=json.dumps({"resource_id": "r2", "resource_type": "s3_bucket", "finding": "Test"}),
            status="PENDING",
            approved=False
        )
        db.add(rem)
        db.commit()
        db.refresh(rem)
        rem_id = rem.id
        db.close()

        # 4. State-changing request with session cookie BUT MISSING CSRF header -> 403 Forbidden
        res_no_csrf = auth_client.put(f"/platform/remediation/{rem_id}/reject")
        assert res_no_csrf.status_code == 403
        assert "CSRF validation failed" in res_no_csrf.json()["detail"]

        # 5. State-changing request with session cookie AND VALID CSRF header -> 200 Success
        res_with_csrf = auth_client.put(
            f"/platform/remediation/{rem_id}/reject",
            headers={"X-CSRF-Token": csrf_token}
        )
        assert res_with_csrf.status_code == 200
        assert res_with_csrf.json()["status"] == "REJECTED"

        # 6. Logout terminates session
        res_logout = auth_client.post("/auth/logout")
        assert res_logout.status_code == 200

        # 7. Post-logout request with old cookie re-attached -> 401
        auth_client.cookies.set("cloudsentinel_session", session_cookie)
        res_after_logout = auth_client.put(
            f"/platform/remediation/{rem_id}/reject",
            headers={"X-CSRF-Token": csrf_token}
        )
        assert res_after_logout.status_code == 401
    finally:
        auth_client.cookies.clear()
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_production_refuses_startup_without_api_key(monkeypatch):
    import backend.auth as auth_mod
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "")
    with pytest.raises(RuntimeError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        auth_mod.validate_environment_auth_config()

def test_production_refuses_startup_with_short_key(monkeypatch):
    import backend.auth as auth_mod
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "short")
    with pytest.raises(RuntimeError, match="too short"):
        auth_mod.validate_environment_auth_config()

def test_ai_remediation_apply_requires_auth():
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    try:
        res = auth_client.post("/remediation/apply", json={"finding": {}, "confirm": True})
        assert res.status_code == 401
    finally:
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

# ==============================================================================
# 7. Adversarial Security Tests
# ==============================================================================

def test_login_brute_force_rate_limiting(monkeypatch):
    import backend.auth as auth_mod
    auth_mod._LOGIN_ATTEMPTS.clear()
    monkeypatch.setenv("DEMO_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "SuperSecurePassword123!")

    # 5 failed attempts allowed, 6th triggers 429
    for i in range(5):
        res = auth_client.post("/auth/login", json={"username": "admin", "password": f"wrong_{i}"})
        assert res.status_code == 401

    # 6th attempt must be throttled with HTTP 429
    res_locked = auth_client.post("/auth/login", json={"username": "admin", "password": "wrong_6"})
    assert res_locked.status_code == 429
    assert "Too many failed login attempts" in res_locked.json()["detail"]

    # Even a valid password during lockout window is rejected with 429
    res_locked_valid = auth_client.post("/auth/login", json={"username": "admin", "password": "SuperSecurePassword123!"})
    assert res_locked_valid.status_code == 429

    # Clean up state
    auth_mod._LOGIN_ATTEMPTS.clear()

def test_session_fixation_protection(monkeypatch):
    import backend.auth as auth_mod
    auth_mod._LOGIN_ATTEMPTS.clear()
    auth_client.cookies.clear()
    monkeypatch.setenv("DEMO_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "SuperSecurePassword123!")

    # Attacker sets an arbitrary pre-existing session cookie
    attacker_cookie = "attacker_chosen_session_id_123"
    auth_mod._ACTIVE_SESSIONS[attacker_cookie] = {
        "username": "victim",
        "role": "user",
        "expires_at": time.time() + 3600,
        "csrf_token": "csrf_123"
    }

    # User authenticates with attacker cookie present in client
    auth_client.cookies.set("cloudsentinel_session", attacker_cookie)
    res = auth_client.post(
        "/auth/login",
        json={"username": "admin", "password": "SuperSecurePassword123!"}
    )
    assert res.status_code == 200
    new_session_id = res.cookies["cloudsentinel_session"]

    # Session ID MUST be rotated (not equal to attacker cookie)
    assert new_session_id != attacker_cookie

    # Old attacker session ID MUST be destroyed in the session store
    assert attacker_cookie not in auth_mod._ACTIVE_SESSIONS
    auth_client.cookies.clear()

def test_forged_and_tampered_session_rejected():
    from backend.auth import get_current_actor
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    auth_client.cookies.clear()
    try:
        # Request with forged session cookie
        auth_client.cookies.set("cloudsentinel_session", "forged_random_token_9999")
        res = auth_client.put("/platform/remediation/1/approve")
        assert res.status_code == 401
        assert "Session has expired or is invalid" in res.json()["detail"]
    finally:
        auth_client.cookies.clear()
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_csrf_token_tampering_rejected():
    from backend.auth import get_current_actor
    import backend.auth as auth_mod
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    auth_client.cookies.clear()

    # Valid session in store
    sess_id, csrf = auth_mod.create_session("admin_user", "security_admin")
    try:
        # Request with valid session cookie but tampered CSRF header
        auth_client.cookies.set("cloudsentinel_session", sess_id)
        res = auth_client.put(
            "/platform/remediation/1/approve",
            headers={"X-CSRF-Token": "tampered_csrf_token_xyz"}
        )
        assert res.status_code == 403
        assert "CSRF validation failed" in res.json()["detail"]
    finally:
        auth_client.cookies.clear()
        auth_mod.destroy_session(sess_id)
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override

def test_actor_spoofing_via_header_ignored():
    from backend.auth import get_current_actor
    import backend.auth as auth_mod
    original_override = app.dependency_overrides.pop(get_current_actor, None)
    auth_client.cookies.clear()

    sess_id, csrf = auth_mod.create_session("genuine_operator", "security_admin")
    try:
        db = TestingSessionLocal()
        rem = Remediation(
            title="Spoof Test Rem",
            finding_json=json.dumps({"resource_id": "r3", "resource_type": "s3_bucket", "finding": "Test"}),
            status="PENDING",
            approved=False
        )
        db.add(rem)
        db.commit()
        db.refresh(rem)
        rem_id = rem.id
        db.close()

        # Attacker tries to pass X-Actor: fake_identity
        auth_client.cookies.set("cloudsentinel_session", sess_id)
        res = auth_client.put(
            f"/platform/remediation/{rem_id}/reject",
            headers={"X-CSRF-Token": csrf, "X-Actor": "fake_identity"}
        )
        assert res.status_code == 200

        # Verify DB audit log recorded genuine_operator, NOT fake_identity
        check_db = TestingSessionLocal()
        audit = check_db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        assert "genuine_operator" in audit.details
        assert "fake_identity" not in audit.details
        check_db.close()
    finally:
        auth_client.cookies.clear()
        auth_mod.destroy_session(sess_id)
        if original_override:
            app.dependency_overrides[get_current_actor] = original_override


def test_remediation_status_fails_when_post_fix_verification_fails():
    db = TestingSessionLocal()
    finding_data = {
        "finding_id": "test_s3_verify_fail",
        "resource_id": "test-unverifiable-bucket",
        "resource_type": "s3_bucket",
        "finding": "Block Public Access is disabled",
        "severity": "HIGH",
        "category": "PUBLIC_ACCESS",
        "evidence": {},
        "status": "OPEN"
    }
    rem = Remediation(
        title="Remediate BPA with failing verify",
        finding_json=json.dumps(finding_data),
        status="PENDING",
        approved=False
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    rem_id = rem.id
    db.close()

    # Mock AWS apply as True, but post-fix verification as FAILED (and backup restore called)
    with patch("backend.services.ai.executor.apply_remediation") as mock_apply, \
         patch("backend.services.ai.executor.verification.verify_finding") as mock_verify, \
         patch("backend.services.ai.executor.backup.snapshot") as mock_snap, \
         patch("backend.services.ai.executor.backup.restore") as mock_restore:
        mock_snap.return_value = {"state": {}}
        mock_apply.return_value = {"applied": True, "detail": "Success"}
        mock_verify.return_value = {"status": "VERIFICATION_FAILED", "details": "Still open after fix"}
        mock_restore.return_value = {"restored": True}

        response = client.put(f"/platform/remediation/{rem_id}/approve")
        assert response.status_code == 200
        data = response.json()
        # Status MUST be FAILED because verification failed, not EXECUTED
        assert data["status"] == "FAILED"
        assert data["finding_status"] == "STILL_OPEN"

        # Check in DB
        check_db = TestingSessionLocal()
        saved = check_db.query(Remediation).filter(Remediation.id == rem_id).first()
        assert saved.status == "FAILED"
        check_db.close()




