"""
Unit tests for Masooma's module: risk scoring, safety gate tiering, and
the AI template fallback (no live AWS or Groq calls -- everything here
is either pure logic or mocked, same pattern as tests/test_scanners.py).
"""

import pytest
from backend.services.ai import risk_engine, safety_gate, ai_engine, pipeline

PUBLIC_BUCKET = {
    "finding_id": "f1", "resource_id": "my-bucket", "resource_type": "s3_bucket",
    "finding": "Bucket is publicly accessible", "severity": "HIGH", "category": "PUBLIC_ACCESS",
    "evidence": {"public": True}, "status": "OPEN",
}
ROOT_NO_MFA = {
    "finding_id": "f2", "resource_id": "root", "resource_type": "iam_account",
    "finding": "Root account MFA is not enabled", "severity": "CRITICAL", "category": "IDENTITY_SECURITY",
    "evidence": {"root_mfa_enabled": False}, "status": "OPEN",
}
VERSIONING_OFF = {
    "finding_id": "f3", "resource_id": "my-bucket-2", "resource_type": "s3_bucket",
    "finding": "Versioning is disabled", "severity": "MEDIUM", "category": "DATA_PROTECTION",
    "evidence": {"versioning_enabled": False}, "status": "OPEN",
}
RESOLVED_FINDING = {
    "finding_id": "f4", "resource_id": "my-bucket-3", "resource_type": "s3_bucket",
    "finding": "Encryption is enabled", "severity": "INFO", "category": "DATA_PROTECTION",
    "evidence": {"encryption_enabled": True}, "status": "RESOLVED",
}


# ---------- Risk Engine ----------

def test_public_bucket_scores_high_exposure():
    risk = risk_engine.score_finding(PUBLIC_BUCKET)
    assert risk["exposure"] == 1.0
    assert 0 <= risk["risk_score"] <= 10

def test_root_no_mfa_is_highest_criticality():
    risk = risk_engine.score_finding(ROOT_NO_MFA)
    assert risk["asset_criticality"] == 1.0
    assert risk["priority"] in ("P1", "P2")

def test_info_severity_scores_zero():
    risk = risk_engine.score_finding(RESOLVED_FINDING)
    assert risk["risk_score"] == 0.0

def test_score_findings_sorts_highest_risk_first():
    scored = risk_engine.score_findings([VERSIONING_OFF, ROOT_NO_MFA, PUBLIC_BUCKET])
    scores = [f["risk"]["risk_score"] for f in scored]
    assert scores == sorted(scores, reverse=True)


# ---------- Safety Gate ----------

def test_root_mfa_is_never_auto():
    decision = safety_gate.gate(ROOT_NO_MFA)
    assert decision["tier"] == safety_gate.NEVER_AUTO
    assert decision["can_execute"] is False

def test_versioning_disabled_is_auto_allowed():
    decision = safety_gate.gate(VERSIONING_OFF)
    assert decision["tier"] == safety_gate.AUTO_ALLOWED
    assert decision["can_execute"] is True

def test_public_bucket_requires_approval():
    decision = safety_gate.gate(PUBLIC_BUCKET)
    assert decision["tier"] == safety_gate.APPROVAL_REQUIRED
    assert decision["requires_approval"] is True

def test_resolved_finding_is_not_executable():
    decision = safety_gate.gate(RESOLVED_FINDING)
    assert decision["can_execute"] is False


# ---------- AI Analysis Engine (template fallback, no Groq key set) ----------

def test_ai_analysis_falls_back_to_template_without_groq_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    risk = risk_engine.score_finding(PUBLIC_BUCKET)
    analysis = ai_engine.analyze_finding(PUBLIC_BUCKET, risk)
    assert analysis["source"] == "template"
    assert all(k in analysis for k in ("explanation", "impact", "attack_scenario", "recommendation", "confidence"))

def test_resolved_finding_gets_no_action_needed_analysis():
    risk = risk_engine.score_finding(RESOLVED_FINDING)
    analysis = ai_engine.analyze_finding(RESOLVED_FINDING, risk)
    assert analysis["recommendation"] == "No action needed."


# ---------- Pipeline ----------

def test_analyze_scan_groups_by_tier(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = pipeline.analyze_scan([PUBLIC_BUCKET, ROOT_NO_MFA, VERSIONING_OFF, RESOLVED_FINDING])
    assert result["total_analyzed"] == 3  # RESOLVED_FINDING excluded (open_only default)
    assert sum(result["by_tier"].values()) == 3
    assert result["findings"][0]["risk"]["risk_score"] >= result["findings"][-1]["risk"]["risk_score"]
