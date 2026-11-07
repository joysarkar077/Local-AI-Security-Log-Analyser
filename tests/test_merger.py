"""Unit tests for finding merger and cross-chunk correlation."""

from backend.models import EvidenceItem, Finding, Severity
from backend.merger import merge_findings, _classify


def test_classify_attack_types():
    assert _classify("Failed Login Attempts") == "brute_force"
    assert _classify("Brute Force Attack") == "brute_force"
    assert _classify("SQL Injection Probing") == "sqli"
    assert _classify("UNION SELECT attempt") == "sqli"
    assert _classify("Directory Traversal") == "scanning"
    assert _classify("Sensitive File Access (.env)") == "scanning"
    assert _classify("Excessive Request Rate") == "rate_abuse"
    assert _classify("AI Prompt Injection Attempt") == "prompt_injection"
    assert _classify("Mass Data Export") == "data_exfil"


def test_merge_cross_chunk_brute_force_to_compromise():
    """Verify that failed logins in early chunks + successful login in late chunk
    correlate into a single Critical Account Compromise finding."""
    # Chunk 1 finding: 3 failed logins
    f1 = Finding(
        attack_type="Brute Force Login",
        severity=Severity.HIGH,
        source_ip="203.0.113.44",
        evidence=[
            EvidenceItem(line=5, description="Failed login for workspace.admin"),
            EvidenceItem(line=13, description="Failed login for workspace.admin"),
        ],
        reason="Repeated authentication failures",
        recommended_action="Block IP",
    )

    # Chunk 2 finding: more failures
    f2 = Finding(
        attack_type="Repeated Login Failure",
        severity=Severity.HIGH,
        source_ip="203.0.113.44",
        evidence=[
            EvidenceItem(line=23, description="Failed login for workspace.admin"),
            EvidenceItem(line=35, description="Failed login for workspace.admin"),
        ],
        reason="Ongoing brute force",
        recommended_action="Enforce lockout",
    )

    # Chunk 10 finding: successful login
    f3 = Finding(
        attack_type="Successful Login after Failures",
        severity=Severity.HIGH,
        source_ip="203.0.113.44",
        evidence=[
            EvidenceItem(line=196, description="Successful login for workspace.admin with session sess-demo-8f20"),
        ],
        reason="Brute force succeeded",
        recommended_action="Revoke session",
    )

    # Chunk 11 finding: data export
    f4 = Finding(
        attack_type="Unauthorized Data Export",
        severity=Severity.HIGH,
        source_ip="203.0.113.44",
        evidence=[
            EvidenceItem(line=201, description="Exported workspace data (2.8 MB)"),
        ],
        reason="Exfiltration after login",
        recommended_action="Audit export logs",
    )

    merged = merge_findings([f1, f2, f3, f4])

    assert len(merged) == 1, f"Expected 1 correlated finding, got {len(merged)}"
    res = merged[0]
    assert res.source_ip == "203.0.113.44"
    assert res.severity == Severity.CRITICAL, "Must escalate to Critical upon compromise/exfiltration"
    assert "Compromise" in res.attack_type

    # Verify all evidence lines are preserved and sorted
    lines = [e.line for e in res.evidence]
    assert lines == [5, 13, 23, 35, 196, 201]


def test_merge_vulnerability_scanning():
    """Verify that multiple probe paths from same IP merge into unified Reconnaissance."""
    f1 = Finding(
        attack_type="Sensitive File Probe (.env)",
        severity=Severity.MEDIUM,
        source_ip="203.0.113.90",
        evidence=[EvidenceItem(line=54, description="GET /.env")],
    )
    f2 = Finding(
        attack_type="Directory Traversal",
        severity=Severity.MEDIUM,
        source_ip="203.0.113.90",
        evidence=[EvidenceItem(line=99, description="GET /api/v1/files?name=../../etc/passwd")],
    )

    merged = merge_findings([f1, f2])
    assert len(merged) == 1
    assert merged[0].source_ip == "203.0.113.90"
    assert [e.line for e in merged[0].evidence] == [54, 99]


def test_severity_ordering():
    """Verify findings are sorted with Critical first, then High, Medium, Low."""
    f_low = Finding(attack_type="Info Probe", severity=Severity.LOW, source_ip="1.1.1.1")
    f_crit = Finding(attack_type="Account Takeover", severity=Severity.CRITICAL, source_ip="2.2.2.2")
    f_med = Finding(attack_type="Scanner", severity=Severity.MEDIUM, source_ip="3.3.3.3")

    merged = merge_findings([f_low, f_crit, f_med])
    assert [f.severity for f in merged] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert [f.id for f in merged] == [1, 2, 3]

