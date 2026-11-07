"""End-to-end integration test verifying the complete analysis and correlation pipeline
against the actual assessment log file (Cultive8_Workspace_Agrigen_Server.log)."""

from pathlib import Path
from backend.models import EvidenceItem, Finding, Severity
from backend.merger import merge_findings
from backend.splitter import split_log_file
from backend import config

LOG_PATH = Path(__file__).resolve().parent.parent / "Cultive8_Workspace_Agrigen_Server.log"


def test_chunking_telemetry_on_real_log():
    """Verify that Cultive8_Workspace_Agrigen_Server.log chunks satisfy all rubric requirements."""
    chunks = split_log_file(LOG_PATH, config.DATA_TOKEN_BUDGET)

    assert len(chunks) > 0
    total_lines = sum(c.line_count for c in chunks)
    assert total_lines == 258

    # Check token limits on every single chunk
    for c in chunks:
        assert c.token_count <= config.DATA_TOKEN_BUDGET
        # Verify lines are not cut mid-entry
        for line in c.text.split("\n"):
            assert line.startswith("[L")
            assert "{" in line and "}" in line


def test_cross_chunk_threat_correlation():
    """Simulate findings produced across multiple chunks representing the 6 distinct threats
    in Cultive8_Workspace_Agrigen_Server.log and verify the merged security report."""

    raw_chunk_findings = [
        # Threat 1 (Early chunks): Brute-force failed logins
        Finding(
            attack_type="Failed Login Attempts",
            severity=Severity.HIGH,
            source_ip="203.0.113.44",
            evidence=[
                EvidenceItem(line=5, description="Failed login: workspace.admin"),
                EvidenceItem(line=13, description="Failed login: workspace.admin"),
                EvidenceItem(line=23, description="Failed login: workspace.admin"),
            ],
            reason="Automated login failures using python-requests",
            recommended_action="Block IP and enable rate limiting",
        ),
        # Threat 2: SQL Injection probing
        Finding(
            attack_type="SQL Injection Probing",
            severity=Severity.HIGH,
            source_ip="203.0.113.72",
            evidence=[
                EvidenceItem(line=29, description="GET /api/v1/crops?search=' OR 1=1--"),
                EvidenceItem(line=30, description="GET /api/v1/crops?search=' UNION SELECT NULL,NULL--"),
                EvidenceItem(line=32, description="GET /api/v1/crops?id=1;SELECT SLEEP(5)--"),
            ],
            reason="Classic SQL injection test payloads blocked by input validation",
            recommended_action="Block IP at WAF and review parameterized queries",
        ),
        # Threat 3: Vulnerability path scanning
        Finding(
            attack_type="Vulnerability Path Scanning",
            severity=Severity.MEDIUM,
            source_ip="203.0.113.90",
            evidence=[
                EvidenceItem(line=54, description="Probing /.env"),
                EvidenceItem(line=56, description="Probing /.git/config"),
                EvidenceItem(line=58, description="Probing /wp-admin/"),
                EvidenceItem(line=60, description="Probing /phpmyadmin/"),
                EvidenceItem(line=99, description="Path traversal /api/v1/files?name=../../etc/passwd"),
            ],
            reason="Automated reconnaissance scanning sensitive system paths",
            recommended_action="Drop traffic from IP and enforce strict 404/403 rules",
        ),
        # Threat 1 (Middle chunk): Continued brute-force
        Finding(
            attack_type="Brute Force Login",
            severity=Severity.HIGH,
            source_ip="203.0.113.44",
            evidence=[
                EvidenceItem(line=35, description="Failed login: workspace.admin"),
                EvidenceItem(line=50, description="Failed login: workspace.admin"),
                EvidenceItem(line=65, description="Failed login: workspace.admin"),
                EvidenceItem(line=80, description="Failed login: workspace.admin"),
                EvidenceItem(line=94, description="Failed login: workspace.admin"),
                EvidenceItem(line=108, description="Failed login: workspace.admin"),
                EvidenceItem(line=123, description="Failed login: workspace.admin"),
                EvidenceItem(line=153, description="Failed login: workspace.admin"),
                EvidenceItem(line=189, description="Failed login: workspace.admin"),
            ],
            reason="Persistent password guessing across 2 hours",
            recommended_action="Lock account workspace.admin",
        ),
        # Threat 4: Rate limit abuse
        Finding(
            attack_type="API Rate Limit Abuse",
            severity=Severity.MEDIUM,
            source_ip="203.0.113.155",
            evidence=[
                EvidenceItem(line=159, description="GET /api/v1/weather (window=124)"),
                EvidenceItem(line=162, description="HTTP 429 Too Many Requests (window=127)"),
                EvidenceItem(line=170, description="HTTP 429 Too Many Requests (window=135)"),
            ],
            reason="Rapid burst of requests exceeding API window threshold",
            recommended_action="Temporarily throttle or blacklist client IP",
        ),
        # Threat 1 (Late chunks): Compromise followed by data exfiltration!
        Finding(
            attack_type="Account Compromise",
            severity=Severity.CRITICAL,
            source_ip="203.0.113.44",
            evidence=[
                EvidenceItem(line=196, description="HTTP 200 Success login for workspace.admin (session sess-demo-8f20)"),
                EvidenceItem(line=198, description="GET /api/v1/admin/users using session sess-demo-8f20"),
            ],
            reason="Attacker successfully authenticated following brute-force campaign",
            recommended_action="Terminate session sess-demo-8f20 immediately and reset credentials",
        ),
        Finding(
            attack_type="Unauthorized Data Export",
            severity=Severity.HIGH,
            source_ip="203.0.113.44",
            evidence=[
                EvidenceItem(line=201, description="GET /api/v1/workspaces/7/export?format=csv (2.84 MB)"),
            ],
            reason="Post-compromise bulk database exfiltration",
            recommended_action="Audit exported records and report breach",
        ),
        # Threat 5: AI Prompt Injection in user-submitted support message
        Finding(
            attack_type="Prompt Injection Attempt",
            severity=Severity.MEDIUM,
            source_ip="203.0.113.201",
            evidence=[
                EvidenceItem(
                    line=217,
                    description="POST /api/v1/support/messages containing 'Ignore previous instructions...'"
                ),
            ],
            reason="Malicious prompt injection string submitted in support body; blocked with 422",
            recommended_action="Flag IP and verify input sanitization on all text fields",
        ),
        # Threat 2 (Late chunk): SQL Injection repeated probe
        Finding(
            attack_type="SQL Injection Probing",
            severity=Severity.HIGH,
            source_ip="203.0.113.72",
            evidence=[
                EvidenceItem(line=222, description="GET /api/v1/crops?search=' OR 1=1--"),
            ],
            reason="Repeated SQL injection payload",
            recommended_action="Block IP",
        ),
    ]

    merged = merge_findings(raw_chunk_findings)

    # 1. Total findings should be grouped by IP/threat into exactly 5 consolidated threats
    # - 203.0.113.44: Brute-Force + Compromise + Exfil (Merged into 1 Critical)
    # - 203.0.113.72: SQL Injection (Merged into 1 High)
    # - 203.0.113.90: Vulnerability Reconnaissance (Merged into 1 Medium)
    # - 203.0.113.155: Rate Limit Abuse (1 Medium)
    # - 203.0.113.201: Prompt Injection (1 Medium)
    assert len(merged) == 5, f"Expected 5 consolidated threats, got {len(merged)}"

    # 2. Top finding must be the Critical account takeover
    top = merged[0]
    assert top.severity == Severity.CRITICAL
    assert top.source_ip == "203.0.113.44"
    assert "Compromise" in top.attack_type
    assert "Exfiltration" in top.attack_type or "Exfil" in top.attack_type
    # Must contain lines 5 through 201
    compromise_lines = [e.line for e in top.evidence]
    assert 5 in compromise_lines
    assert 196 in compromise_lines
    assert 201 in compromise_lines

    # 3. SQL injection finding
    sqli = next(f for f in merged if f.source_ip == "203.0.113.72")
    assert sqli.severity == Severity.HIGH
    sqli_lines = [e.line for e in sqli.evidence]
    assert 29 in sqli_lines and 222 in sqli_lines

    # 4. Prompt injection finding (IP 203.0.113.201)
    prompt_inj = next(f for f in merged if f.source_ip == "203.0.113.201")
    assert prompt_inj.attack_type == "Prompt Injection Attempt"
    assert prompt_inj.evidence[0].line == 217

    # 5. Check all findings comply with assessment instruction criteria
    for f in merged:
        assert f.attack_type != ""
        assert f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        assert f.source_ip != ""
        assert len(f.evidence) > 0
        for ev in f.evidence:
            assert ev.line > 0
        assert f.reason != ""
        assert f.recommended_action != ""

