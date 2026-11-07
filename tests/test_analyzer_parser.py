"""Unit tests for analyzer JSON parsing resilience."""

from backend.analyzer import _parse_findings
from backend.models import LogChunk, Severity


def _make_dummy_chunk():
    return LogChunk(
        index=0,
        start_line=1,
        end_line=20,
        line_count=20,
        token_count=100,
        text="[L1] sample log line",
    )


def test_parse_direct_json_array():
    chunk = _make_dummy_chunk()
    raw = '''[
        {
            "type": "SQL Injection",
            "severity": "High",
            "ip": "203.0.113.72",
            "lines": [29, 30],
            "reason": "Union select probe",
            "action": "Block IP"
        }
    ]'''
    findings = _parse_findings(raw, chunk)
    assert len(findings) == 1
    assert findings[0].attack_type == "SQL Injection"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source_ip == "203.0.113.72"
    assert [e.line for e in findings[0].evidence] == [29, 30]


def test_parse_markdown_code_fence():
    chunk = _make_dummy_chunk()
    raw = '''Here are the threats detected:
```json
[
    {
        "type": "Path Scanning",
        "severity": "Medium",
        "ip": "203.0.113.90",
        "lines": [54, 56],
        "reason": "Attempting to probe .env and .git",
        "action": "Firewall rule"
    }
]
```
Hope this helps!'''
    findings = _parse_findings(raw, chunk)
    assert len(findings) == 1
    assert findings[0].attack_type == "Path Scanning"
    assert findings[0].source_ip == "203.0.113.90"


def test_parse_wrapper_object():
    chunk = _make_dummy_chunk()
    raw = '''{"findings": [
        {
            "attack_type": "Rate Limit Abuse",
            "severity": "Low",
            "source_ip": "203.0.113.155",
            "lines": [159, 160],
            "reason": "Rapid bursts",
            "recommended_action": "Rate limit"
        }
    ]}'''
    findings = _parse_findings(raw, chunk)
    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.155"


def test_parse_repaired_trailing_comma():
    chunk = _make_dummy_chunk()
    raw = '''[
        {
            "type": "Prompt Injection",
            "severity": "Medium",
            "ip": "203.0.113.201",
            "lines": [217],
            "reason": "Attempted to inject prompt instructions in support message",
            "action": "Sanitize and block",
        },
    ]'''
    findings = _parse_findings(raw, chunk)
    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.201"
    assert [e.line for e in findings[0].evidence] == [217]


def test_parse_empty_array_or_no_threats():
    chunk = _make_dummy_chunk()
    assert _parse_findings("[]", chunk) == []
    assert _parse_findings("No security threats detected in these lines.", chunk) == []

