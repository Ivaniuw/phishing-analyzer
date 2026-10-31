import json
from pathlib import Path

import pytest

from analyzer import llm
from analyzer.ioc import extract_iocs
from analyzer.parse_eml import parse_eml
from analyzer.report import build_report
from analyzer.rules import check_red_flags, score

SAMPLES = Path(__file__).parent.parent / "samples"

FAKE_ANSWER = {
    "verdict": "phishing",
    "confidence": "high",
    "summary": "Spoofed bank sender, failed DMARC and a link to a raw IP.",
    "actions": ["Block the domain", "Search for other recipients"],
}


@pytest.fixture
def analysis():
    email_data = parse_eml(SAMPLES / "phish_sample.eml")
    iocs = extract_iocs(email_data)
    flags = check_red_flags(email_data)
    total, verdict = score(flags)
    return email_data, iocs, flags, total, verdict


class FakeResponse:
    """Stands in for requests.Response, so tests run without Ollama."""

    def raise_for_status(self):
        pass

    def json(self):
        return {"response": json.dumps(FAKE_ANSWER)}


def test_ask_model_parses_json(monkeypatch, analysis):
    sent = {}

    def fake_post(url, json, timeout):
        sent.update(json)
        return FakeResponse()

    monkeypatch.setattr(llm.requests, "post", fake_post)
    email_data, iocs, flags, _, verdict = analysis
    answer = llm.ask_model(llm.build_facts(email_data, iocs, flags, verdict))

    assert answer == FAKE_ANSWER
    assert sent["format"] == "json"
    assert sent["options"]["temperature"] == 0


def test_body_is_truncated_for_the_model(analysis):
    email_data, iocs, flags, _, verdict = analysis
    email_data["body"] = "A" * 10_000
    facts = llm.build_facts(email_data, iocs, flags, verdict)
    assert len(facts["body_excerpt"]) == llm.MAX_BODY_CHARS


def test_report_without_ai_is_defanged(analysis):
    report = build_report(*analysis)
    assert "**Rule-based verdict:** likely phishing" in report
    assert "AI summary skipped" in report
    assert "hxxp://203[.]0[.]113[.]45" in report
    assert "http://203.0.113.45" not in report


def test_report_with_ai(analysis):
    report = build_report(*analysis, ai=FAKE_ANSWER)
    assert "**AI verdict:** phishing (confidence: high)" in report
    assert "- Block the domain" in report


def test_mitre_comes_from_rules_not_from_the_model(analysis):
    report = build_report(*analysis)
    assert ("**MITRE ATT&CK:** T1566.001 Spearphishing Attachment, "
            "T1566.002 Spearphishing Link, T1656 Impersonation") in report


def test_benign_mail_has_no_mitre():
    email_data = parse_eml(SAMPLES / "benign_sample.eml")
    flags = check_red_flags(email_data)
    report = build_report(email_data, extract_iocs(email_data), flags, *score(flags))
    assert "**MITRE ATT&CK:** -" in report
