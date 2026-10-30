from pathlib import Path

import pytest

from analyzer.ioc import defang, extract_iocs
from analyzer.parse_eml import parse_eml
from analyzer.rules import check_red_flags, score

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture
def phish():
    return parse_eml(SAMPLES / "phish_sample.eml")


@pytest.fixture
def benign():
    return parse_eml(SAMPLES / "benign_sample.eml")


def test_iocs_from_phish(phish):
    iocs = extract_iocs(phish)
    assert iocs["ips"] == ["203.0.113.45"]
    assert "bank-example.secure-pay.test" in iocs["domains"]
    assert "secure-pay.test" in iocs["domains"]
    assert iocs["emails"] == ["bounce@mailer.secure-pay.test", "security@bank.example",
                              "support@secure-pay.test"]
    assert len(iocs["sha256"]) == 1


def test_defang():
    assert defang("http://evil.test/login") == "hxxp://evil[.]test/login"
    assert defang("a@evil.test") == "a[@]evil[.]test"


def test_phish_red_flags(phish):
    ids = {f["id"] for f in check_red_flags(phish)}
    assert {"dmarc_fail", "spf_fail", "reply_to_mismatch", "ip_in_url",
            "link_domain_mismatch", "dangerous_attachment", "urgency"} <= ids


def test_phish_verdict(phish):
    total, verdict = score(check_red_flags(phish))
    assert verdict == "likely phishing"
    assert total >= 6


def test_benign_has_no_flags(benign):
    flags = check_red_flags(benign)
    assert flags == []
    assert score(flags) == (0, "no strong indicators")


def test_subdomain_of_sender_is_not_a_mismatch(benign):
    # Return-Path is mail.shop.example, sender is shop.example - same organisation.
    ids = {f["id"] for f in check_red_flags(benign)}
    assert "return_path_mismatch" not in ids
