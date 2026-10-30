from pathlib import Path

import pytest

from analyzer.parse_eml import parse_auth_results, parse_eml

SAMPLE = Path(__file__).parent.parent / "samples" / "phish_sample.eml"


@pytest.fixture
def phish():
    return parse_eml(SAMPLE)


def test_sender_headers(phish):
    assert phish["from_address"] == "security@bank.example"
    assert phish["from_domain"] == "bank.example"
    assert phish["reply_to"] == "support@secure-pay.test"
    assert phish["return_path"] == "bounce@mailer.secure-pay.test"
    assert phish["subject"].startswith("Urgent")


def test_authentication_results(phish):
    assert phish["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


def test_urls_from_body(phish):
    assert phish["urls"] == [
        "http://203.0.113.45/login/verify?id=88231",
        "https://bank-example.secure-pay.test/account/confirm",
    ]


def test_attachment_is_hashed_not_opened(phish):
    attachment = phish["attachments"][0]
    assert attachment["filename"] == "invoice.html"
    assert attachment["content_type"] == "text/html"
    assert len(attachment["sha256"]) == 64


@pytest.mark.parametrize("header, expected", [
    ("spf=pass dkim=pass dmarc=pass", {"spf": "pass", "dkim": "pass", "dmarc": "pass"}),
    ("SPF=SoftFail", {"spf": "softfail", "dkim": "none", "dmarc": "none"}),
    ("", {"spf": "none", "dkim": "none", "dmarc": "none"}),
])
def test_parse_auth_results(header, expected):
    assert parse_auth_results(header) == expected
