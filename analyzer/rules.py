"""Simple, explainable red flags - the same checks an analyst does by hand."""
from pathlib import PurePath
from urllib.parse import urlparse

from analyzer.ioc import is_ip
from analyzer.parse_eml import domain_of

WEIGHTS = {"high": 3, "medium": 2, "low": 1}

DANGEROUS_EXTENSIONS = {".html", ".htm", ".exe", ".scr", ".js", ".vbs", ".lnk",
                        ".iso", ".img", ".zip", ".rar", ".docm", ".xlsm"}

URGENCY_WORDS = ["urgent", "suspended", "24 hours", "verify your account", "immediately",
                 "pilne", "zablokowane", "natychmiast", "zweryfikuj"]


def same_org(domain, from_domain):
    """mail.bank.example belongs to bank.example."""
    return domain == from_domain or domain.endswith("." + from_domain)


def check_red_flags(email_data):
    """Return a list of red flags: {"id", "severity", "detail"}."""
    flags = []
    from_domain = email_data["from_domain"]

    def flag(flag_id, severity, detail):
        flags.append({"id": flag_id, "severity": severity, "detail": detail})

    auth = email_data["auth"]
    if auth["dmarc"] == "fail":
        flag("dmarc_fail", "high", f"DMARC failed for {from_domain} - the sender is likely spoofed")
    if auth["spf"] in ("fail", "softfail"):
        flag("spf_fail", "medium", f"SPF result: {auth['spf']}")
    if auth["dkim"] in ("fail", "none"):
        flag("dkim_missing", "low", f"DKIM result: {auth['dkim']}")

    reply_domain = domain_of(email_data["reply_to"])
    if reply_domain and not same_org(reply_domain, from_domain):
        flag("reply_to_mismatch", "high", f"Replies go to {reply_domain}, not {from_domain}")

    return_domain = domain_of(email_data["return_path"])
    if return_domain and not same_org(return_domain, from_domain):
        flag("return_path_mismatch", "medium", f"Return-Path domain is {return_domain}")

    for url in email_data["urls"]:
        host = (urlparse(url).hostname or "").lower()
        if is_ip(host):
            flag("ip_in_url", "high", f"Link points to a raw IP address: {host}")
        elif host and not same_org(host, from_domain):
            flag("link_domain_mismatch", "medium", f"Link goes to {host}, not {from_domain}")

    for attachment in email_data["attachments"]:
        extension = PurePath(attachment["filename"]).suffix.lower()
        if extension in DANGEROUS_EXTENSIONS:
            flag("dangerous_attachment", "high", f"Risky attachment type: {attachment['filename']}")

    text = (email_data["subject"] + " " + email_data["body"]).lower()
    found = [word for word in URGENCY_WORDS if word in text]
    if found:
        flag("urgency", "low", "Pressure words: " + ", ".join(found))

    return flags


def score(flags):
    """Add up the weights and turn them into a rule-based verdict."""
    total = sum(WEIGHTS[f["severity"]] for f in flags)
    if total >= 6:
        verdict = "likely phishing"
    elif total >= 3:
        verdict = "suspicious"
    else:
        verdict = "no strong indicators"
    return total, verdict
