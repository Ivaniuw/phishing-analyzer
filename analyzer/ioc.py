"""Extract indicators of compromise (IOCs) from a parsed e-mail.

IOCs come from code, not from the AI model: a model can invent a domain,
a regular expression cannot.
"""
import re
from urllib.parse import urlparse

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_ip(host):
    return bool(IP_RE.fullmatch(host))


def defang(value):
    """Make an IOC safe to paste into a report: nobody can click it by accident."""
    return value.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")


def extract_iocs(email_data):
    """Collect URLs, domains, IPs, e-mail addresses and file hashes."""
    domains = set()
    ips = set()

    for url in email_data["urls"]:
        host = (urlparse(url).hostname or "").lower()
        if is_ip(host):
            ips.add(host)
        elif host:
            domains.add(host)

    addresses = {a for a in (email_data["from_address"], email_data["reply_to"],
                             email_data["return_path"]) if a}
    # The From domain is often the brand being impersonated (a real bank), so it is
    # not an IOC: blocking it would also block the real bank's mail.
    for address in (email_data["reply_to"], email_data["return_path"]):
        if address:
            domains.add(address.rsplit("@", 1)[-1])
    domains.discard(email_data["from_domain"])

    # IPs of the servers that relayed the message, e.g. "[203.0.113.45]".
    for header in email_data["received"]:
        ips.update(IP_RE.findall(header))

    return {
        "urls": sorted(email_data["urls"]),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "emails": sorted(addresses),
        "sha256": sorted(a["sha256"] for a in email_data["attachments"]),
    }
