"""Read an .eml file and pull out the parts an analyst checks first."""
import email
import hashlib
import re
from email import policy
from email.utils import parseaddr

# A URL starts with http:// or https:// and ends at whitespace, a quote or a bracket.
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


def parse_auth_results(value):
    """Return SPF, DKIM and DMARC results from an Authentication-Results header."""
    results = {}
    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{check}=(\w+)", value or "", re.IGNORECASE)
        results[check] = match.group(1).lower() if match else "none"
    return results


def domain_of(address):
    """security@bank.example -> bank.example"""
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def parse_eml(path):
    """Parse one e-mail file into a plain dictionary."""
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    from_name, from_address = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))

    body_parts = []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            # Never open an attachment - only measure and hash it.
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        elif part.get_content_type() in ("text/plain", "text/html"):
            body_parts.append(part.get_content())

    body = "\n".join(body_parts)
    urls = sorted({url.rstrip(".,;") for url in URL_RE.findall(body)})

    return {
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "from_name": from_name,
        "from_address": from_address.lower(),
        "from_domain": domain_of(from_address),
        "reply_to": reply_to.lower(),
        "return_path": return_path.lower(),
        "received": msg.get_all("Received", []),
        "auth": parse_auth_results(msg.get("Authentication-Results", "")),
        "body": body,
        "urls": urls,
        "attachments": attachments,
    }
