"""
Parse raw email files (.eml), plain text, or dict payloads into a unified EmailDocument.
"""
import email
import email.policy
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EmailDocument:
    subject: str = ""
    sender: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    recipients: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    attachments: list[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Combined subject + body for analysis."""
        return f"{self.subject}\n{self.body_text}"


def _extract_domain(address: str) -> str:
    if "@" in address:
        return address.split("@")[-1].strip(">").lower()
    return ""


def parse_eml_file(path: Path) -> EmailDocument:
    raw = path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return _msg_to_doc(msg)


def parse_eml_string(raw: str) -> EmailDocument:
    msg = email.message_from_string(raw, policy=email.policy.default)
    return _msg_to_doc(msg)


def parse_plain_text(text: str, subject: str = "", sender: str = "") -> EmailDocument:
    return EmailDocument(
        subject=subject,
        sender=sender,
        sender_domain=_extract_domain(sender),
        body_text=text,
    )


def _msg_to_doc(msg) -> EmailDocument:
    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")

    body_text = ""
    body_html = ""
    attachments: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                attachments.append(part.get_filename() or "unknown")
            elif ct == "text/plain":
                body_text += part.get_content() or ""
            elif ct == "text/html":
                body_html += part.get_content() or ""
    else:
        ct = msg.get_content_type()
        if ct == "text/html":
            body_html = msg.get_content() or ""
        else:
            body_text = msg.get_content() or ""

    headers = {k: str(v) for k, v in msg.items()}

    return EmailDocument(
        subject=subject,
        sender=sender,
        sender_domain=_extract_domain(sender),
        reply_to=reply_to,
        reply_to_domain=_extract_domain(reply_to),
        recipients=[str(r) for r in msg.get_all("To", [])],
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        attachments=attachments,
    )
