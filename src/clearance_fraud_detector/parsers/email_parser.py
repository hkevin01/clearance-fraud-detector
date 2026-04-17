"""
Parse raw email files (.eml), plain text, or dict payloads into a unified EmailDocument.
"""
import email
import email.policy
import html as _html_lib
import re as _re
from dataclasses import dataclass, field
from pathlib import Path


def _strip_html(html_text: str) -> str:
    """
    Convert HTML email body to plain text for rule-engine scanning.

    Removes script/style blocks, converts block elements to newlines,
    strips remaining tags, and decodes HTML entities. This ensures fraud
    signals embedded in HTML-only emails are exposed to the regex pattern
    library rather than being silently ignored.
    """
    # Drop script/style blocks entirely — they can't contain actionable fraud text
    text = _re.sub(
        r'<(?:script|style)[^>]*>.*?</(?:script|style)>',
        ' ', html_text, flags=_re.DOTALL | _re.IGNORECASE,
    )
    # Replace common block/line elements with newlines to preserve sentence boundaries
    text = _re.sub(r'<(?:br|p|div|tr|li|h[1-6])[^>]*/?>',
                   '\n', text, flags=_re.IGNORECASE)
    # Strip all remaining HTML tags
    text = _re.sub(r'<[^>]+>', ' ', text)
    # Decode HTML character entities (&amp; &lt; &#160; etc.)
    text = _html_lib.unescape(text)
    # Normalise horizontal whitespace; collapse excessive blank lines
    text = _re.sub(r'[ \t]+', ' ', text)
    text = _re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


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
        """
        Combined subject + body for rule-engine analysis.

        Uses plain-text body when present; falls back to HTML-stripped body so
        that HTML-only emails are not silently skipped by the pattern library.
        """
        body = self.body_text.strip()
        if not body and self.body_html:
            body = _strip_html(self.body_html)
        return f"{self.subject}\n{body}"


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
