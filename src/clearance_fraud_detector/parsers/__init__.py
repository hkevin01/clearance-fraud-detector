"""Email parsers — .eml files, raw strings, and plain-text inputs → EmailDocument."""

from .email_parser import (
    EmailDocument,
    _strip_html,
    parse_eml_file,
    parse_eml_string,
    parse_plain_text,
)

__all__ = [
    "EmailDocument",
    "_strip_html",
    "parse_eml_file",
    "parse_eml_string",
    "parse_plain_text",
]