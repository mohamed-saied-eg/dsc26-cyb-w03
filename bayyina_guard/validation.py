"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

_BIDI = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_MAGIC = {"pdf": b"%PDF-", "docx": b"PK\x03\x04"}
_MATTER_RE = re.compile(r"MAT-\d{4}-\d{5}", re.ASCII)


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(name):
    """Returns (error_or_None, nfc_name, ext)."""
    if not isinstance(name, str):
        return "must be a string", None, None
    nfc = unicodedata.normalize("NFC", name)
    if not 1 <= len(nfc) <= 120:
        return "length must be 1-120", None, None
    for ch in nfc:
        if unicodedata.category(ch) == "Cc" or ch in _BIDI:
            return "control or bidi character", None, None
    if "/" in nfc or "\\" in nfc or ".." in nfc:
        return "path characters not allowed", None, None
    if nfc.startswith("."):
        return "must not start with a dot", None, None
    if "." not in nfc:
        return "missing extension", None, None
    base, ext = nfc.rsplit(".", 1)
    ext = ext.lower()
    if ext not in _CONTENT_TYPES:
        return "extension must be pdf or docx", None, None
    if not base.strip():
        return "name part is blank", None, None
    return None, nfc, ext


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    errors = {}

    fn_err, display, ext = _check_filename(meta.get("filename"))
    if fn_err:
        errors["filename"] = fn_err

    ct = meta.get("content_type")
    if fn_err:
        if not isinstance(ct, str):
            errors["content_type"] = "must be a string"
    elif ct != _CONTENT_TYPES[ext]:
        errors["content_type"] = "does not match extension"

    fb = meta.get("first_bytes")
    if not isinstance(fb, bytes):
        errors["first_bytes"] = "must be bytes"
    elif not fn_err and not fb.startswith(_MAGIC[ext]):
        errors["first_bytes"] = "signature does not match extension"

    size = meta.get("size_bytes")
    if type(size) is not int or not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = "must be an int from 1 to MAX_BYTES"

    mid = meta.get("matter_id")
    if not isinstance(mid, str) or not _MATTER_RE.fullmatch(mid):
        errors["matter_id"] = "invalid matter id"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=uuid.uuid4().hex + "." + ext,
        display_name=display,
        extension=ext,
        content_type=_CONTENT_TYPES[ext],
        size_bytes=size,
        matter_id=mid,
    )