from __future__ import annotations

import re
from pathlib import Path

from app.config import Settings


class ValidationError(Exception):
    """Raised when uploaded metadata or source content fails safety checks."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[>"]', re.MULTILINE)
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(raw_filename: str | None) -> str:
    if not raw_filename:
        raise ValidationError("Filename is required.", status_code=400)

    # Strip any Windows or POSIX directory components
    base_name = Path(raw_filename.replace("\\", "/")).name
    cleaned = _SAFE_NAME_RE.sub("_", base_name).strip("._")

    if not cleaned:
        raise ValidationError("Invalid filename.", status_code=400)

    ext = Path(cleaned).suffix.lower()
    stem = _SAFE_NAME_RE.sub("_", Path(cleaned).stem).strip("._") or "source"
    return f"{stem}{ext}"


def validate_upload(
    filename: str | None,
    content: bytes,
    package_name: str,
    version: str,
    settings: Settings,
) -> tuple[str, str]:
    if not package_name or not package_name.strip():
        raise ValidationError("Package name must not be empty.", status_code=400)
    if len(package_name.strip()) > 100:
        raise ValidationError("Package name is too long (max 100 chars).", status_code=400)

    if not version or not version.strip():
        raise ValidationError("Version must not be empty.", status_code=400)
    if len(version.strip()) > 40:
        raise ValidationError("Version string is too long (max 40 chars).", status_code=400)

    if len(content) == 0:
        raise ValidationError("Uploaded file is empty.", status_code=400)

    if len(content) > settings.max_upload_bytes:
        raise ValidationError(
            f"File size ({len(content)} bytes) exceeds maximum allowed ({settings.max_upload_bytes} bytes).",
            status_code=413,
        )

    safe_name = sanitize_filename(filename)
    ext = Path(safe_name).suffix.lower()

    if ext not in settings.allowed_extensions:
        allowed = ", ".join(sorted(settings.allowed_extensions))
        raise ValidationError(
            f"Unsupported file extension '{ext or '(none)'}'. Allowed extensions: {allowed}.",
            status_code=400,
        )

    # Ensure content can be decoded as text
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("Source file must be valid UTF-8 text.", status_code=400) from exc

    if ext == ".c":
        check_c_includes(text, settings)

    return safe_name, ext


def check_c_includes(c_source: str, settings: Settings) -> None:
    for match in _INCLUDE_RE.finditer(c_source):
        header = match.group(1).strip().lower()
        header_base = Path(header).name.lower()
        if header in settings.blocked_c_headers or header_base in settings.blocked_c_headers:
            raise ValidationError(
                f"Risky C include '{match.group(1).strip()}' is not allowed.",
                status_code=400,
            )