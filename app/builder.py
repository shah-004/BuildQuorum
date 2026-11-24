from __future__ import annotations

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.security import ValidationError


class BuildError(Exception):
    """Raised when a build times out or fails unexpectedly."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class BuildResult:
    build_hash: str
    artifact_bytes: bytes
    build_mode: str  # "gcc-deterministic" or "simulated-deterministic"


def normalize_source(raw_bytes: bytes) -> tuple[str, bytes, str]:
    """Strip UTF-8 BOM and normalize line endings (\r\n and \r -> \n)."""
    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("Source file must be valid UTF-8 text.", status_code=400) from exc

    normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized_bytes = normalized_text.encode("utf-8")
    source_hash = hashlib.sha256(normalized_bytes).hexdigest()
    return normalized_text, normalized_bytes, source_hash


def _compile_c_once(c_source: str, out_path: Path, timeout_seconds: int) -> bytes:
    """Compile C source to an object file without executing it."""
    cmd = [
        "gcc",
        "-x",
        "c",
        "-",
        "-c",
        "-O2",
        "-std=c11",
        "-fno-ident",
        "-w",
        "-o",
        str(out_path),
    ]
    proc = subprocess.run(
        cmd,
        input=c_source.encode("utf-8"),
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if proc.returncode != 0 or not out_path.exists():
        stderr_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise BuildError(f"gcc compilation failed: {stderr_msg or 'unknown error'}", status_code=400)
    return out_path.read_bytes()


def check_gcc_deterministic(timeout_seconds: int = 5) -> bool:
    """Startup self-check: verify gcc exists and produces identical bytes across two runs."""
    probe_c = "int add_two(int x) { return x + 2; }\n"
    try:
        with tempfile.TemporaryDirectory(prefix="bq_gcc_check_") as tmp:
            tmp_dir = Path(tmp)
            out1 = tmp_dir / "probe1.o"
            out2 = tmp_dir / "probe2.o"
            b1 = _compile_c_once(probe_c, out1, timeout_seconds)
            b2 = _compile_c_once(probe_c, out2, timeout_seconds)
            return len(b1) > 0 and b1 == b2
    except (FileNotFoundError, subprocess.TimeoutExpired, BuildError, OSError):
        return False


def build_artifact(
    normalized_source: str,
    extension: str,
    package_name: str,
    version: str,
    gcc_usable: bool,
    settings: Settings,
) -> BuildResult:
    """Deterministically build an artifact from normalized source without executing untrusted code."""
    ext = extension.lower()
    src_hash = hashlib.sha256(normalized_source.encode("utf-8")).hexdigest()

    if ext == ".c" and gcc_usable:
        try:
            with tempfile.TemporaryDirectory(prefix="bq_build_") as tmp:
                out_obj = Path(tmp) / "artifact.o"
                compiled_bytes = _compile_c_once(
                    normalized_source,
                    out_obj,
                    timeout_seconds=settings.build_timeout_seconds,
                )
                # Wrap compiled object bytes deterministically with canonical metadata header
                header = (
                    f"BUILDQUORUM_GCC_OBJ\nname={package_name}\nversion={version}\n"
                    f"src_sha256={src_hash}\nlen={len(compiled_bytes)}\n---\n"
                ).encode("utf-8")
                artifact = header + compiled_bytes
                digest = hashlib.sha256(artifact).hexdigest()
                return BuildResult(
                    build_hash=digest,
                    artifact_bytes=artifact,
                    build_mode="gcc-deterministic",
                )
        except subprocess.TimeoutExpired as exc:
            raise BuildError(
                f"Build timed out after {settings.build_timeout_seconds} seconds.",
                status_code=408,
            ) from exc

    # Simulated deterministic build (for .py, .txt, or when gcc is unavailable/non-deterministic)
    payload = (
        f"BUILDQUORUM_SIM_ARTIFACT_V1\n"
        f"ext={ext}\n"
        f"package={package_name}\n"
        f"version={version}\n"
        f"source_sha256={src_hash}\n"
        f"source_len={len(normalized_source.encode('utf-8'))}\n"
        f"---BEGIN_SOURCE---\n"
        f"{normalized_source}"
        f"\n---END_SOURCE---\n"
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return BuildResult(
        build_hash=digest,
        artifact_bytes=payload,
        build_mode="simulated-deterministic",
    )


def prepare_published_artifact(clean_artifact: bytes, compromised: bool) -> tuple[bytes, str]:
    """Return published artifact bytes and its SHA-256 hash, injecting bytes if compromised."""
    if compromised:
        injected = clean_artifact + b"\n/* COMPROMISED_PUBLISHER_INJECTED_BYTES:0xDEADCAFE */\n"
        return injected, hashlib.sha256(injected).hexdigest()
    return clean_artifact, hashlib.sha256(clean_artifact).hexdigest()