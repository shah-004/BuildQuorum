from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    # Validator & consensus settings
    validator_ids: list[str] = field(default_factory=lambda: ["V1", "V2", "V3", "V4"])
    quorum_threshold: int = 3

    # Upload & build settings
    max_upload_bytes: int = 100 * 1024  # 100 KB
    allowed_extensions: set[str] = field(default_factory=lambda: {".c", ".py", ".txt"})
    build_timeout_seconds: int = 10
    min_delay_seconds: float = 0.15
    max_delay_seconds: float = 0.60
    enable_delays: bool = True

    # Risky C headers (compile-only guard; never executes code)
    blocked_c_headers: set[str] = field(
        default_factory=lambda: {
            "process.h",
            "winsock2.h",
            "ws2tcpip.h",
            "windows.h",
            "sys/socket.h",
            "netdb.h",
            "arpa/inet.h",
            "unistd.h",
            "fcntl.h",
            "dlfcn.h",
            "sys/wait.h",
        }
    )

    # Paths
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data")
    static_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "static")

    @property
    def chain_file(self) -> Path:
        return self.data_dir / "chain.json"

    @property
    def snapshot_file(self) -> Path:
        return self.data_dir / "chain_snapshot.json"

    @property
    def keys_file(self) -> Path:
        return self.data_dir / "validator_keys.json"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    settings = Settings()

    data_override = os.getenv("BUILDQUORUM_DATA_DIR")
    if data_override:
        settings.data_dir = Path(data_override)

    static_override = os.getenv("BUILDQUORUM_STATIC_DIR")
    if static_override:
        settings.static_dir = Path(static_override)

    delays_env = os.getenv("BUILDQUORUM_ENABLE_DELAYS")
    if delays_env is not None:
        settings.enable_delays = delays_env.strip().lower() in {"1", "true", "yes", "on"}

    min_delay = os.getenv("BUILDQUORUM_MIN_DELAY")
    if min_delay is not None:
        settings.min_delay_seconds = max(0.0, float(min_delay))

    max_delay = os.getenv("BUILDQUORUM_MAX_DELAY")
    if max_delay is not None:
        settings.max_delay_seconds = max(settings.min_delay_seconds, float(max_delay))

    settings.ensure_dirs()
    return settings