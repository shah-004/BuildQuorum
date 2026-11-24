from __future__ import annotations

from pathlib import Path
import pytest

from app.builder import build_artifact, normalize_source, prepare_published_artifact
from app.chain import BuildQuorumEngine
from app.config import Settings
from app.merkle import verify_merkle_proof
from app.security import ValidationError, validate_upload


def make_settings(tmp_path: Path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        static_dir=tmp_path / "static",
        enable_delays=False,
        min_delay_seconds=0.0,
        max_delay_seconds=0.0,
    )
    s.ensure_dirs()
    return s


def test_upload_validation_and_risky_c_headers(tmp_path: Path) -> None:
    s = make_settings(tmp_path)

    # Valid Python upload
    name, ext = validate_upload("hello.py", b"print('hi')\n", "demo", "1.0.0", s)
    assert name == "hello.py"
    assert ext == ".py"

    # Risky C header rejected
    with pytest.raises(ValidationError) as exc:
        validate_upload(
            "evil.c",
            b"#include <winsock2.h>\nint main(void) { return 0; }\n",
            "netpkg",
            "1.0.0",
            s,
        )
    assert exc.value.status_code == 400

    # Oversized file rejected
    with pytest.raises(ValidationError) as size_exc:
        validate_upload("big.txt", b"a" * (s.max_upload_bytes + 1), "bigpkg", "1.0.0", s)
    assert size_exc.value.status_code == 413


def test_normalization_and_deterministic_build(tmp_path: Path) -> None:
    s = make_settings(tmp_path)

    _, _, h_crlf = normalize_source(b"\xef\xbb\xbfint f(void){\r\nreturn 1;\r\n}\r\n")
    _, _, h_lf = normalize_source(b"int f(void){\nreturn 1;\n}\n")
    assert h_crlf == h_lf

    b1 = build_artifact("int f(void){\nreturn 1;\n}\n", ".c", "mathlib", "0.1", False, s)
    b2 = build_artifact("int f(void){\nreturn 1;\n}\n", ".c", "mathlib", "0.1", False, s)
    assert b1.build_hash == b2.build_hash
    assert b1.artifact_bytes == b2.artifact_bytes

    clean_bytes, clean_hash = prepare_published_artifact(b1.artifact_bytes, compromised=False)
    comp_bytes, comp_hash = prepare_published_artifact(b1.artifact_bytes, compromised=True)
    assert clean_hash == b1.build_hash
    assert comp_hash != clean_hash
    assert len(comp_bytes) > len(clean_bytes)


def test_quorum_consensus_merkle_proof_and_duplicates(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    engine = BuildQuorumEngine(s, gcc_usable=False)

    assert engine.validate_chain()["valid"] is True

    # 1 lying validator out of 4 -> 3 honest agree -> quorum met
    engine.set_validator_lying("V4", True)
    res = engine.submit_package_job(
        raw_bytes=b"print('hello quorum')\n",
        filename="main.py",
        extension=".py",
        package_name="quorum-app",
        version="1.0.0",
        compromised_publisher=False,
        run_async=False,
    )
    assert res["duplicate"] is False
    assert res["job"]["status"] == "finalized"
    assert res["job"]["block_number"] == 1
    assert engine.validate_chain()["valid"] is True
    assert engine.get_validators_status()["validators"][3]["flag_count"] == 1  # V4 flagged

    # Merkle proof verification for V1 in block 1
    proof = engine.get_merkle_proof_for_block(1, "V1")
    block1 = engine.get_block(1)
    assert block1 is not None
    assert proof["valid"] is True
    assert verify_merkle_proof(proof["leaf_hash"], proof["steps"], block1["merkle_root"]) is True

    # Duplicate submission returns existing block without minting a new block
    dup = engine.submit_package_job(
        raw_bytes=b"print('hello quorum')\n",
        filename="main.py",
        extension=".py",
        package_name="quorum-app",
        version="1.0.0",
        compromised_publisher=False,
        run_async=False,
    )
    assert dup["duplicate"] is True
    assert dup["job"]["duplicate_of_block"] == 1
    assert len(engine.chain) == 2


def test_lying_quorum_failure_compromised_publisher_and_tamper_repair(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    engine = BuildQuorumEngine(s, gcc_usable=False)

    # 2 lying validators -> only 2 honest agree (< quorum 3) -> rejected
    engine.set_validator_lying("V2", True)
    engine.set_validator_lying("V3", True)
    rejected = engine.submit_package_job(
        raw_bytes=b"x = 10\n",
        filename="mod.py",
        extension=".py",
        package_name="split-vote",
        version="1.0.0",
        compromised_publisher=False,
        run_async=False,
    )
    assert rejected["job"]["status"] == "rejected"
    assert rejected["job"]["block_number"] is None
    assert len(engine.chain) == 1

    # Reset lying validators, submit with compromised publisher -> block minted with FLAGGED status
    engine.set_validator_lying("V2", False)
    engine.set_validator_lying("V3", False)
    comp_res = engine.submit_package_job(
        raw_bytes=b"y = 20\n",
        filename="mod.py",
        extension=".py",
        package_name="comp-pkg",
        version="1.0.0",
        compromised_publisher=True,
        run_async=False,
    )
    assert comp_res["job"]["status"] == "finalized"
    block1 = engine.get_block(1)
    assert block1 is not None
    assert block1["package"]["status"] == "FLAGGED"
    assert block1["package"]["published_hash"] != block1["package"]["consensus_build_hash"]

    # Tamper block 1 -> chain invalid; repair from snapshot -> chain valid again
    tampered = engine.tamper_block(1)
    assert tampered["validation"]["valid"] is False
    assert tampered["validation"]["broken_block"] == 1

    repaired = engine.repair_from_snapshot()
    assert repaired["repaired"] is True
    assert repaired["validation"]["valid"] is True