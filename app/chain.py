from __future__ import annotations

import hashlib
import json
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.builder import BuildResult, build_artifact, normalize_source, prepare_published_artifact
from app.config import Settings
from app.keys import ValidatorKeyPair, load_or_create_validator_keys, verify_signature
from app.merkle import (
    build_merkle_tree,
    canonical_attestation_leaf_hash,
    generate_merkle_proof,
    verify_merkle_proof,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_block_payload(block: dict[str, Any]) -> str:
    payload = {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "previous_hash": block["previous_hash"],
        "proposer_id": block["proposer_id"],
        "merkle_root": block["merkle_root"],
        "package": block.get("package"),
        "attestations": block.get("attestations", []),
        "validator_registry": block.get("validator_registry"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_block_hash(block: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_block_payload(block).encode("utf-8")).hexdigest()


def _proposer_signing_message(block: dict[str, Any]) -> str:
    return f"BLOCK:{block['index']}:{block['previous_hash']}:{block['merkle_root']}:{block['block_hash']}"


def _validator_signing_message(validator_id: str, build_hash: str) -> str:
    return f"ATTEST:{validator_id}:{build_hash}"


def forge_lying_hash(validator_id: str, clean_hash: str, job_id: str) -> str:
    """Produce a distinct fake hash per validator so two lying validators never match."""
    seed = f"LIE:{validator_id}:{job_id}:{clean_hash}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


@dataclass
class JobRecord:
    job_id: str
    package_name: str
    version: str
    filename: str
    extension: str
    source_hash: str
    published_hash: str
    clean_build_hash: str
    compromised_publisher: bool
    status: str = "queued"  # queued, building, voting, finalized, rejected
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    reason: str | None = None
    block_number: int | None = None
    duplicate_of_block: int | None = None
    validators: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        agreeing_count = sum(
            1 for v in self.validators.values() if v.get("agrees_with_consensus") is True
        )
        return {
            "job_id": self.job_id,
            "package_name": self.package_name,
            "version": self.version,
            "filename": self.filename,
            "extension": self.extension,
            "source_hash": self.source_hash,
            "published_hash": self.published_hash,
            "published_matches_consensus": (
                self.published_hash == self.clean_build_hash if self.status == "finalized" else None
            ),
            "compromised_publisher": self.compromised_publisher,
            "status": self.status,
            "reason": self.reason,
            "block_number": self.block_number,
            "duplicate_of_block": self.duplicate_of_block,
            "agreeing_validators": agreeing_count,
            "quorum_required": len(self.validators),
            "validators": list(self.validators.values()),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class BuildQuorumEngine:
    def __init__(self, settings: Settings, gcc_usable: bool) -> None:
        self.settings = settings
        self.gcc_usable = gcc_usable
        self.lock = threading.RLock()

        self.keypairs: dict[str, ValidatorKeyPair] = load_or_create_validator_keys(
            settings.keys_file, settings.validator_ids
        )
        self.lying_validators: dict[str, bool] = {vid: False for vid in settings.validator_ids}
        self.flag_counts: dict[str, int] = {vid: 0 for vid in settings.validator_ids}
        self.proposer_cursor: int = 0
        self.chain: list[dict[str, Any]] = []
        self.jobs: dict[str, JobRecord] = {}

        self._load_or_init_chain()

    def _build_genesis_block(self) -> dict[str, Any]:
        registry = {
            vid: {"validator_id": vid, "public_key": self.keypairs[vid].public_key_hex}
            for vid in self.settings.validator_ids
        }
        merkle_root, _ = build_merkle_tree(
            [f"GENESIS:{vid}:{self.keypairs[vid].public_key_hex}" for vid in self.settings.validator_ids]
        )
        block: dict[str, Any] = {
            "index": 0,
            "timestamp": _utc_now_iso(),
            "previous_hash": "0" * 64,
            "proposer_id": "GENESIS",
            "proposer_signature": None,
            "merkle_root": merkle_root,
            "package": None,
            "attestations": [],
            "validator_registry": registry,
        }
        block["block_hash"] = compute_block_hash(block)
        return block

    def _save_chain_locked(self, update_snapshot: bool = False) -> None:
        state = {
            "chain": self.chain,
            "flag_counts": self.flag_counts,
            "proposer_cursor": self.proposer_cursor,
            "lying_validators": self.lying_validators,
        }
        self.settings.chain_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        if update_snapshot:
            self.settings.snapshot_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _load_or_init_chain(self) -> None:
        with self.lock:
            if self.settings.chain_file.exists():
                raw = json.loads(self.settings.chain_file.read_text(encoding="utf-8"))
                loaded_chain = raw.get("chain", [])
                if isinstance(loaded_chain, list) and len(loaded_chain) >= 1:
                    self.chain = loaded_chain
                    loaded_flags = raw.get("flag_counts", {})
                    for vid in self.settings.validator_ids:
                        self.flag_counts[vid] = int(loaded_flags.get(vid, 0))
                    self.proposer_cursor = int(raw.get("proposer_cursor", 0)) % len(
                        self.settings.validator_ids
                    )
                    loaded_lying = raw.get("lying_validators", {})
                    for vid in self.settings.validator_ids:
                        self.lying_validators[vid] = bool(loaded_lying.get(vid, False))
                    if not self.settings.snapshot_file.exists():
                        self._save_chain_locked(update_snapshot=True)
                    return

            self.chain = [self._build_genesis_block()]
            self.flag_counts = {vid: 0 for vid in self.settings.validator_ids}
            self.proposer_cursor = 0
            self._save_chain_locked(update_snapshot=True)

    def reset_to_genesis(self) -> dict[str, Any]:
        with self.lock:
            self.lying_validators = {vid: False for vid in self.settings.validator_ids}
            self.flag_counts = {vid: 0 for vid in self.settings.validator_ids}
            self.proposer_cursor = 0
            self.chain = [self._build_genesis_block()]
            self.jobs.clear()
            for artifact_path in self.settings.artifacts_dir.glob("*"):
                if artifact_path.is_file():
                    artifact_path.unlink()
            self._save_chain_locked(update_snapshot=True)
            return self.get_chain_summary()

    def set_validator_lying(self, validator_id: str, lying: bool) -> dict[str, Any]:
        with self.lock:
            if validator_id not in self.lying_validators:
                raise KeyError(f"Unknown validator '{validator_id}'.")
            self.lying_validators[validator_id] = bool(lying)
            self._save_chain_locked(update_snapshot=False)
            return self.get_validators_status()

    def get_validators_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "quorum_threshold": self.settings.quorum_threshold,
                "total_validators": len(self.settings.validator_ids),
                "validators": [
                    {
                        "validator_id": vid,
                        "public_key": self.keypairs[vid].public_key_hex,
                        "lying": self.lying_validators[vid],
                        "flag_count": self.flag_counts[vid],
                    }
                    for vid in self.settings.validator_ids
                ],
            }

    def get_chain_summary(self) -> dict[str, Any]:
        with self.lock:
            return {
                "length": len(self.chain),
                "latest_block_hash": self.chain[-1]["block_hash"] if self.chain else None,
                "proposer_cursor": self.proposer_cursor,
                "next_proposer": self.settings.validator_ids[self.proposer_cursor],
                "blocks": self.chain,
            }

    def get_block(self, block_number: int) -> dict[str, Any] | None:
        with self.lock:
            if 0 <= block_number < len(self.chain):
                return self.chain[block_number]
            return None

    def find_duplicate_block(
        self, package_name: str, version: str, source_hash: str
    ) -> dict[str, Any] | None:
        with self.lock:
            for block in self.chain[1:]:
                pkg = block.get("package") or {}
                if (
                    pkg.get("name") == package_name
                    and pkg.get("version") == version
                    and pkg.get("source_hash") == source_hash
                ):
                    return block
            return None

    def submit_package_job(
        self,
        raw_bytes: bytes,
        filename: str,
        extension: str,
        package_name: str,
        version: str,
        compromised_publisher: bool,
        run_async: bool = True,
    ) -> dict[str, Any]:
        norm_text, _, source_hash = normalize_source(raw_bytes)
        clean_build: BuildResult = build_artifact(
            normalized_source=norm_text,
            extension=extension,
            package_name=package_name,
            version=version,
            gcc_usable=self.gcc_usable,
            settings=self.settings,
        )
        published_bytes, published_hash = prepare_published_artifact(
            clean_build.artifact_bytes, compromised=compromised_publisher
        )

        with self.lock:
            dup_block = self.find_duplicate_block(package_name, version, source_hash)
            if dup_block is not None:
                job_id = f"dup-{uuid.uuid4().hex[:10]}"
                dup_job = JobRecord(
                    job_id=job_id,
                    package_name=package_name,
                    version=version,
                    filename=filename,
                    extension=extension,
                    source_hash=source_hash,
                    published_hash=published_hash,
                    clean_build_hash=clean_build.build_hash,
                    compromised_publisher=compromised_publisher,
                    status="finalized",
                    reason="Duplicate submission matched existing finalized block.",
                    block_number=dup_block["index"],
                    duplicate_of_block=dup_block["index"],
                    validators={
                        vid: {
                            "validator_id": vid,
                            "state": "attested",
                            "build_hash": clean_build.build_hash,
                            "agrees_with_consensus": True,
                            "signature_valid": True,
                        }
                        for vid in self.settings.validator_ids
                    },
                )
                self.jobs[job_id] = dup_job
                return {"duplicate": True, "job": dup_job.to_dict(), "block": dup_block}

            job_id = uuid.uuid4().hex[:12]
            job = JobRecord(
                job_id=job_id,
                package_name=package_name,
                version=version,
                filename=filename,
                extension=extension,
                source_hash=source_hash,
                published_hash=published_hash,
                clean_build_hash=clean_build.build_hash,
                compromised_publisher=compromised_publisher,
                status="queued",
                validators={
                    vid: {
                        "validator_id": vid,
                        "state": "queued",
                        "build_hash": None,
                        "signature": None,
                        "signature_valid": None,
                        "agrees_with_consensus": None,
                        "lying_at_run": self.lying_validators[vid],
                    }
                    for vid in self.settings.validator_ids
                },
            )
            self.jobs[job_id] = job

        if run_async:
            worker = threading.Thread(
                target=self._execute_job_pipeline,
                args=(job, norm_text, published_bytes, clean_build.build_mode),
                daemon=True,
            )
            worker.start()
        else:
            self._execute_job_pipeline(job, norm_text, published_bytes, clean_build.build_mode)

        return {"duplicate": False, "job": job.to_dict()}

    def _execute_job_pipeline(
        self,
        job: JobRecord,
        normalized_source: str,
        published_bytes: bytes,
        build_mode: str,
    ) -> None:
        with self.lock:
            job.status = "building"
            job.updated_at = _utc_now_iso()
            for vid in self.settings.validator_ids:
                job.validators[vid]["state"] = "building"

        results_lock = threading.Lock()
        attestations: list[dict[str, Any]] = []

        def validator_worker(vid: str) -> None:
            if self.settings.enable_delays and self.settings.max_delay_seconds > 0:
                delay = random.uniform(
                    self.settings.min_delay_seconds, self.settings.max_delay_seconds
                )
                time.sleep(delay)

            with self.lock:
                is_lying = self.lying_validators[vid]
                job.validators[vid]["lying_at_run"] = is_lying
                job.validators[vid]["state"] = "voting"
                job.updated_at = _utc_now_iso()

            clean_res = build_artifact(
                normalized_source=normalized_source,
                extension=job.extension,
                package_name=job.package_name,
                version=job.version,
                gcc_usable=self.gcc_usable,
                settings=self.settings,
            )
            reported_hash = (
                forge_lying_hash(vid, clean_res.build_hash, job.job_id)
                if is_lying
                else clean_res.build_hash
            )
            sig = self.keypairs[vid].sign_message(_validator_signing_message(vid, reported_hash))

            att = {
                "validator_id": vid,
                "build_hash": reported_hash,
                "signature": sig,
            }
            with results_lock:
                attestations.append(att)

            with self.lock:
                job.validators[vid]["state"] = "voted"
                job.validators[vid]["build_hash"] = reported_hash
                job.validators[vid]["signature"] = sig
                job.updated_at = _utc_now_iso()

        threads = [
            threading.Thread(target=validator_worker, args=(vid,), daemon=True)
            for vid in self.settings.validator_ids
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with self.lock:
            job.status = "voting"
            job.updated_at = _utc_now_iso()

            genesis_registry = self.chain[0].get("validator_registry", {})
            valid_by_hash: dict[str, list[dict[str, Any]]] = {}

            for att in attestations:
                vid = att["validator_id"]
                b_hash = att["build_hash"]
                sig = att["signature"]
                pub_key = (genesis_registry.get(vid) or {}).get("public_key")
                sig_ok = bool(pub_key) and verify_signature(
                    pub_key, _validator_signing_message(vid, b_hash), sig
                )
                job.validators[vid]["signature_valid"] = sig_ok
                if sig_ok:
                    valid_by_hash.setdefault(b_hash, []).append(att)

            winning_hash: str | None = None
            winning_votes: list[dict[str, Any]] = []
            for h, votes in valid_by_hash.items():
                if len(votes) > len(winning_votes):
                    winning_hash = h
                    winning_votes = votes

            quorum_reached = (
                winning_hash is not None and len(winning_votes) >= self.settings.quorum_threshold
            )

            for vid in self.settings.validator_ids:
                v_info = job.validators[vid]
                agreed = bool(v_info.get("signature_valid")) and (
                    v_info.get("build_hash") == winning_hash
                )
                v_info["agrees_with_consensus"] = agreed
                if not agreed:
                    self.flag_counts[vid] = self.flag_counts.get(vid, 0) + 1

            if not quorum_reached or winning_hash is None:
                job.status = "rejected"
                job.reason = (
                    f"Consensus not reached: required {self.settings.quorum_threshold} agreeing valid votes, "
                    f"got {len(winning_votes)}."
                )
                job.updated_at = _utc_now_iso()
                self._save_chain_locked(update_snapshot=False)
                return

            ordered_attestations = [
                next(a for a in attestations if a["validator_id"] == vid)
                for vid in self.settings.validator_ids
                if any(a["validator_id"] == vid for a in attestations)
            ]
            leaf_hashes = [canonical_attestation_leaf_hash(a) for a in ordered_attestations]
            merkle_root, _ = build_merkle_tree(leaf_hashes)

            proposer_id = self.settings.validator_ids[
                self.proposer_cursor % len(self.settings.validator_ids)
            ]
            self.proposer_cursor = (self.proposer_cursor + 1) % len(self.settings.validator_ids)

            prev_block = self.chain[-1]
            new_index = prev_block["index"] + 1
            pkg_status = "FLAGGED" if job.published_hash != winning_hash else "OK"

            artifact_path = self.settings.artifacts_dir / f"block_{new_index}_{job.filename}.bin"
            artifact_path.write_bytes(published_bytes)

            package_record = {
                "name": job.package_name,
                "version": job.version,
                "filename": job.filename,
                "extension": job.extension,
                "source_hash": job.source_hash,
                "consensus_build_hash": winning_hash,
                "published_hash": job.published_hash,
                "status": pkg_status,
                "compromised_publisher": job.compromised_publisher,
                "build_mode": build_mode,
                "artifact_file": artifact_path.name,
                "job_id": job.job_id,
                "submitted_at": _utc_now_iso(),
            }

            block: dict[str, Any] = {
                "index": new_index,
                "timestamp": _utc_now_iso(),
                "previous_hash": prev_block["block_hash"],
                "proposer_id": proposer_id,
                "proposer_signature": None,
                "merkle_root": merkle_root,
                "package": package_record,
                "attestations": ordered_attestations,
                "validator_registry": None,
            }
            block["block_hash"] = compute_block_hash(block)
            block["proposer_signature"] = self.keypairs[proposer_id].sign_message(
                _proposer_signing_message(block)
            )

            self.chain.append(block)
            job.status = "finalized"
            job.block_number = new_index
            job.reason = (
                "Finalized with tampered publisher artifact flagged."
                if pkg_status == "FLAGGED"
                else "Finalized cleanly by validator quorum."
            )
            job.updated_at = _utc_now_iso()
            self._save_chain_locked(update_snapshot=True)

    def validate_chain(self) -> dict[str, Any]:
        with self.lock:
            if not self.chain:
                return {"valid": False, "broken_block": 0, "reason": "Chain is empty."}

            genesis = self.chain[0]
            if genesis.get("index") != 0:
                return {"valid": False, "broken_block": 0, "reason": "Genesis block index is not 0."}
            if compute_block_hash(genesis) != genesis.get("block_hash"):
                return {
                    "valid": False,
                    "broken_block": 0,
                    "reason": "Genesis block hash does not match its contents.",
                }

            registry = genesis.get("validator_registry") or {}

            for i in range(1, len(self.chain)):
                block = self.chain[i]
                prev = self.chain[i - 1]

                if block.get("index") != i:
                    return {
                        "valid": False,
                        "broken_block": i,
                        "reason": f"Block {i} has unexpected index {block.get('index')}.",
                    }
                if block.get("previous_hash") != prev.get("block_hash"):
                    return {
                        "valid": False,
                        "broken_block": i,
                        "reason": f"Block {i} previous_hash does not match block {i - 1} block_hash.",
                    }
                if compute_block_hash(block) != block.get("block_hash"):
                    return {
                        "valid": False,
                        "broken_block": i,
                        "reason": f"Block {i} contents were altered; block_hash mismatch.",
                    }

                attestations = block.get("attestations") or []
                leaf_hashes = [canonical_attestation_leaf_hash(a) for a in attestations]
                expected_root, _ = build_merkle_tree(leaf_hashes)
                if block.get("merkle_root") != expected_root:
                    return {
                        "valid": False,
                        "broken_block": i,
                        "reason": f"Block {i} merkle_root does not match attestation hashes.",
                    }

                for att in attestations:
                    vid = att.get("validator_id", "")
                    b_hash = att.get("build_hash", "")
                    sig = att.get("signature", "")
                    pub = (registry.get(vid) or {}).get("public_key")
                    if not pub or not verify_signature(
                        pub, _validator_signing_message(vid, b_hash), sig
                    ):
                        return {
                            "valid": False,
                            "broken_block": i,
                            "reason": f"Block {i} has an invalid validator signature from {vid}.",
                        }

                proposer_id = block.get("proposer_id", "")
                proposer_sig = block.get("proposer_signature", "")
                proposer_pub = (registry.get(proposer_id) or {}).get("public_key")
                if not proposer_pub or not verify_signature(
                    proposer_pub, _proposer_signing_message(block), proposer_sig
                ):
                    return {
                        "valid": False,
                        "broken_block": i,
                        "reason": f"Block {i} has an invalid proposer signature from {proposer_id}.",
                    }

            return {"valid": True, "broken_block": None, "reason": "Chain is valid."}

    def get_merkle_proof_for_block(self, block_number: int, validator_id: str) -> dict[str, Any]:
        with self.lock:
            block = self.get_block(block_number)
            if block is None:
                raise KeyError(f"Block {block_number} not found.")
            if block_number == 0:
                raise ValueError("Genesis block does not contain package attestations.")

            attestations = block.get("attestations") or []
            leaf_hashes = [canonical_attestation_leaf_hash(a) for a in attestations]
            target_idx = next(
                (idx for idx, a in enumerate(attestations) if a.get("validator_id") == validator_id),
                None,
            )
            if target_idx is None:
                raise KeyError(f"Validator '{validator_id}' not found in block {block_number}.")

            proof = generate_merkle_proof(leaf_hashes, target_idx)
            proof["block_number"] = block_number
            proof["validator_id"] = validator_id
            proof["attestation"] = attestations[target_idx]
            proof["valid"] = verify_merkle_proof(
                proof["leaf_hash"], proof["steps"], block["merkle_root"]
            )
            return proof

    def verify_uploaded_file(
        self, file_bytes: bytes, block_number: int | None = None
    ) -> dict[str, Any]:
        actual_hash = hashlib.sha256(file_bytes).hexdigest()

        with self.lock:
            if block_number is not None:
                block = self.get_block(block_number)
                if block is None or block.get("index") == 0 or not block.get("package"):
                    raise KeyError(f"Package block {block_number} not found.")
                pkg = block["package"]
                expected_hash = pkg["consensus_build_hash"]
                status = "VERIFIED" if actual_hash == expected_hash else "TAMPERED"
                return {
                    "status": status,
                    "file_hash": actual_hash,
                    "expected_hash": expected_hash,
                    "block_number": block["index"],
                    "package_name": pkg["name"],
                    "version": pkg["version"],
                }

            for block in self.chain[1:]:
                pkg = block.get("package") or {}
                expected_hash = pkg.get("consensus_build_hash")
                if actual_hash == expected_hash:
                    return {
                        "status": "VERIFIED",
                        "file_hash": actual_hash,
                        "expected_hash": expected_hash,
                        "block_number": block["index"],
                        "package_name": pkg.get("name"),
                        "version": pkg.get("version"),
                    }

            return {
                "status": "NOT RECOGNIZED",
                "file_hash": actual_hash,
                "expected_hash": None,
                "block_number": None,
                "package_name": None,
                "version": None,
            }

    def list_packages(self) -> list[dict[str, Any]]:
        with self.lock:
            pkgs: list[dict[str, Any]] = []
            for block in self.chain[1:]:
                pkg = block.get("package")
                if pkg:
                    pkgs.append(
                        {
                            "block_number": block["index"],
                            "name": pkg["name"],
                            "version": pkg["version"],
                            "filename": pkg["filename"],
                            "status": pkg["status"],
                            "consensus_build_hash": pkg["consensus_build_hash"],
                            "published_hash": pkg["published_hash"],
                            "source_hash": pkg["source_hash"],
                            "compromised_publisher": pkg.get("compromised_publisher", False),
                            "submitted_at": pkg.get("submitted_at"),
                        }
                    )
            return pkgs

    def get_artifact_path(self, block_number: int) -> Path:
        with self.lock:
            block = self.get_block(block_number)
            if block is None or block.get("index") == 0 or not block.get("package"):
                raise KeyError(f"No package artifact for block {block_number}.")
            artifact_name = block["package"].get("artifact_file")
            if not artifact_name:
                raise FileNotFoundError("Artifact filename missing.")
            path = self.settings.artifacts_dir / artifact_name
            if not path.exists():
                raise FileNotFoundError("Artifact file not found on disk.")
            return path

    def tamper_block(self, block_number: int) -> dict[str, Any]:
        """Mutate an existing block's package/validator field without recomputing block_hash."""
        with self.lock:
            block = self.get_block(block_number)
            if block is None:
                raise KeyError(f"Block {block_number} not found.")
            if block_number == 0:
                reg = block.get("validator_registry") or {}
                first_vid = next(iter(reg), None)
                if first_vid:
                    reg[first_vid]["public_key"] = "00" * 32
            else:
                pkg = block.get("package") or {}
                pkg["consensus_build_hash"] = "ff" * 32
                block["package"] = pkg
            self._save_chain_locked(update_snapshot=False)
            return {
                "tampered_block": block_number,
                "validation": self.validate_chain(),
            }

    def repair_from_snapshot(self) -> dict[str, Any]:
        with self.lock:
            if not self.settings.snapshot_file.exists():
                raise FileNotFoundError("Clean chain snapshot does not exist.")
            snap = json.loads(self.settings.snapshot_file.read_text(encoding="utf-8"))
            self.chain = snap.get("chain", [self._build_genesis_block()])
            loaded_flags = snap.get("flag_counts", {})
            for vid in self.settings.validator_ids:
                self.flag_counts[vid] = int(loaded_flags.get(vid, 0))
            self.proposer_cursor = int(snap.get("proposer_cursor", 0)) % len(
                self.settings.validator_ids
            )
            loaded_lying = snap.get("lying_validators", {})
            for vid in self.settings.validator_ids:
                self.lying_validators[vid] = bool(loaded_lying.get(vid, False))
            self._save_chain_locked(update_snapshot=False)
            return {
                "repaired": True,
                "validation": self.validate_chain(),
                "length": len(self.chain),
            }