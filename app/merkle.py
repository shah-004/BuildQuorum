from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: bytes | str) -> str:
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def canonical_attestation_leaf_hash(attestation: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "validator_id": attestation["validator_id"],
            "build_hash": attestation["build_hash"],
            "signature": attestation["signature"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex(canonical)


def _pair_hash(left_hex: str, right_hex: str) -> str:
    return sha256_hex(f"{left_hex}:{right_hex}")


def build_merkle_tree(leaf_hashes: list[str]) -> tuple[str, list[list[str]]]:
    """Build a binary Merkle tree from leaf hashes. Returns (root_hash, levels)."""
    if not leaf_hashes:
        empty_root = sha256_hex("EMPTY_MERKLE_TREE")
        return empty_root, [[empty_root]]

    levels: list[list[str]] = [list(leaf_hashes)]
    current = list(leaf_hashes)

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        next_level: list[str] = []
        for idx in range(0, len(current), 2):
            next_level.append(_pair_hash(current[idx], current[idx + 1]))
        levels.append(next_level)
        current = next_level

    return current[0], levels


def generate_merkle_proof(leaf_hashes: list[str], index: int) -> dict[str, Any]:
    """Generate a Merkle inclusion proof for the leaf at `index`."""
    if not leaf_hashes:
        raise ValueError("Cannot generate Merkle proof for an empty leaf list.")
    if index < 0 or index >= len(leaf_hashes):
        raise IndexError(f"Leaf index {index} out of range (0..{len(leaf_hashes) - 1}).")

    root_hash, levels = build_merkle_tree(leaf_hashes)
    steps: list[dict[str, str]] = []
    pos = index

    # Walk all levels except the final root level
    for level in levels[:-1]:
        working = list(level)
        if len(working) % 2 == 1:
            working.append(working[-1])

        if pos % 2 == 0:
            sibling_hash = working[pos + 1]
            steps.append({"position": "right", "hash": sibling_hash})
        else:
            sibling_hash = working[pos - 1]
            steps.append({"position": "left", "hash": sibling_hash})

        pos //= 2

    return {
        "leaf_hash": leaf_hashes[index],
        "index": index,
        "merkle_root": root_hash,
        "steps": steps,
    }


def verify_merkle_proof(
    leaf_hash: str,
    proof_steps: list[dict[str, str]],
    expected_root: str,
) -> bool:
    """Verify a Merkle inclusion proof against `expected_root`."""
    if not leaf_hash or not expected_root:
        return False

    computed = leaf_hash
    for step in proof_steps:
        direction = step.get("position")
        sibling = step.get("hash", "")
        if not sibling:
            return False
        if direction == "right":
            computed = _pair_hash(computed, sibling)
        elif direction == "left":
            computed = _pair_hash(sibling, computed)
        else:
            return False

    return computed == expected_root
    