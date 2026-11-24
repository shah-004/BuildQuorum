from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


@dataclass
class ValidatorKeyPair:
    validator_id: str
    signing_key: SigningKey
    verify_key: VerifyKey

    @property
    def public_key_hex(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode("ascii")

    @property
    def private_key_hex(self) -> str:
        return self.signing_key.encode(encoder=HexEncoder).decode("ascii")

    def sign_message(self, message: bytes | str) -> str:
        payload = message.encode("utf-8") if isinstance(message, str) else message
        signed = self.signing_key.sign(payload, encoder=HexEncoder)
        return signed.signature.decode("ascii")


def verify_signature(public_key_hex: str, message: bytes | str, signature_hex: str) -> bool:
    try:
        payload = message.encode("utf-8") if isinstance(message, str) else message
        verify_key = VerifyKey(public_key_hex.encode("ascii"), encoder=HexEncoder)
        sig_bytes = HexEncoder.decode(signature_hex.encode("ascii"))
        verify_key.verify(payload, sig_bytes)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def load_or_create_validator_keys(keys_path: Any, validator_ids: list[str]) -> dict[str, ValidatorKeyPair]:
    path = keys_path
    existing: dict[str, dict[str, str]] = {}

    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            existing = raw

    keypairs: dict[str, ValidatorKeyPair] = {}
    updated = False

    for vid in validator_ids:
        entry = existing.get(vid)
        if entry and "private_key_hex" in entry:
            signing_key = SigningKey(entry["private_key_hex"].encode("ascii"), encoder=HexEncoder)
            verify_key = signing_key.verify_key
        else:
            signing_key = SigningKey.generate()
            verify_key = signing_key.verify_key
            existing[vid] = {
                "public_key_hex": verify_key.encode(encoder=HexEncoder).decode("ascii"),
                "private_key_hex": signing_key.encode(encoder=HexEncoder).decode("ascii"),
            }
            updated = True

        keypairs[vid] = ValidatorKeyPair(
            validator_id=vid,
            signing_key=signing_key,
            verify_key=verify_key,
        )

    if updated or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    return keypairs