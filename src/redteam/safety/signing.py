from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol, runtime_checkable


class SigningKeyError(Exception):
    pass


@runtime_checkable
class Signer(Protocol):
    def sign(self, content: bytes) -> str: ...
    def verify(self, content: bytes, signature: str) -> bool: ...


class HmacSigner:
    def __init__(self, key: bytes):
        self._key = key

    def sign(self, content: bytes) -> str:
        return hmac.new(self._key, content, hashlib.sha256).hexdigest()

    def verify(self, content: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(content), signature)


def default_signer() -> Signer:
    key = os.getenv("REDTEAM_SIGNING_KEY") or os.getenv("REDSCOPE_SIGNING_KEY")
    if key:
        return HmacSigner(key.encode("utf-8"))
    key_file = os.getenv("REDTEAM_SIGNING_KEY_FILE")
    if key_file:
        try:
            with open(key_file, "rb") as fh:
                return HmacSigner(fh.read())
        except OSError as exc:
            raise SigningKeyError(f"Clé de signature illisible : {key_file}") from exc
    raise SigningKeyError(
        "Aucune clé de signature : définir REDTEAM_SIGNING_KEY ou REDTEAM_SIGNING_KEY_FILE."
    )
