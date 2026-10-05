from __future__ import annotations

import datetime
import json

import yaml
from pydantic import BaseModel

from redteam.safety.domain import Intensity
from redteam.safety.signing import Signer, default_signer


class ScopeSignatureError(Exception):
    pass


class Window(BaseModel):
    start: datetime.date
    end: datetime.date


class Authorized(BaseModel):
    domains: list[str]
    ips: list[str]


class Limits(BaseModel):
    max_requests_per_module: int = 1000


class Scope(BaseModel):
    mission: str
    mandate_ref: str
    client_contact: str
    authorized: Authorized
    excluded: list[str]
    window: Window
    allowed_intensity: Intensity
    sandbox: dict[str, str] = {}
    limits: Limits = Limits()
    signature: str


def _canonical(scope_dict: dict) -> bytes:
    content = {k: v for k, v in scope_dict.items() if k != "signature"}
    return json.dumps(content, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")


def compute_signature(scope_dict: dict, signer: Signer | None = None) -> str:
    return (signer or default_signer()).sign(_canonical(scope_dict))


def load_scope(path: str, signer: Signer | None = None) -> Scope:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not (signer or default_signer()).verify(_canonical(data), data.get("signature", "")):
        raise ScopeSignatureError(
            "Signature invalide : le scope a été modifié après scellement, ou la clé diffère."
        )
    return Scope.model_validate(data)
