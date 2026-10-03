"""Esquemas Pydantic para la API REST Kyber ML-KEM (FIPS 203).

Define los modelos de solicitud y respuesta para:
- Generación de claves ML-KEM (FIPS 203)
- Cifrado y descifrado híbrido autenticado (ML-KEM + AES-256-GCM)
"""

import base64
import binascii
from typing import Literal
from pydantic import BaseModel, Field, field_validator

SecurityLevel = Literal[512, 768, 1024]


def _validate_base64_field(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} debe ser una cadena de texto.")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} no puede estar vacío.")
    try:
        base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Codificación Base64 inválida para '{field_name}': {exc}")
    return stripped


class KeygenRequest(BaseModel):
    security_level: SecurityLevel = Field(default=768)


class KeygenResponse(BaseModel):
    ek_b64: str
    dk_b64: str
    security_level: int


class HybridEncryptRequest(BaseModel):
    ek_b64: str
    plaintext: str
    security_level: SecurityLevel = Field(default=768)

    @field_validator("ek_b64")
    @classmethod
    def validate_ek(cls, v: str) -> str:
        return _validate_base64_field(v, "ek_b64")

    def get_ek_bytes(self) -> bytes:
        return base64.b64decode(self.ek_b64)


class HybridEncryptResponse(BaseModel):
    capsule_b64: str
    nonce_b64: str
    ciphertext_b64: str


class HybridDecryptRequest(BaseModel):
    dk_b64: str
    capsule_b64: str
    nonce_b64: str
    ciphertext_b64: str
    security_level: SecurityLevel = Field(default=768)

    @field_validator("dk_b64")
    @classmethod
    def validate_dk(cls, v: str) -> str:
        return _validate_base64_field(v, "dk_b64")

    @field_validator("capsule_b64")
    @classmethod
    def validate_capsule(cls, v: str) -> str:
        return _validate_base64_field(v, "capsule_b64")

    @field_validator("nonce_b64")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        return _validate_base64_field(v, "nonce_b64")

    @field_validator("ciphertext_b64")
    @classmethod
    def validate_ciphertext(cls, v: str) -> str:
        return _validate_base64_field(v, "ciphertext_b64")

    def get_dk_bytes(self) -> bytes:
        return base64.b64decode(self.dk_b64)

    def get_capsule_bytes(self) -> bytes:
        return base64.b64decode(self.capsule_b64)

    def get_nonce_bytes(self) -> bytes:
        return base64.b64decode(self.nonce_b64)

    def get_ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext_b64)


class HybridDecryptResponse(BaseModel):
    plaintext: str
