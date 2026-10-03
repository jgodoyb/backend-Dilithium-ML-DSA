"""Pruebas de integración para el router de cifrado híbrido poscuántico ML-KEM (FIPS 203 + AES-256-GCM)."""

import os
import base64
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "test"

from api.main import app


def test_health_check_endpoint():
    """Valida que el endpoint raíz reporte ambos estándares criptográficos (ML-DSA y ML-KEM)."""
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "ML-DSA" in str(data)
    assert "ML-KEM" in str(data)


def test_keygen_endpoints():
    """Valida la generación de claves para los niveles de seguridad 512, 768 y 1024."""
    client = TestClient(app)

    # 1. Por defecto (nivel 768)
    res = client.post("/keygen", json={})
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["security_level"] == 768
    ek_bytes = base64.b64decode(data["ek_b64"])
    dk_bytes = base64.b64decode(data["dk_b64"])
    assert len(ek_bytes) == 1184
    assert len(dk_bytes) == 2400

    # 2. Nivel 512
    res_512 = client.post("/keygen", json={"security_level": 512})
    assert res_512.status_code == 200
    assert res_512.json()["security_level"] == 512

    # 3. Nivel 1024
    res_1024 = client.post("/keygen", json={"security_level": 1024})
    assert res_1024.status_code == 200
    assert res_1024.json()["security_level"] == 1024


def test_hybrid_encrypt_decrypt_roundtrip():
    """Valida el ciclo completo de cifrado y descifrado de texto en claro."""
    client = TestClient(app)

    # 1. Generar par de claves
    res_gen = client.post("/keygen", json={"security_level": 768})
    assert res_gen.status_code == 200
    keys = res_gen.json()
    ek_b64 = keys["ek_b64"]
    dk_b64 = keys["dk_b64"]

    # 2. Cifrar payload
    secret_message = "Mensaje altamente confidencial protegido por criptografía post-cuántica Q-Proof"
    res_enc = client.post(
        "/encrypt",
        json={
            "ek_b64": ek_b64,
            "plaintext": secret_message,
            "security_level": 768,
        },
    )
    assert res_enc.status_code == 200, res_enc.text
    cipher_payload = res_enc.json()
    assert "capsule_b64" in cipher_payload
    assert "nonce_b64" in cipher_payload
    assert "ciphertext_b64" in cipher_payload

    # 3. Descifrar payload
    res_dec = client.post(
        "/decrypt",
        json={
            "dk_b64": dk_b64,
            "capsule_b64": cipher_payload["capsule_b64"],
            "nonce_b64": cipher_payload["nonce_b64"],
            "ciphertext_b64": cipher_payload["ciphertext_b64"],
            "security_level": 768,
        },
    )
    assert res_dec.status_code == 200, res_dec.text
    decrypted = res_dec.json()
    assert decrypted["plaintext"] == secret_message


def test_hybrid_decrypt_tampered_ciphertext_fails():
    """Valida que la alteración del ciphertext provoque un fallo de integridad (HTTP 400)."""
    client = TestClient(app)

    # 1. Generar claves y cifrar
    res_gen = client.post("/keygen", json={"security_level": 768})
    keys = res_gen.json()

    res_enc = client.post(
        "/encrypt",
        json={
            "ek_b64": keys["ek_b64"],
            "plaintext": "Texto a proteger",
            "security_level": 768,
        },
    )
    cipher_payload = res_enc.json()

    # 2. Alterar el ciphertext (modificar un byte)
    raw_ciphertext = bytearray(base64.b64decode(cipher_payload["ciphertext_b64"]))
    raw_ciphertext[0] ^= 0xFF
    tampered_ciphertext_b64 = base64.b64encode(raw_ciphertext).decode("ascii")

    # 3. Intento de descifrado con carga manipulada
    res_dec = client.post(
        "/decrypt",
        json={
            "dk_b64": keys["dk_b64"],
            "capsule_b64": cipher_payload["capsule_b64"],
            "nonce_b64": cipher_payload["nonce_b64"],
            "ciphertext_b64": tampered_ciphertext_b64,
            "security_level": 768,
        },
    )
    assert res_dec.status_code == 400
    assert "integrity check failed" in res_dec.json()["detail"]


def test_hybrid_decrypt_tampered_capsule_fails():
    """Valida que la alteración de la cápsula KEM provoque el rechazo por autenticación simétrica."""
    client = TestClient(app)

    res_gen = client.post("/keygen", json={"security_level": 768})
    keys = res_gen.json()

    res_enc = client.post(
        "/encrypt",
        json={
            "ek_b64": keys["ek_b64"],
            "plaintext": "Texto de prueba cápsula",
            "security_level": 768,
        },
    )
    cipher_payload = res_enc.json()

    # Alterar la cápsula
    raw_capsule = bytearray(base64.b64decode(cipher_payload["capsule_b64"]))
    raw_capsule[0] ^= 0xFF
    tampered_capsule_b64 = base64.b64encode(raw_capsule).decode("ascii")

    res_dec = client.post(
        "/decrypt",
        json={
            "dk_b64": keys["dk_b64"],
            "capsule_b64": tampered_capsule_b64,
            "nonce_b64": cipher_payload["nonce_b64"],
            "ciphertext_b64": cipher_payload["ciphertext_b64"],
            "security_level": 768,
        },
    )
    assert res_dec.status_code == 400
    assert "integrity check failed" in res_dec.json()["detail"]


def test_encryption_schema_validation_errors():
    """Valida los errores de validación Base64 y campos requeridos."""
    client = TestClient(app)

    # Base64 corrupto en /encrypt
    res_bad_ek = client.post(
        "/encrypt",
        json={"ek_b64": "!!!not-valid-base64!!!", "plaintext": "Hola"},
    )
    assert res_bad_ek.status_code == 422

    # Campos faltantes en /decrypt
    res_missing = client.post(
        "/decrypt",
        json={"dk_b64": "AAAA"},
    )
    assert res_missing.status_code == 422
