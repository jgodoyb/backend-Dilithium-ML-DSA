"""Pruebas de integración para el router de firmas digitales ML-DSA (FIPS 204)."""

import os
import base64
import hashlib
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "test"

import api.main
from api.main import app
import api.dependencies as deps
import mldsa.mldsa as mldsa


def test_signatures_flow():
    """Valida el ciclo completo de firma, verificación y verificación por lotes con ML-DSA."""
    client = TestClient(app)
    auth_headers = {"Authorization": "Bearer test-token"}

    mock_supabase = MagicMock()
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table

    deps.supabase = mock_supabase
    deps.create_client = MagicMock(return_value=mock_supabase)
    api.main.supabase = mock_supabase
    api.main.create_client = MagicMock(return_value=mock_supabase)

    # Generamos claves ML-DSA de prueba
    pk, sk = mldsa.keygen()
    pk_b64 = base64.b64encode(pk).decode("utf-8")
    sk_b64 = base64.b64encode(sk).decode("utf-8")

    # Mock de selección de clave privada
    mock_execute_priv = MagicMock()
    mock_execute_priv.data = {"private_key": sk_b64}
    mock_single_priv = MagicMock()
    mock_single_priv.execute.return_value = mock_execute_priv
    mock_eq_priv = MagicMock()
    mock_eq_priv.single.return_value = mock_single_priv
    mock_select_priv = MagicMock()
    mock_select_priv.eq.return_value = mock_eq_priv
    mock_table.select.return_value = mock_select_priv

    # 1. Test Sign Document (Multipart file)
    try:
        with open("test_sig.pdf", "wb") as f:
            f.write(b"Dummy PDF Content for Signatures")

        with open("test_sig.pdf", "rb") as f:
            res_sign = client.post(
                "/api/sign",
                headers=auth_headers,
                files={"file": ("test_sig.pdf", f, "application/pdf")},
            )

        assert res_sign.status_code == 200, res_sign.text
        sig_b64 = res_sign.json()["signature_b64"]

        # 2. Test Verify Document (Multipart file + signature)
        sig_bytes = base64.b64decode(sig_b64)
        with open("test_sig.pdf", "rb") as f:
            res_verify = client.post(
                "/api/verify",
                headers=auth_headers,
                files={
                    "file": ("test_sig.pdf", f, "application/pdf"),
                    "signature": ("signature.sig", sig_bytes, "application/octet-stream"),
                },
                data={"public_key": pk_b64},
            )

        assert res_verify.status_code == 200, res_verify.text
        assert res_verify.json()["is_valid"] is True

    finally:
        if os.path.exists("test_sig.pdf"):
            os.remove("test_sig.pdf")

    # 3. Test Sign & Verify by Hash (JSON Payload)
    dummy_bytes = b"Dummy PDF Content for Signatures"
    doc_hash_hex = hashlib.sha256(dummy_bytes).hexdigest()

    res_sign_hash = client.post(
        "/api/sign",
        headers=auth_headers,
        json={"document_hash": doc_hash_hex},
    )
    assert res_sign_hash.status_code == 200, res_sign_hash.text
    hash_sig_b64 = res_sign_hash.json()["signature_b64"]

    res_verify_hash = client.post(
        "/api/verify",
        headers=auth_headers,
        json={
            "document_hash": doc_hash_hex,
            "signature_b64": hash_sig_b64,
            "public_key": pk_b64,
        },
    )
    assert res_verify_hash.status_code == 200, res_verify_hash.text
    assert res_verify_hash.json()["is_valid"] is True

    # 4. Test Verify Batch (Multi-layer PAdES simulation con Zero-Trust)
    def mock_in_filter(field, values):
        mock_res = MagicMock()
        mock_data = []
        for val in values:
            if val == "test-user-123":
                mock_data.append({"user_id": "test-user-123", "public_key": pk_b64})
        mock_res.execute.return_value = MagicMock(data=mock_data)
        return mock_res

    mock_table.select.return_value.in_.side_effect = mock_in_filter

    sig_hex = base64.b64decode(hash_sig_b64).hex()
    batch_payload = {
        "validations": [
            {
                "layer": 1,
                "document_hash": doc_hash_hex,
                "signature_hex": sig_hex,
                "signer_id": "test-user-123",
            },
            {
                "layer": 2,
                "document_hash": doc_hash_hex,
                "signature_hex": "deadbeef",
                "signer_id": "non-existent-user-uuid",
            },
        ]
    }
    res_batch = client.post("/api/verify-batch", json=batch_payload)
    assert res_batch.status_code == 200, res_batch.text
    batch_results = res_batch.json().get("results", [])
    assert len(batch_results) == 2
    assert batch_results[0] == {"layer": 1, "is_valid": True}
    assert batch_results[1] == {"layer": 2, "is_valid": False, "error": "Identity not found"}


def test_openapi_schema_dual_content_types():
    """Valida que la especificación OpenAPI declare adecuadamente JSON y multipart para firmas."""
    client = TestClient(app)
    res = client.get("/openapi.json")
    assert res.status_code == 200
    paths = res.json().get("paths", {})

    # /api/sign debe tener application/json y multipart/form-data
    sign_content = paths["/api/sign"]["post"]["requestBody"]["content"]
    assert "application/json" in sign_content
    assert "multipart/form-data" in sign_content

    # /api/verify debe tener application/json y multipart/form-data
    verify_content = paths["/api/verify"]["post"]["requestBody"]["content"]
    assert "application/json" in verify_content
    assert "multipart/form-data" in verify_content


def test_validation_errors():
    """Valida los códigos de respuesta esperados ante peticiones incompletas o inválidas."""
    client = TestClient(app)
    auth_headers = {"Authorization": "Bearer test-token"}

    # /api/sign sin hash ni archivo
    res_sign = client.post("/api/sign", headers=auth_headers, json={})
    assert res_sign.status_code in [400, 422]

    # /api/verify sin clave pública
    res_verify = client.post(
        "/api/verify",
        headers=auth_headers,
        json={"document_hash": "a" * 64, "signature_b64": "AAAA"},
    )
    assert res_verify.status_code in [400, 422]
