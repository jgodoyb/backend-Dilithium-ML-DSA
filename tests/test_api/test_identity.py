"""Pruebas de integración para el router de identidad y generación de claves (/api/generate)."""

import os
import sys
import base64
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "test"

import api.main
from api.main import app
import api.dependencies as deps
from mlkem.parameters.params import ML_KEM_768


def test_generate_keys_unified():
    """Valida la generación simultánea de claves ML-DSA (FIPS 204) y ML-KEM-768 (FIPS 203)

    y su almacenamiento correcto en la tabla 'crypto_identities' de Supabase.
    """
    client = TestClient(app)
    auth_headers = {"Authorization": "Bearer test-token"}

    # Mock de Supabase para capturar el payload del upsert
    mock_supabase = MagicMock()
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table
    mock_upsert = MagicMock()
    mock_table.upsert.return_value = mock_upsert
    mock_upsert.execute.return_value = MagicMock(data=[])

    deps.supabase = mock_supabase
    deps.create_client = MagicMock(return_value=mock_supabase)
    api.main.supabase = mock_supabase
    api.main.create_client = MagicMock(return_value=mock_supabase)

    response = client.post("/api/generate", headers=auth_headers)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "success"
    assert "ML-DSA + ML-KEM" in data["message"]

    # Verificar que se llamó al upsert en crypto_identities con los campos requeridos
    mock_supabase.table.assert_called_with("crypto_identities")
    assert mock_table.upsert.called
    upsert_arg = mock_table.upsert.call_args[0][0]

    assert upsert_arg["user_id"] == "test-user-123"
    assert upsert_arg["email"] == "test@qproof.com"
    assert "public_key" in upsert_arg
    assert "private_key" in upsert_arg
    assert "kem_public_key" in upsert_arg
    assert "kem_private_key" in upsert_arg
    assert upsert_arg["kem_security_level"] == 768

    # Validar que las claves son Base64 válido y tienen las dimensiones criptográficas correctas
    dsa_pk = base64.b64decode(upsert_arg["public_key"])
    dsa_sk = base64.b64decode(upsert_arg["private_key"])
    kem_ek = base64.b64decode(upsert_arg["kem_public_key"])
    kem_dk = base64.b64decode(upsert_arg["kem_private_key"])

    assert len(dsa_pk) > 0
    assert len(dsa_sk) > 0
    assert len(kem_ek) == ML_KEM_768.ek_pke_len  # 1184 bytes para ML-KEM-768
    assert len(kem_dk) == 2400  # dk_pke + ek_pke + H(ek) + z = 1152 + 1184 + 32 + 32 = 2400 bytes
