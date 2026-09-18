import os
import base64
from unittest.mock import MagicMock

import sys
from unittest.mock import MagicMock

sys.modules['supabase'] = MagicMock()

os.environ["ENVIRONMENT"] = "test"
import api.main

# Mapeamos la tabla de la BD en memoria para que el mock devuelva los mismos datos insertados
fake_db = {}

def mock_execute_select_private():
    return MagicMock(data=[{"private_key": fake_db["test-user-123"]["private"]}])

def mock_execute_select_public():
    return MagicMock(data=[{"public_key": fake_db["test-user-123"]["public"]}])

def mock_execute_upsert(data):
    fake_db[data["user_id"]] = {
        "private": data["private_key"],
        "public": data["public_key"]
    }
    return MagicMock()

# Setup Supabase Mock
mock_supabase = MagicMock()
api.main.supabase = mock_supabase
api.main.create_client = MagicMock(return_value=mock_supabase)

def setup_mock_db():
    class TableMock:
        def __init__(self, table_name):
            self.table_name = table_name
            self.current_op = None
            self.upsert_data = None
            
        def upsert(self, data):
            self.current_op = "upsert"
            self.upsert_data = data
            return self
            
        def select(self, *args):
            self.current_op = "select"
            return self
            
        def eq(self, field, value):
            return self
            
        def execute(self):
            if self.current_op == "upsert":
                return mock_execute_upsert(self.upsert_data)
            elif self.current_op == "select":
                # A hack to return private or public depending on route
                if "signature_b64" in locals().get("self", ""): 
                    pass
                # The mock just uses the test-user-123 static fallback
                pass
                
    # Better structure: just MagicMock with side effects
    pass

from fastapi.testclient import TestClient
from api.main import app
import mldsa.mldsa as mldsa

def test_flow():
    client = TestClient(app)
    auth_headers = {"Authorization": "Bearer test-token"}
    
    # 1. Test Generate
    # Reemplazamos la lógica del mock para poder usar la clave generada
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table
    mock_upsert = MagicMock()
    mock_table.upsert.return_value = mock_upsert
    
    # Se llama a generate
    res_gen = client.post("/api/generate", headers=auth_headers)
    assert res_gen.status_code == 200, res_gen.text
    print("Generate API [OK]:", res_gen.json())
    
    # Tomamos la data que intentó guardar upsert
    upsert_call_args = mock_upsert.execute.call_args
    # call_args no lo pillamos así si lo encadenamos, vamos a crear las llaves manualmente para las subsiguientes
    pk, sk = mldsa.keygen()
    pk_b64 = base64.b64encode(pk).decode("utf-8")
    sk_b64 = base64.b64encode(sk).decode("utf-8")
    
    # Creamos un mock con una respuesta específica para la clave privada
    mock_execute_priv = MagicMock()
    mock_execute_priv.data = {"private_key": sk_b64}
    mock_single_priv = MagicMock()
    mock_single_priv.execute.return_value = mock_execute_priv
    mock_eq_priv = MagicMock()
    mock_eq_priv.single.return_value = mock_single_priv
    mock_select_priv = MagicMock()
    mock_select_priv.eq.return_value = mock_eq_priv
    
    # 2. Test Sign
    mock_table.select.return_value = mock_select_priv
    
    with open("test.pdf", "wb") as f:
        f.write(b"Dummy PDF Content")
        
    with open("test.pdf", "rb") as f:
        res_sign = client.post("/api/sign", headers=auth_headers, files={"file": ("test.pdf", f, "application/pdf")})
    
    assert res_sign.status_code == 200, res_sign.text
    sig_b64 = res_sign.json()["signature_b64"]
    print("Sign API [OK]: Signature generated successfully")
    
    # 3. Test Verify
    sig_bytes = base64.b64decode(sig_b64)
    with open("test.pdf", "rb") as f:
        res_verify = client.post(
            "/api/verify", 
            headers=auth_headers, 
            files={
                "file": ("test.pdf", f, "application/pdf"),
                "signature": ("signature.sig", sig_bytes, "application/octet-stream")
            },
            data={"public_key": pk_b64}
        )
        
    assert res_verify.status_code == 200, res_verify.text
    is_valid = res_verify.json()["is_valid"]
    print(f"Verify API [OK]: Result: {is_valid}")
    assert is_valid == True
    
    # 4. Test Sign & Verify by Hash (JSON Payload)
    import hashlib
    dummy_bytes = b"Dummy PDF Content"
    doc_hash_hex = hashlib.sha256(dummy_bytes).hexdigest()
    
    res_sign_hash = client.post(
        "/api/sign",
        headers=auth_headers,
        json={"document_hash": doc_hash_hex}
    )
    assert res_sign_hash.status_code == 200, res_sign_hash.text
    hash_sig_b64 = res_sign_hash.json()["signature_b64"]
    print("Sign API via Hash [OK]: Signature generated successfully")
    
    res_verify_hash = client.post(
        "/api/verify",
        headers=auth_headers,
        json={
            "document_hash": doc_hash_hex,
            "signature_b64": hash_sig_b64,
            "public_key": pk_b64
        }
    )
    assert res_verify_hash.status_code == 200, res_verify_hash.text
    assert res_verify_hash.json()["is_valid"] == True
    print("Verify API via Hash [OK]: Result: True")

    # Limpiamos
    os.remove("test.pdf")
    print("Todos los endpoints integrados con MLDSA (archivos y hashes) funcionan correctamente bajo entorno simulado.")

if __name__ == "__main__":
    test_flow()

