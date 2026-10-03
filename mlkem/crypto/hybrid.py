import os
from mlkem.parameters.params import MLKEMParameters, ML_KEM_768
from mlkem.core.internal import (
    ml_kem_keygen_internal,
    ml_kem_encaps_internal,
    ml_kem_decaps_internal,
)
from mlkem.crypto.symmetric import encrypt_aes_gcm, decrypt_aes_gcm


class HybridPQC:
    def __init__(self, params: MLKEMParameters = ML_KEM_768):
        self.params = params

    def keygen(self) -> tuple[bytes, bytes]:
        """Genera par de claves (ek, dk) según FIPS 203 usando entropía del sistema."""
        d = os.urandom(32)
        z = os.urandom(32)
        return ml_kem_keygen_internal(self.params, d, z)

    def encrypt_payload(self, ek: bytes, plaintext: bytes) -> dict:
        """Flujo emisor: Encapsula con ML-KEM y cifra con AES-256-GCM."""
        # 1. Semilla m de 32 bytes para la encapsulación
        m = os.urandom(32)
        shared_key, capsule = ml_kem_encaps_internal(self.params, ek, m)

        # 2. Cifrado simétrico AES-256-GCM con el secreto compartido (32 bytes)
        nonce, ciphertext_and_tag = encrypt_aes_gcm(shared_key, plaintext)

        return {
            "capsule": capsule,
            "nonce": nonce,
            "ciphertext": ciphertext_and_tag,
        }

    def encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        """Encapsula una llave secreta compartida K con la clave pública ek.

        Devuelve: (shared_key de 32 bytes, capsule)
        """
        from mlkem.mlkem import ml_kem_encaps
        return ml_kem_encaps(self.params, ek)

    def decapsulate(self, dk: bytes, capsule: bytes) -> bytes:
        """Desencapsula la cápsula con la clave privada dk para obtener la llave compartida K.

        Devuelve: shared_key de 32 bytes
        """
        from mlkem.mlkem import ml_kem_decaps
        return ml_kem_decaps(self.params, dk, capsule)

    def decrypt_payload(self, dk: bytes, capsule: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Flujo receptor: Decapsula con ML-KEM y descifra con AES-256-GCM."""
        # 1. Decapsulación formal FIPS 203 (con rechazo implícito)
        shared_key = ml_kem_decaps_internal(self.params, dk, capsule)

        # 2. Descifrado autenticado con AES-256-GCM
        return decrypt_aes_gcm(shared_key, nonce, ciphertext)