import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Cifra datos usando AES-256-GCM.

    - key: Clave simétrica de 32 bytes (la derivada de ML-KEM).
    - plaintext: Mensaje en claro.
    - associated_data: Datos adicionales autenticados (opcional).

    Devuelve: (nonce de 12 bytes, ciphertext_con_tag)
    """
    if len(key) != 32:
        raise ValueError("La clave para AES-256-GCM debe tener exactamente 32 bytes.")

    # Nonce estándar recomendado por NIST de 96 bits (12 bytes)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    # AESGCM de 'cryptography' concatena automáticamente el tag de autenticación (16 bytes) al final
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    return nonce, ciphertext_and_tag


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, associated_data: bytes = b"") -> bytes:
    """Descifra y verifica la autenticidad de los datos.

    Lanza InvalidTag si los datos, el nonce o la clave han sido manipulados.
    """
    if len(key) != 32:
        raise ValueError("La clave para AES-256-GCM debe tener exactamente 32 bytes.")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)