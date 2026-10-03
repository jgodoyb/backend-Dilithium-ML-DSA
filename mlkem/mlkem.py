import os
import hmac
from typing import Tuple, Optional
from mlkem.parameters.params import MLKEMParameters, ML_KEM_768
from mlkem.encoding.coding import byte_decode, byte_encode
from mlkem.crypto.hash import hash_h
from mlkem.core.internal import (
    ml_kem_keygen_internal,
    ml_kem_encaps_internal,
    ml_kem_decaps_internal
)


def validate_encapsulation_key(params: MLKEMParameters, ek: bytes) -> bool:
    """Sección 7.2: Encapsulation key check.
    1. Type check: longitud exacta 384k + 32.
    2. Modulus check: ByteEncode_12(ByteDecode_12(ek[0:384k])) == ek[0:384k].
    """
    if not isinstance(ek, (bytes, bytearray)):
        return False
    if len(ek) != params.ek_pke_len:
        return False

    k = params.k
    ek_t = ek[: 384 * k]
    re_encoded = bytearray()
    for i in range(k):
        chunk = ek_t[384 * i : 384 * (i + 1)]
        decoded = byte_decode(chunk, 12)
        re_encoded.extend(byte_encode(decoded, 12))

    return hmac.compare_digest(bytes(re_encoded), ek_t)


def validate_decapsulation_input(params: MLKEMParameters, dk: bytes, c: bytes) -> bool:
    """Sección 7.3: Decapsulation input check.
    1. Ciphertext type check: len(c) == 32 * (du * k + dv).
    2. Decapsulation key type check: len(dk) == 768k + 96.
    3. Hash check: H(ek) == dk[768k+32 : 768k+64].
    """
    if not isinstance(c, (bytes, bytearray)) or len(c) != params.c_len:
        return False

    k = params.k
    expected_dk_len = 768 * k + 96
    if not isinstance(dk, (bytes, bytearray)) or len(dk) != expected_dk_len:
        return False

    ek = dk[384 * k : 768 * k + 32]
    expected_hash = dk[768 * k + 32 : 768 * k + 64]
    computed_hash = hash_h(ek)

    return hmac.compare_digest(computed_hash, expected_hash)


def ml_kem_keygen(params: MLKEMParameters = ML_KEM_768) -> Tuple[bytes, bytes]:
    """Algorithm 19: ML-KEM.KeyGen()
    Genera un par de claves (ek, dk) usando el generador de entropía del sistema (RBG).
    """
    try:
        # Línea 1-2: d <-$ B^32, z <-$ B^32
        d = os.urandom(32)
        z = os.urandom(32)
    except Exception:
        # Línea 3-4: if d == NULL or z == NULL then return bot
        raise RuntimeError("Fallo crítico en la generación de números aleatorios (RBG).")

    # Línea 6: (ek, dk) <- ML-KEM.KeyGen_internal(d, z)
    return ml_kem_keygen_internal(params, d, z)


def ml_kem_encaps(params: MLKEMParameters, ek: bytes) -> Tuple[bytes, bytes]:
    """Algorithm 20: ML-KEM.Encaps(ek)
    Encapsula una llave secreta de 32 bytes con la clave pública ek.
    """
    # Verificación de entrada (Sección 7.2)
    if not validate_encapsulation_key(params, ek):
        raise ValueError("Clave de encapsulación inválida (falló Type Check o Modulus Check).")

    try:
        # Línea 1: m <-$ B^32
        m = os.urandom(32)
    except Exception:
        # Línea 2-3: if m == NULL then return bot
        raise RuntimeError("Fallo crítico en la generación de números aleatorios (RBG).")

    # Línea 5: (K, c) <- ML-KEM.Encaps_internal(ek, m)
    return ml_kem_encaps_internal(params, ek, m)


def ml_kem_decaps(params: MLKEMParameters, dk: bytes, c: bytes) -> bytes:
    """Algorithm 21: ML-KEM.Decaps(dk, c)
    Desencapsula el ciphertext c usando la clave privada dk para obtener la llave compartida K.
    """
    # Verificación de entrada (Sección 7.3)
    if not validate_decapsulation_input(params, dk, c):
        raise ValueError("Entrada de desencapsulado inválida (falló Type Check o Hash Check).")

    # Línea 1: K_prime <- ML-KEM.Decaps_internal(dk, c)
    return ml_kem_decaps_internal(params, dk, c)