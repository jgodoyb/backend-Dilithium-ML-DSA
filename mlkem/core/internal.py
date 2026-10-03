import hmac
from typing import Tuple
from mlkem.parameters.params import MLKEMParameters
from mlkem.crypto.hash import hash_h, hash_g, hash_j
from mlkem.pke.kpke import k_pke_keygen, k_pke_encrypt, k_pke_decrypt


def ml_kem_keygen_internal(params: MLKEMParameters, d: bytes, z: bytes) -> Tuple[bytes, bytes]:
    """Algorithm 16: ML-KEM.KeyGen_internal(d, z)

    Genera deterministamente la clave de encapsulación (ek) y decapsulación (dk).
    Input: randomness d in B^32, z in B^32.
    Output: ek in B^{384k + 32}, dk in B^{768k + 96}.
    """
    if len(d) != 32 or len(z) != 32:
        raise ValueError("Las semillas d y z deben tener exactamente 32 bytes cada una.")

    # Línea 1: (ek_PKE, dk_PKE) <- K-PKE.KeyGen(d)
    ek_pke, dk_pke = k_pke_keygen(params, d)

    # Línea 2: ek <- ek_PKE
    ek = ek_pke

    # Línea 3: dk <- (dk_PKE || ek || H(ek) || z)
    h_ek = hash_h(ek)
    dk = dk_pke + ek + h_ek + z

    # Línea 4: return (ek, dk)
    return ek, dk


def ml_kem_encaps_internal(params: MLKEMParameters, ek: bytes, m: bytes) -> Tuple[bytes, bytes]:
    """Algorithm 17: ML-KEM.Encaps_internal(ek, m)

    Genera una llave secreta compartida K y su ciphertext asociado c a partir de m.
    Input: ek in B^{384k + 32}, m in B^32.
    Output: shared key K in B^32, ciphertext c in B^{32(du*k + dv)}.
    """
    if len(ek) != params.ek_pke_len:
        raise ValueError(f"ek debe tener {params.ek_pke_len} bytes.")
    if len(m) != 32:
        raise ValueError("La aleatoriedad m debe tener exactamente 32 bytes.")

    # Línea 1: (K, r) <- G(m || H(ek))
    h_ek = hash_h(ek)
    K, r = hash_g(m + h_ek)

    # Línea 2: c <- K-PKE.Encrypt(ek, m, r)
    c = k_pke_encrypt(params, ek, m, r)

    # Línea 3: return (K, c)
    return K, c


def ml_kem_decaps_internal(params: MLKEMParameters, dk: bytes, c: bytes) -> bytes:
    """Algorithm 18: ML-KEM.Decaps_internal(dk, c)

    Extrae la clave compartida K a partir del ciphertext c y la clave privada dk.
    Implementa el mecanismo de rechazo implícito frente a manipulaciones.
    """
    k = params.k
    expected_dk_len = 768 * k + 96
    if len(dk) != expected_dk_len:
        raise ValueError(f"dk debe tener exactamente {expected_dk_len} bytes.")
    if len(c) != params.c_len:
        raise ValueError(f"c debe tener exactamente {params.c_len} bytes.")

    # Línea 1: dk_PKE <- dk[0 : 384k]
    dk_pke = dk[: 384 * k]

    # Línea 2: ek_PKE <- dk[384k : 768k + 32]
    ek_pke = dk[384 * k : 768 * k + 32]

    # Línea 3: h <- dk[768k + 32 : 768k + 64]
    h = dk[768 * k + 32 : 768 * k + 64]

    # Línea 4: z <- dk[768k + 64 : 768k + 96]
    z = dk[768 * k + 64 : 768 * k + 96]

    # Línea 5: m_prime <- K-PKE.Decrypt(dk_PKE, c)
    m_prime = k_pke_decrypt(params, dk_pke, c)

    # Línea 6: (K_prime, r_prime) <- G(m_prime || h)
    K_prime, r_prime = hash_g(m_prime + h)

    # Línea 7: K_bar <- J(z || c)
    K_bar = hash_j(z + c)

    # Línea 8: c_prime <- K-PKE.Encrypt(ek_PKE, m_prime, r_prime)
    c_prime = k_pke_encrypt(params, ek_pke, m_prime, r_prime)

    # Líneas 9-11: if c != c_prime then K_prime <- K_bar
    # Usamos compare_digest para mitigar fugas temporales en la comparación
    if not hmac.compare_digest(c, c_prime):
        K_prime = K_bar

    # Línea 12: return K_prime
    return K_prime