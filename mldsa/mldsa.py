# src/mldsa/mldsa.py
import os
import hashlib
from mldsa.core import keygen_internal, sign_internal, verify_internal

# Función auxiliar para IntegerToBytes(x, 1) usada en los prefijos
def _int_to_byte(val: int) -> bytes:
    return bytes([val])

# --- OIDs en formato DER (Distinguished Encoding Rules) para las variantes Pre-Hash ---
# Definidos en el Algoritmo 4 y 5 del FIPS 204
OID_SHA256 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
OID_SHA512 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
OID_SHAKE128 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B])

# =============================================================================
# ALGORITMO 1: ML-DSA.KeyGen()
# =============================================================================
def keygen(level: str = "ML_DSA_65") -> tuple[bytes, bytes]:
    """Genera un par de claves (pk, sk)."""
    # 1: xi <- B^32 (Entropía aleatoria del sistema)
    xi = os.urandom(32)
    # 2-4: Manejo de errores de entropía (os.urandom lanzaría excepción si falla)
    # 5: return ML-DSA.KeyGen_internal(xi)
    return keygen_internal(xi, level=level)

# =============================================================================
# ALGORITMO 2: ML-DSA.Sign(sk, M, ctx)
# =============================================================================
def sign(sk: bytes, M: bytes, ctx: bytes = b"", level: str = "ML_DSA_65") -> bytes:
    """Firma un mensaje M (variante pura)."""
    # 1-3: if |ctx| > 255 then return perpendicular
    if len(ctx) > 255:
        raise ValueError("El contexto no puede exceder los 255 bytes.")
    
    # 5: rnd <- B^32 (Variante hedged por defecto)
    rnd = os.urandom(32)
    
    # 10: M' <- 0 || len(ctx) || ctx || M
    m_prime = _int_to_byte(0) + _int_to_byte(len(ctx)) + ctx + M
    
    # 11: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
    return sign_internal(sk, m_prime, rnd, level=level)

# =============================================================================
# ALGORITMO 3: ML-DSA.Verify(pk, M, sigma, ctx)
# =============================================================================
def verify(pk: bytes, M: bytes, sigma: bytes, ctx: bytes = b"", level: str = "ML_DSA_65") -> bool:
    """Verifica una firma (variante pura)."""
    # 1-3: if |ctx| > 255 then return perpendicular
    if len(ctx) > 255:
        return False
        
    # 5: M' <- 0 || len(ctx) || ctx || M
    m_prime = _int_to_byte(0) + _int_to_byte(len(ctx)) + ctx + M
    
    # 6: return ML-DSA.Verify_internal(pk, M', sigma)
    return verify_internal(pk, m_prime, sigma, level=level)

# =============================================================================
# ALGORITMO 4: HashML-DSA.Sign(sk, M, ctx, PH)
# =============================================================================
def hash_sign_digest(sk: bytes, ph_m: bytes, ph_algo: str = "SHA-256", ctx: bytes = b"", level: str = "ML_DSA_65") -> bytes:
    """Firma un digest (hash precalculado ph_m) usando la variante Pre-Hash (HashML-DSA)."""
    if len(ctx) > 255:
        raise ValueError("El contexto no puede exceder los 255 bytes.")
        
    rnd = os.urandom(32)
    ph_algo = ph_algo.upper()
    if ph_algo == "SHA-256":
        if len(ph_m) != 32:
            raise ValueError("El digest para SHA-256 debe tener 32 bytes.")
        oid = OID_SHA256
    elif ph_algo == "SHA-512":
        if len(ph_m) != 64:
            raise ValueError("El digest para SHA-512 debe tener 64 bytes.")
        oid = OID_SHA512
    elif ph_algo == "SHAKE128":
        if len(ph_m) != 32:
            raise ValueError("El digest para SHAKE128 debe tener 32 bytes.")
        oid = OID_SHAKE128
    else:
        raise ValueError(f"Algoritmo Pre-Hash no soportado: {ph_algo}")
        
    m_prime = _int_to_byte(1) + _int_to_byte(len(ctx)) + ctx + oid + ph_m
    return sign_internal(sk, m_prime, rnd, level=level)


def hash_sign(sk: bytes, M: bytes, ph_algo: str = "SHA-256", ctx: bytes = b"", level: str = "ML_DSA_65") -> bytes:
    """Firma un mensaje M calculando primero su hash (variante Pre-Hash HashML-DSA)."""
    ph_algo_upper = ph_algo.upper()
    if ph_algo_upper == "SHA-256":
        ph_m = hashlib.sha256(M).digest()
    elif ph_algo_upper == "SHA-512":
        ph_m = hashlib.sha512(M).digest()
    elif ph_algo_upper == "SHAKE128":
        ph_m = hashlib.shake_128(M).digest(32)
    else:
        raise ValueError(f"Algoritmo Pre-Hash no soportado: {ph_algo}")
        
    return hash_sign_digest(sk=sk, ph_m=ph_m, ph_algo=ph_algo, ctx=ctx, level=level)

# =============================================================================
# ALGORITMO 5: HashML-DSA.Verify(pk, M, sigma, ctx, PH)
# =============================================================================
def hash_verify_digest(pk: bytes, ph_m: bytes, sigma: bytes, ph_algo: str = "SHA-256", ctx: bytes = b"", level: str = "ML_DSA_65") -> bool:
    """Verifica una firma contra un digest (hash precalculado ph_m) usando HashML-DSA."""
    if len(ctx) > 255:
        return False
        
    ph_algo_upper = ph_algo.upper()
    if ph_algo_upper == "SHA-256":
        if len(ph_m) != 32:
            return False
        oid = OID_SHA256
    elif ph_algo_upper == "SHA-512":
        if len(ph_m) != 64:
            return False
        oid = OID_SHA512
    elif ph_algo_upper == "SHAKE128":
        if len(ph_m) != 32:
            return False
        oid = OID_SHAKE128
    else:
        return False
        
    m_prime = _int_to_byte(1) + _int_to_byte(len(ctx)) + ctx + oid + ph_m
    return verify_internal(pk, m_prime, sigma, level=level)


def hash_verify(pk: bytes, M: bytes, sigma: bytes, ph_algo: str = "SHA-256", ctx: bytes = b"", level: str = "ML_DSA_65") -> bool:
    """Verifica una firma calculando primero el hash del mensaje M."""
    ph_algo_upper = ph_algo.upper()
    if ph_algo_upper == "SHA-256":
        ph_m = hashlib.sha256(M).digest()
    elif ph_algo_upper == "SHA-512":
        ph_m = hashlib.sha512(M).digest()
    elif ph_algo_upper == "SHAKE128":
        ph_m = hashlib.shake_128(M).digest(32)
    else:
        return False
        
    return hash_verify_digest(pk=pk, ph_m=ph_m, sigma=sigma, ph_algo=ph_algo, ctx=ctx, level=level)