from typing import Tuple, List
from mlkem.constants import N
from mlkem.parameters.params import MLKEMParameters
from mlkem.crypto.hash import hash_g, prf
from mlkem.sampling.sampling import sample_ntt, sample_poly_cbd
from mlkem.encoding.coding import compress, decompress, byte_encode, byte_decode
from mlkem.ntt.ntt import (
    ntt, ntt_inv, poly_add, poly_sub,
    mat_vec_mul_ntt, mat_transpose_vec_mul_ntt, dot_product_ntt
)


def k_pke_keygen(params: MLKEMParameters, d: bytes) -> Tuple[bytes, bytes]:
    """Algorithm 13: K-PKE.KeyGen(d)
    Genera ek_PKE y dk_PKE a partir de una semilla d de 32 bytes.
    """
    if len(d) != 32:
        raise ValueError("La semilla d debe tener exactamente 32 bytes.")

    k = params.k
    eta1 = params.eta1

    # Línea 1: (rho, sigma) <- G(d || k) (Separación de dominios FIPS 203 final)
    rho, sigma = hash_g(d + bytes([k]))

    # Línea 2: N <- 0
    nonce = 0

    # Líneas 3-7: Generar matriz A_hat k x k en T_q
    A_hat: List[List[List[int]]] = []
    for i in range(k):
        row = []
        for j in range(k):
            # Línea 5: SampleNTT(rho || j || i)
            row.append(sample_ntt(rho + bytes([j, i])))
        A_hat.append(row)

    # Líneas 8-11: Muestrear s in R_q^k desde CBD_eta1
    s: List[List[int]] = []
    for _ in range(k):
        s.append(sample_poly_cbd(prf(eta1, sigma, nonce), eta1))
        nonce += 1

    # Líneas 12-15: Muestrear e in R_q^k desde CBD_eta1
    e: List[List[int]] = []
    for _ in range(k):
        e.append(sample_poly_cbd(prf(eta1, sigma, nonce), eta1))
        nonce += 1

    # Línea 16: s_hat <- NTT(s)
    s_hat = [ntt(s[i]) for i in range(k)]

    # Línea 17: e_hat <- NTT(e)
    e_hat = [ntt(e[i]) for i in range(k)]

    # Línea 18: t_hat <- A_hat o s_hat + e_hat
    As_hat = mat_vec_mul_ntt(A_hat, s_hat)
    t_hat = [poly_add(As_hat[i], e_hat[i]) for i in range(k)]

    # Línea 19: ek_PKE <- ByteEncode_12(t_hat) || rho
    ek_pke_bytes = bytearray()
    for i in range(k):
        ek_pke_bytes.extend(byte_encode(t_hat[i], 12))
    ek_pke_bytes.extend(rho)

    # Línea 20: dk_PKE <- ByteEncode_12(s_hat)
    dk_pke_bytes = bytearray()
    for i in range(k):
        dk_pke_bytes.extend(byte_encode(s_hat[i], 12))

    # Línea 21: return (ek_PKE, dk_PKE)
    return bytes(ek_pke_bytes), bytes(dk_pke_bytes)


def k_pke_encrypt(params: MLKEMParameters, ek_pke: bytes, m: bytes, r: bytes) -> bytes:
    """Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r)
    Cifra un mensaje m de 32 bytes usando la clave pública ek_PKE y aleatoriedad r.
    """
    if len(ek_pke) != params.ek_pke_len:
        raise ValueError(f"ek_pke debe tener {params.ek_pke_len} bytes.")
    if len(m) != 32:
        raise ValueError("El mensaje m debe tener exactamente 32 bytes.")
    if len(r) != 32:
        raise ValueError("La aleatoriedad r debe tener exactamente 32 bytes.")

    k = params.k
    eta1 = params.eta1
    eta2 = params.eta2
    du = params.du
    dv = params.dv

    # Línea 1: N <- 0
    nonce = 0

    # Línea 2: t_hat <- ByteDecode_12(ek_PKE[0 : 384k])
    t_hat: List[List[int]] = []
    for i in range(k):
        chunk = ek_pke[384 * i : 384 * (i + 1)]
        t_hat.append(byte_decode(chunk, 12))

    # Línea 3: rho <- ek_PKE[384k : 384k + 32]
    rho = ek_pke[384 * k : 384 * k + 32]

    # Líneas 4-8: Regenerar matriz A_hat
    A_hat: List[List[List[int]]] = []
    for i in range(k):
        row = []
        for j in range(k):
            row.append(sample_ntt(rho + bytes([j, i])))
        A_hat.append(row)

    # Líneas 9-12: Muestrear y in R_q^k desde CBD_eta1
    y: List[List[int]] = []
    for _ in range(k):
        y.append(sample_poly_cbd(prf(eta1, r, nonce), eta1))
        nonce += 1

    # Líneas 13-16: Muestrear e1 in R_q^k desde CBD_eta2
    e1: List[List[int]] = []
    for _ in range(k):
        e1.append(sample_poly_cbd(prf(eta2, r, nonce), eta2))
        nonce += 1

    # Línea 17: Muestrear e2 in R_q desde CBD_eta2
    e2 = sample_poly_cbd(prf(eta2, r, nonce), eta2)

    # Línea 18: y_hat <- NTT(y)
    y_hat = [ntt(y[i]) for i in range(k)]

    # Línea 19: u <- NTT^-1(A_hat^T o y_hat) + e1
    At_y = mat_transpose_vec_mul_ntt(A_hat, y_hat)
    u: List[List[int]] = []
    for i in range(k):
        u_poly = poly_add(ntt_inv(At_y[i]), e1[i])
        u.append(u_poly)

    # Línea 20: mu <- Decompress_1(ByteDecode_1(m))
    m_decoded = byte_decode(m, 1)
    mu = [decompress(coeff, 1) for coeff in m_decoded]

    # Línea 21: v <- NTT^-1(t_hat^T o y_hat) + e2 + mu
    t_dot_y = dot_product_ntt(t_hat, y_hat)
    v_partial = poly_add(ntt_inv(t_dot_y), e2)
    v = poly_add(v_partial, mu)

    # Línea 22: c1 <- ByteEncode_du(Compress_du(u))
    c1_bytes = bytearray()
    for i in range(k):
        comp_u = [compress(val, du) for val in u[i]]
        c1_bytes.extend(byte_encode(comp_u, du))

    # Línea 23: c2 <- ByteEncode_dv(Compress_dv(v))
    comp_v = [compress(val, dv) for val in v]
    c2_bytes = byte_encode(comp_v, dv)

    # Línea 24: return c <- c1 || c2
    return bytes(c1_bytes + c2_bytes)


def k_pke_decrypt(params: MLKEMParameters, dk_pke: bytes, c: bytes) -> bytes:
    """Algorithm 15: K-PKE.Decrypt(dk_PKE, c)
    Descifra el ciphertext c usando la clave privada dk_PKE y devuelve el mensaje m.
    """
    if len(dk_pke) != params.dk_pke_len:
        raise ValueError(f"dk_pke debe tener {params.dk_pke_len} bytes.")
    if len(c) != params.c_len:
        raise ValueError(f"c debe tener {params.c_len} bytes.")

    k = params.k
    du = params.du
    dv = params.dv

    # Línea 1: c1 <- c[0 : 32 * du * k]
    split_idx = 32 * du * k
    c1 = c[:split_idx]

    # Línea 2: c2 <- c[32 * du * k : 32 * (du * k + dv)]
    c2 = c[split_idx : split_idx + 32 * dv]

    # Línea 3: u_prime <- Decompress_du(ByteDecode_du(c1))
    u_prime: List[List[int]] = []
    chunk_size = 32 * du
    for i in range(k):
        chunk = c1[i * chunk_size : (i + 1) * chunk_size]
        decoded_u = byte_decode(chunk, du)
        u_prime.append([decompress(val, du) for val in decoded_u])

    # Línea 4: v_prime <- Decompress_dv(ByteDecode_dv(c2))
    decoded_v = byte_decode(c2, dv)
    v_prime = [decompress(val, dv) for val in decoded_v]

    # Línea 5: s_hat <- ByteDecode_12(dk_PKE)
    s_hat: List[List[int]] = []
    for i in range(k):
        chunk = dk_pke[384 * i : 384 * (i + 1)]
        s_hat.append(byte_decode(chunk, 12))

    # Línea 6: w <- v_prime - NTT^-1(s_hat^T o NTT(u_prime))
    ntt_u = [ntt(u_prime[i]) for i in range(k)]
    s_dot_u = dot_product_ntt(s_hat, ntt_u)
    inv_prod = ntt_inv(s_dot_u)
    w = poly_sub(v_prime, inv_prod)

    # Línea 7: m <- ByteEncode_1(Compress_1(w))
    comp_w = [compress(val, 1) for val in w]
    m = byte_encode(comp_w, 1)

    # Línea 8: return m
    return m