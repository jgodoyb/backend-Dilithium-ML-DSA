from typing import List
from mlkem.constants import N, Q
from mlkem.crypto.hash import SHAKE128XOF
from mlkem.primitives.conversions import bytes_to_bits


def sample_ntt(B: bytes) -> List[int]:
    """Algorithm 7: SampleNTT(B)

    Muestrea un elemento pseudialeatorio de T_q a partir de una semilla B de 34
    bytes (semilla de 32 bytes + 2 índices de coordenadas).
    """
    if len(B) != 34:
        raise ValueError("SampleNTT requiere una entrada de exactamente 34 bytes (rho || j || i).")

    # Línea 1: ctx <- XOF.Init()
    ctx = SHAKE128XOF()

    # Línea 2: ctx <- XOF.Absorb(ctx, B)
    ctx.absorb(B)

    # Inicializar array a_hat de longitud 256 en Z_q
    a_hat = [0] * N

    # Línea 3: j <- 0
    j = 0

    # Línea 4: while j < 256 do
    while j < N:
        # Línea 5: (ctx, C) <- XOF.Squeeze(ctx, 3)
        C = ctx.squeeze(3)

        # Línea 6: d1 <- C[0] + 256 * (C[1] mod 16)
        d1 = C[0] + 256 * (C[1] % 16)

        # Línea 7: d2 <- |_ C[1] / 16 _| + 16 * C[2]
        d2 = (C[1] // 16) + 16 * C[2]

        # Línea 8-11:
        if d1 < Q:
            a_hat[j] = d1
            j += 1

        # Línea 12-15:
        if d2 < Q and j < N:
            a_hat[j] = d2
            j += 1

    # Línea 17: return a_hat
    return a_hat


def sample_poly_cbd(B: bytes, eta: int) -> List[int]:
    """Algorithm 8: SamplePolyCBD_eta(B)

    Muestrea un polinomio con distribución binomial centrada D_eta(R_q).
    Input: byte array B in B^{64 * eta}.
    Output: array f in Z_q^{256}.
    """
    if eta not in (2, 3):
        raise ValueError("eta debe ser 2 o 3 en ML-KEM.")

    expected_len = 64 * eta
    if len(B) != expected_len:
        raise ValueError(f"B debe tener exactamente {expected_len} bytes para eta={eta}.")

    # Línea 1: b <- BytesToBits(B)
    b = bytes_to_bits(B)
    f = [0] * N

    # Línea 2: for (i <- 0; i < 256; i++)
    for i in range(N):
        # Línea 3: x <- sum_{j=0}^{eta - 1} b[2 * i * eta + j]
        x = sum(b[2 * i * eta + j] for j in range(eta))

        # Línea 4: y <- sum_{j=0}^{eta - 1} b[2 * i * eta + eta + j]
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))

        # Línea 5: f[i] <- (x - y) mod q
        f[i] = (x - y) % Q

    # Línea 7: return f
    return f