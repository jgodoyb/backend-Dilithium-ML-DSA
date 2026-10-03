from typing import Sequence, List, Tuple
from mlkem.constants import N, Q, ZETA

# Apéndice A (FIPS 203): zetas[i] = ZETA^(BitRev7(i)) mod q para i = 0 ... 127
ZETAS: List[int] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
]


def bit_rev_7(r: int) -> int:
    """Invierte los 7 bits del entero r (0 <= r < 128)."""
    ans = 0
    for _ in range(7):
        ans = (ans << 1) | (r & 1)
        r >>= 1
    return ans


def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> Tuple[int, int]:
    """Algorithm 12: BaseCaseMultiply(a0, a1, b0, b1, gamma)

    Multiplica dos polinomios de grado 1 respecto a X^2 - gamma mod q.
    """
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f_hat: Sequence[int], g_hat: Sequence[int]) -> List[int]:
    """Algorithm 11: MultiplyNTTs(f_hat, g_hat)

    Multiplica dos polinomios en el dominio NTT (T_q).
    """
    if len(f_hat) != N or len(g_hat) != N:
        raise ValueError(f"Las entradas deben tener longitud {N}.")

    h_hat = [0] * N
    for i in range(128):
        # gamma = ZETA^(2 * BitRev7(i) + 1) mod q
        gamma = pow(ZETA, 2 * bit_rev_7(i) + 1, Q)
        c0, c1 = base_case_multiply(
            f_hat[2 * i], f_hat[2 * i + 1],
            g_hat[2 * i], g_hat[2 * i + 1],
            gamma
        )
        h_hat[2 * i] = c0
        h_hat[2 * i + 1] = c1

    return h_hat


def ntt(f: Sequence[int]) -> List[int]:
    """Algorithm 9: NTT(f)

    Transforma un polinomio de R_q a su representación NTT en T_q.
    """
    if len(f) != N:
        raise ValueError(f"f debe tener longitud {N}.")

    f_hat = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length //= 2

    return f_hat


def ntt_inv(f_hat: Sequence[int]) -> List[int]:
    """Algorithm 10: NTT^-1(f_hat)

    Transformada inversa: T_q -> R_q.
    Multiplica al final por 3303 = 128^-1 mod q.
    """
    if len(f_hat) != N:
        raise ValueError(f"f_hat debe tener longitud {N}.")

    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2

    # Factor de escalado 128^-1 mod 3329 = 3303
    inv_128 = 3303
    for j in range(N):
        f[j] = (f[j] * inv_128) % Q

    return f


# Funciones de apoyo para vectores y matrices sobre T_q (Sección 2.4.7)

def poly_add(a: Sequence[int], b: Sequence[int]) -> List[int]:
    """Suma coeficiente a coeficiente dos polinomios modulo q."""
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int]) -> List[int]:
    """Resta coeficiente a coeficiente dos polinomios modulo q."""
    return [(x - y) % Q for x, y in zip(a, b)]


def mat_vec_mul_ntt(A_hat: List[List[List[int]]], s_hat: List[List[int]]) -> List[List[int]]:
    """Ecuación 2.12: w_hat = A_hat o s_hat

    Multiplica una matriz k x k por un vector k x 1 en el dominio NTT.
    """
    k = len(A_hat)
    w_hat = [[0] * N for _ in range(k)]
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            prod = multiply_ntts(A_hat[i][j], s_hat[j])
            acc = poly_add(acc, prod)
        w_hat[i] = acc
    return w_hat


def mat_transpose_vec_mul_ntt(A_hat: List[List[List[int]]], y_hat: List[List[int]]) -> List[List[int]]:
    """Ecuación 2.13: w_hat = A_hat^T o y_hat

    Multiplica la traspuesta de una matriz k x k por un vector k x 1 en T_q.
    """
    k = len(A_hat)
    w_hat = [[0] * N for _ in range(k)]
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            prod = multiply_ntts(A_hat[j][i], y_hat[j])
            acc = poly_add(acc, prod)
        w_hat[i] = acc
    return w_hat


def dot_product_ntt(u_hat: List[List[int]], v_hat: List[List[int]]) -> List[int]:
    """Ecuación 2.14: z_hat = u_hat^T o v_hat

    Producto escalar de dos vectores de dimension k en T_q.
    """
    k = len(u_hat)
    acc = [0] * N
    for i in range(k):
        prod = multiply_ntts(u_hat[i], v_hat[i])
        acc = poly_add(acc, prod)
    return acc