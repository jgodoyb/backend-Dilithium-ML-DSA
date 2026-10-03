from typing import Sequence, List
from mlkem.constants import N, Q
from mlkem.primitives.conversions import bits_to_bytes, bytes_to_bits


def compress(x: int, d: int) -> int:
    """
    Ecuación 4.7: Compress_d(x)
    Compress_d: Z_q -> Z_{2^d}
    x |-> round((2^d / q) * x) mod 2^d
    """
    if not (1 <= d < 12):
        raise ValueError("Masapul a 1 <= d < 12 para iti compress")
    x = x % Q
    num = x * (1 << d)
    val = (2 * num + Q) // (2 * Q)
    return val % (1 << d)


def decompress(y: int, d: int) -> int:
    """
    Ecuación 4.8: Decompress_d(y)
    Decompress_d: Z_{2^d} -> Z_q
    y |-> round((q / 2^d) * y)
    """
    if not (1 <= d < 12):
        raise ValueError("Masapul a 1 <= d < 12 para iti decompress")
    mod_d = 1 << d
    y = y % mod_d
    val = (2 * y * Q + mod_d) // (2 * mod_d)
    return val % Q


def byte_encode(F: Sequence[int], d: int) -> bytes:
    """
    Algorithm 5: ByteEncode_d(F)
    """
    if len(F) != N:
        raise ValueError(f"Masapul nga addaan iti eksakto a {N} nga integer ti F.")
    if not (1 <= d <= 12):
        raise ValueError("Masapul nga adda ti d iti sakop a 1 <= d <= 12.")

    b = [0] * (N * d)
    for i in range(N):
        a = F[i]
        for j in range(d):
            bit = a % 2
            b[i * d + j] = bit
            a = (a - bit) // 2

    return bits_to_bytes(b)


def byte_decode(B: bytes, d: int) -> List[int]:
    """
    Algorithm 6: ByteDecode_d(B)
    """
    if not (1 <= d <= 12):
        raise ValueError("Masapul nga adda ti d iti sakop a 1 <= d <= 12.")
    expected_len = 32 * d
    if len(B) != expected_len:
        raise ValueError(f"Masapul a {expected_len} bytes ti B para iti d={d}.")

    m = (1 << d) if d < 12 else Q
    b = bytes_to_bits(B)
    F = [0] * N

    for i in range(N):
        val = 0
        for j in range(d):
            val += b[i * d + j] * (1 << j)
        F[i] = val % m

    return F