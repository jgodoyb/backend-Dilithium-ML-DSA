import hashlib
from typing import Tuple


class SHAKE128XOF:
    """Implementa el envoltorio XOF incremental para SHAKE128

    especificado en FIPS 203 (Sección 4.1 y Algoritmo 2).
    """

    def __init__(self, data: bytes = b""):
        self.ctx = hashlib.shake_128()
        if data:
            self.ctx.update(data)
        self.offset = 0

    def absorb(self, data: bytes) -> None:
        self.ctx.update(data)

    def squeeze(self, length: int) -> bytes:
        """Exprime 'length' bytes adicionales del flujo de salida."""
        total_needed = self.offset + length
        full_stream = self.ctx.digest(total_needed)
        chunk = full_stream[self.offset : total_needed]
        self.offset = total_needed
        return chunk


def prf(eta: int, s: bytes, b: int) -> bytes:
    """Ecuación 4.3: PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta)"""
    if len(s) != 32:
        raise ValueError("s debe ser de 32 bytes.")
    if not (0 <= b <= 255):
        raise ValueError("b debe ser un byte (0-255).")
    output_len_bytes = 64 * eta
    return hashlib.shake_256(s + bytes([b])).digest(output_len_bytes)


def hash_h(s: bytes) -> bytes:
    """Ecuación 4.4: H(s) = SHA3-256(s)"""
    return hashlib.sha3_256(s).digest()


def hash_j(s: bytes) -> bytes:
    """Ecuación 4.4: J(s) = SHAKE256(s, 8 * 32)"""
    return hashlib.shake_256(s).digest(32)


def hash_g(c: bytes) -> Tuple[bytes, bytes]:
    """Ecuación 4.5: G(c) = SHA3-512(c) dividido en dos bloques de 32 bytes."""
    digest = hashlib.sha3_512(c).digest()
    return digest[:32], digest[32:]