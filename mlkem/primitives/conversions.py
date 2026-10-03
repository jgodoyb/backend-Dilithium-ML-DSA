from typing import Sequence, List, Union


def bits_to_bytes(b: Sequence[int]) -> bytes:
    """Algorithm 3: BitsToBytes(b)

    Convierte un array de bits (longitud múltiplo de 8) en un array de bytes
    siguiendo orden little-endian.
    """
    total_bits = len(b)
    if total_bits % 8 != 0:
        raise ValueError("La longitud del array de bits debe ser múltiplo de 8.")

    ell = total_bits // 8
    # Paso 1: B <- (0, ..., 0)
    B = bytearray(ell)

    # Paso 2-4: B[|_ i/8 _|] <- B[|_ i/8 _|] + b[i] * 2^(i mod 8)
    for i in range(8 * ell):
        bit = b[i]
        if bit not in (0, 1):
            raise ValueError(f"Valor de bit inválido en el índice {i}: {bit}")
        B[i // 8] += bit * (1 << (i % 8))

    # Paso 5: return B
    return bytes(B)


def bytes_to_bits(B: Union[bytes, bytearray, Sequence[int]]) -> List[int]:
    """Algorithm 4: BytesToBits(B)

    Realiza la inversa de BitsToBytes, convirtiendo bytes en un array de bits.
    """
    # Paso 1: C <- B (copia mutable de los bytes)
    C = list(B)
    ell = len(C)

    # Inicializar array de bits b con longitud 8 * ell
    b = [0] * (8 * ell)

    # Paso 2-7: Extracción de bits en orden little-endian
    for i in range(ell):
        val = C[i]
        for j in range(8):
            b[8 * i + j] = val % 2
            val = val // 2
        C[i] = val

    # Paso 8: return b
    return b