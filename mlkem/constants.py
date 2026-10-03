"""
Konstante ti pagalagadan a FIPS 203 (ML-KEM).
"""

# Kangrunaan a constante ti ring R_q
N: int = 256  # Grado ti polinomial (Section 2.3)
Q: int = 3329  # Modulo a numero a prime: 2^8 * 13 + 1 (Section 2.3)

# Ramut ti unity para iti NTT
ZETA: int = 17  # Primitive 256-th root of unity modulo q (Section 2.3)