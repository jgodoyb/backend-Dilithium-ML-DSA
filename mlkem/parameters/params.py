from dataclasses import dataclass


@dataclass(frozen=True)
class MLKEMParameters:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    @property
    def ek_pke_len(self) -> int:
        return 384 * self.k + 32

    @property
    def dk_pke_len(self) -> int:
        return 384 * self.k

    @property
    def c_len(self) -> int:
        return 32 * (self.du * self.k + self.dv)


# Conjuntos de parámetros aprobados por el FIPS 203 (Tabla 2)
ML_KEM_512 = MLKEMParameters(name="ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4)
ML_KEM_768 = MLKEMParameters(name="ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4)
ML_KEM_1024 = MLKEMParameters(name="ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5)