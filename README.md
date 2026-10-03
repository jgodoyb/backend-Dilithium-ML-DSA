# Q-Proof Cryptographic Core (ML-DSA / FIPS 204)

Este repositorio contiene la implementación e integración de **Q-Proof Core**, una API de firma digital de documentos y verificación basada en criptografía **Post-Cuántica**. 

El sistema implementa de forma nativa desde cero el estándar **ML-DSA (FIPS 204)**, garantizando que las firmas digitales producidas sean resistentes a ataques mediante ordenadores cuánticos (utilizando criptografía basada en retículos estructurados).

---

## Características Principales

*   **Algoritmo Post-Cuántico Nativo:** Implementación completa y modular en Python del estándar **FIPS 204 (ML-DSA)**, soportando niveles de seguridad estándar como **ML-DSA-65**.
*   **Variantes Pura y Pre-Hash:**
    *   **ML-DSA Puro:** Firma directa del mensaje o documento con separación de dominios mediante contexto.
    *   **HashML-DSA:** Variante Pre-Hash compatible con funciones de resumen como **SHA-256**, **SHA-512** y **SHAKE128** (256 bits).
*   **Separación de Dominios (Contexto):** Validación estricta del parámetro opcional `ctx` (límite de 255 bytes) para prevenir ataques de colisión de firmas entre diferentes aplicaciones.
*   **API Backend Moderna:** Desarrollada con **FastAPI** para una integración web ágil, segura y asíncrona.
*   **Integración Segura con Supabase:** 
    *   Las identidades criptográficas (clave pública y clave privada cifrada) se almacenan en la nube utilizando **Supabase**.
    *   Seguridad basada en **RLS (Row Level Security)**: el backend inyecta dinámicamente el token JWT del usuario autenticado en el cliente de Supabase para asegurar que un usuario solo pueda leer o escribir sus propias claves.
*   **Mitigación de Abuso:** Límite de peticiones (Rate limiting) integrado a nivel de endpoint mediante **SlowAPI** para prevenir ataques de denegación de servicio (DoS) en operaciones criptográficas pesadas.

---

## Arquitectura de Seguridad y Flujo de Datos

1.  **Generación de Claves (`/api/generate`):**
    *   Se genera un par de claves ML-DSA localmente en el servidor.
    *   La clave pública y privada se codifican en Base64 y se guardan directamente en la tabla `crypto_identities` de Supabase bajo el contexto del JWT del usuario.
2.  **Firma de Documentos (`/api/sign`):**
    *   El usuario sube el documento PDF.
    *   El servidor recupera la clave privada de Supabase de forma segura (validando el JWT del usuario contra la base de datos).
    *   La clave privada nunca se expone al cliente web.
    *   Se genera la firma digital utilizando la variante Pre-Hash y se devuelve codificada en Base64.
3.  **Verificación Pública (`/api/verify`):**
    *   Cualquier tercero puede verificar la autenticidad del documento sin necesidad de estar autenticado.
    *   Se envía el PDF original, la firma digital (`.sig`) y la clave pública en Base64 del autor.
    *   El servidor realiza la verificación localmente de manera limpia y devuelve un valor booleano (`is_valid`).

---

## Estructura del Proyecto

*   `api/`:
    *   `main.py`: Servidor FastAPI con los endpoints de generación, firma y verificación.
*   `mldsa/`:
    *   `mldsa.py`: Punto de entrada del módulo criptográfico (expone `keygen`, `sign`, `verify`, `hash_sign`, `hash_verify`).
    *   `constants.py`: Constantes globales del estándar (Q = 8380417, N = 256).
    *   `parameters/`: Definición y registro de parámetros estándar (ML-DSA-44, 65, 87) según FIPS 204.
    *   `core/`, `crypto/`, `decomposition/`, `encoding/`, `ntt/`, `sampling/`, `primitives/`: Módulos matemáticos internos (aritmética polinomial, Transformación Teórica de Números - NTT, empaquetado de bits y muestreo).
    *   `arbol_dependencias_mldsa.md`: Documentación detallada del orden matemático y dependencias de la biblioteca criptográfica.
*   `tests/`: Suite completa de pruebas unitarias dividida por componentes matemáticos, criptográficos y de integración (`test_api.py`).
*   `requirements.txt`: Dependencias de librerías Python necesarias.

---

## Instalación y Configuración

### 1. Requisitos Previos

Asegúrese de tener instalado **Python 3.10** o superior en su sistema.

### 2. Clonar e Instalar Dependencias

Clona este repositorio, crea un entorno virtual e instala los paquetes requeridos:

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Windows:
.\venv\Scripts\activate
# En macOS/Linux:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### 3. Variables de Entorno (`.env`)

El backend requiere credenciales válidas de Supabase. A partir del archivo de plantilla `.env.example`, configure las siguientes variables:

1.  Copia `.env.example` y renómbralo a `.env`.
2.  Configura las siguientes variables:
    *   `ENVIRONMENT`: `development` o `production` (use `test` para pruebas locales).
    *   `FRONTEND_URL`: URL(s) permitidas para CORS (ej: `http://localhost:8080`).
    *   `SUPABASE_URL`: Endpoint de su proyecto en Supabase.
    *   `SUPABASE_KEY`: Clave pública anónima (`anon` key) de Supabase.
    *   `SUPABASE_JWKS_URL`: URL del endpoint JWKS de su proyecto de Supabase (usado para verificar las firmas de los tokens JWT de forma local, ej. `https://<tu-id>.supabase.co/auth/v1/.well-known/jwks.json`).

*(Nota: El archivo `.env` está ignorado en Git para evitar la filtración de credenciales reales).*

### 4. Ejecución del Servidor

Para iniciar la API localmente en modo desarrollo con recarga automática:

```bash
python api/main.py
```

La API estará disponible en `http://127.0.0.1:8000` y la documentación interactiva podrá visualizarse en `http://127.0.0.1:8000/docs`.

---

## Pruebas Unitarias y de Integración

El repositorio cuenta con pruebas que cubren tanto los fundamentos matemáticos de ML-DSA como el comportamiento de la API.

### Ejecutar pruebas criptográficas (unitarias)

```bash
python -m unittest discover -s tests -p "*.py"
```

### Ejecutar pruebas de la API (flujo completo mockeado)

```bash
python -m api.test_api
```

---

## Licencia

Este proyecto está diseñado con fines de investigación académica y estudio de la criptografía post-cuántica aplicable.
