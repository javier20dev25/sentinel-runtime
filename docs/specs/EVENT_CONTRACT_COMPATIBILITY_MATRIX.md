# SENTINEL RUNTIME — EVENT CONTRACT COMPATIBILITY MATRIX
## MATRIX-COMPAT-V1-V2r2.3: Compatibility Analysis v1 vs. v2 (Revision R2.3)

**Estado:** `NORMATIVE AUDIT SPECIFICATION (R2.3)`  
**Fecha:** 2026-11-02  
**Baseline Evaluado:** `schemas/runtime-event-v1.schema.json`  
- **Estado de Versión:** Archivo local congelado (untracked en árbol de trabajo, preservado de commits para garantizar inmutabilidad normativa).
- **Ancla de Git:** Commit base `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`
- **Hash SHA-256 Acreditado:** `8c58cd9661eb3e192d89a3480572486fd96fe24f5bdb3219e3053a807515cfe9`
- **Dimensiones:** 19,586 bytes, 652 líneas.
**Propuesta Evaluada:** `docs/specs/EVENT_CONTRACT_V2_PROPOSAL.md` (Revision R2.3)  
**Autor:** Sentinel Runtime Engineering & Security Architecture

> [!IMPORTANT]
> **Esta revisión ratifica la eliminación permanente del Shim v2 → v1.** Cualquier intento de sintetizar campos mediante heurísticas en el pipeline de ingestión introduce falsificaciones semánticas inaceptables. Ver §3 para las reglas de confinamiento de tokenización heurística.

---

## 1. Matriz Comparativa Campo a Campo (v1 vs. v2)

| Campo Canónico | Estado en Contract v1 | Definición en Contract v2 (R2.3) | Tipo de Cambio | Clasificación de Compatibilidad |
| :--- | :--- | :--- | :--- | :--- |
| `schema_version` | `"1.0.0"` | `"2.0.0"` | Breaking | **BREAKING / MAJOR DISCRIMINATOR** |
| `event_id` | UUIDv4 obligatorio | UUIDv4 obligatorio | Compatible | **BACKWARD COMPATIBLE** |
| `source_event_key` | No existía | SHA-256 obligatorio en raíz (length-prefixed) | Aditivo | **ADDITIVE** |
| `event_type` | Enum de 14 tipos | Enum de 14 tipos | Compatible | **BACKWARD COMPATIBLE** |
| `timestamps.source_timestamp` | `uint64` en raíz plana | `uint64` en objeto `timestamps` | Reestructuración | **BREAKING (relocalización)** |
| `host_identity` | `host_id`, `boot_id` en raíz | Agrupados en objeto `host_identity` | Reestructuración | **BREAKING (relocalización)** |
| `process_identity.exec_id` | String Base64 | String Base64 | Compatible | **BACKWARD COMPATIBLE** |
| `process_identity.parent_exec_id` | String Base64 o null | String Base64 o null | Compatible | **BACKWARD COMPATIBLE** |
| `process_identity.euid` | Integer requerido | Integer requerido (semántica clarificada) | Compatible | **BACKWARD COMPATIBLE** |
| `process_identity.ruid` (`uid` en v1) | Integer requerido | Integer \| null (nullable) | Breaking | **BREAKING (nullable)** |
| `process_namespaces` | `pid_ns`, `mnt_ns`, `net_ns` obligatorios | Objeto con `capture_status` y nulls | Breaking | **BREAKING (nullability + restructure)** |
| `PROCESS_EXEC.payload.arguments` | Array de strings obligatorio | **Eliminado; sustituido por `arguments_raw` + `argv` + `arguments_capture_status`** | Breaking | **BREAKING / CONTRACT MISMATCH** |
| `PROCESS_EXIT.payload.exit_code` | Integer obligatorio | **Eliminado; sustituido por `termination.exit_status`** | Breaking | **BREAKING / CONTRACT MISMATCH** |
| `PROCESS_EXIT.payload.signal` | Integer \| null | **Eliminado; sustituido por `termination.signal_name` (string)** | Breaking | **BREAKING / CONTRACT MISMATCH** |
| `loss_metrics.*` | Enteros a `0` | Objetos `{ state, count }` discriminados | Breaking | **BREAKING (restructure + semantics)** |
| `sensor_metadata.transport_authenticated` | Boolean | `transport_authentication` (string enum) | Breaking | **BREAKING (type + semantics)** |

---

## 2. Análisis de Impacto por Consumidor de Sentinel Runtime

### A. Causal Core (Motor de Grafo DAG)

- **Consumo Primario:** `process_identity.exec_id` (nodos) y `process_identity.parent_exec_id` (aristas dirigidas).
- **Campos Críticos Afectados:** `exec_id`, `parent_exec_id`, `timestamps.source_timestamp`.
- **Evaluación:** `IMPACTO PENDIENTE DE EVALUACIÓN`
  - Los identificadores `exec_id` y `parent_exec_id` son cadenas Base64 opacas idénticas en ambas versiones — la lógica de construcción del grafo no cambia.
  - La relocalización de `timestamps.source_timestamp` a `event.timestamps.source_timestamp` requiere actualizar las rutas de acceso en el Causal Core.
  - La incorporación de `termination.kind` provee semántica de terminación más precisa (`"SIGNALED"` vs. `"EXITED"` vs. `"AMBIGUOUS"`), clarificando el cierre de nodos.
  - **Estado:** `REQUIRES PATH MIGRATION` (congelado hasta desbloqueo normativo).

### B. Evidence Ledger (Integridad Forense Criptográfica)

- **Consumo Primario:** Hashes de eventos, timestamps, firmas de procedencia.
- **Evaluación:** `MIGRACIÓN NECESARIA`
  - En v1, el hash del payload dependía de un array sintético que desvirtuaba la evidencia del sensor.
  - En v2, `raw_payload_sha256` y `arguments_raw` preservan la secuencia de bytes exacta observada en el kernel.
  - `source_cursor` incorpora `inode`, `byte_offset`, `payload_byte_length`, `delimiter_byte_length` y `file_generation_id` para atestar la posición física en el archivo de log.
  - `source_event_key` (SHA-256 determinista con codificación length-prefixed) provee deduplicación idempotente independiente del `event_id` aleatorio.
  - El Evidence Ledger debe migrar su índice primario para operar sobre `source_event_key`.
  - **Estado:** `REQUIRES SCHEMA MIGRATION` (congelado hasta desbloqueo normativo).

### C. Profiler & Anomaly Detector (Detección de Desviaciones)

- **Consumo Primario:** Patrones de líneas de comandos, binarios ejecutados, códigos de retorno.
- **Evaluación:** `ADAPTACIÓN SEMÁNTICA CON BARRERAS DEFENSIVAS`
  - El Profiler en v1 consumía `payload.arguments` como array de strings. En v2 solo existe `arguments_raw` (string).
  - Si el Profiler realiza tokenización defensiva local mediante un parser POSIX `shlex` o expresiones regulares, los tokens resultantes quedan sujetos a las siguientes **reglas obligatorias**:
    1. **Clasificación Estricta:** Los tokens generados se clasifican internamente como **`DERIVED_HEURISTIC`**.
    2. **Prohibición de Promoción a `argv[]`:** Los tokens `DERIVED_HEURISTIC` **jamás** se asignan al campo `payload.argv`, el cual permanece estrictamente en `null` salvo que provenga de un sensor con captura real de vector de kernel.
    3. **Inmutabilidad de `arguments_raw`:** Los tokens no sustituyen ni mutan el campo `arguments_raw`.
    4. **Prohibición en Evidence Ledger:** Los tokens heurísticos **no pueden** registrarse en el Evidence Ledger como evidencia atestada de kernel.
    5. **Prohibición de Bloqueo Autónomo en PEP:** Ninguna política de contención de bloqueo o terminación de procesos puede fundamentarse exclusivamente en tokens `DERIVED_HEURISTIC`.
    6. **Cotas de Longitud y DoS:** El tokenizador debe imponer cotas estrictas (máximo 131,072 caracteres de entrada y máximo 1,024 tokens) para evitar ataques de denegación de servicio por expresiones regulares patológicas (ReDoS) o secuencias de escape no cerradas.
  - `arguments_capture_status = "TRUNCATED"` o `"UNAVAILABLE_PARENT_MISS"` debe inhibir la inferencia de perfiles sobre la línea de comandos.
  - **Estado:** `REQUIRES SEMANTIC ADAPTATION` (congelado hasta desbloqueo normativo).

### D. Enforcement & PEP (Policy Enforcement Point)

- **Consumo Primario:** `workload_context.cgroup_path` y `process_identity.pid` para contención.
- **Evaluación:** `NO EVALUABLE (CONTINÚA SIN IMPLEMENTAR)`
  - El módulo de enforcement no existe en producción. No se puede evaluar compatibilidad sobre código inexistente.
  - Los campos de contención (`cgroup_path`, `pid`) preservan su semántica; su nulabilidad declarada previene fallos silenciosos ante ausencia de datos.
  - **Estado:** `NOT EVALUATED — IMPLEMENTATION PENDING`

---

## 3. Política de Inconvertibilidad y Sustitución del Shim R1

### 3.1 Eliminación Definitiva del Shim
El mecanismo `v2ToV1CompatShim` propuesto en R1 fue eliminado definitivamente debido a las siguientes falsificaciones de evidencia identificadas:

| Conversión del Shim R1 | Falsificación Producida | Veredicto |
| :--- | :--- | :--- |
| `arguments: v2Event.payload.argv ?? [v2Event.payload.arguments_raw]` | Convierte una cadena continua en un array unitario que no representa el `argv[]` del kernel. | **FALSIFICACIÓN DE EVIDENCIA — ELIMINADO** |
| `exit_code: v2Event.payload.termination.exit_status ?? 0` | Asigna `exit_code = 0` a procesos terminados por señal (`SIGKILL`) cuyo estado real no existe. | **FALSIFICACIÓN DE EVIDENCIA — ELIMINADO** |
| `signal: v2Event.payload.termination.signal_name ? 1 : null` | Convierte `"SIGKILL"` en el entero `1`, que no corresponde a ninguna convención POSIX estándar. | **FALSIFICACIÓN DE EVIDENCIA — ELIMINADO** |
| `uid: v2Event.process_identity.ruid ?? v2Event.process_identity.euid` | Sustituye un RUID desconocido por el EUID. Dos UIDs distintos se confunden bajo binarios `setuid`. | **FALSIFICACIÓN DE IDENTIDAD — ELIMINADO** |
| `pid_ns: ... ?? "0"` | Sustituye un namespace ausente por el string `"0"`, que no corresponde al namespace real del kernel. | **FABRICACIÓN DE IDENTIFICADOR — ELIMINADO** |

### 3.2 Clasificación Formal de Convertibilidad

| Categoría | Criterio | Uso Permitido |
| :--- | :--- | :--- |
| `COMPATIBLE_LOSSLESSLY` | Todos los campos se mapean 1:1 sin ninguna transformación, inferencia ni valor sintético. | Enforcement, evidencia forense, auditoría judicial. |
| `NOT_CONVERTIBLE_LOSSLESSLY` | Uno o más campos requieren transformación, inferencia o valor sintético para satisfacer el esquema de destino. | **Prohibido para cualquier consumidor de seguridad.** |
| `LOSSY_DIAGNOSTIC_PROJECTION` | Conversión con pérdidas explícitamente declarada, marcada con `projection_mode: "LOSSY_UNVERIFIED"` y lista de `synthetic_fields`. | Exclusivo para dashboards o consolas de operador. Prohibido para PEP, Evidence Ledger y Profiler de producción. |

### 3.3 Clasificación de Eventos por Convertibilidad

| Tipo de Evento | Campo Problemático | Clasificación |
| :--- | :--- | :--- |
| `PROCESS_EXEC` con `arguments_capture_status = "RAW_STRING_ONLY"` | `payload.arguments` (array) no existe en v2 | `NOT_CONVERTIBLE_LOSSLESSLY` |
| `PROCESS_EXIT` con `kind = "SIGNALED"` | `exit_code` no tiene equivalente semántico | `NOT_CONVERTIBLE_LOSSLESSLY` |
| `PROCESS_EXIT` con `kind = "AMBIGUOUS"` | Datos contradictorios en sensor (`signal` + `status > 0`) | `NOT_CONVERTIBLE_LOSSLESSLY` |
| `PROCESS_EXIT` con `status_origin = "PROTO3_SCALAR_ZERO_INFERRED"` | `exit_code = 0` inferido mediante las 5 condiciones del exportador, no medido explícitamente | `NOT_CONVERTIBLE_LOSSLESSLY` (valor real no atestado por el sensor) |
| `PROCESS_EXIT` con `kind = "EXITED"` y `status_origin = "EXPLICIT_NONZERO"` | Conversión directa de `exit_status` a `exit_code` posible | `COMPATIBLE_LOSSLESSLY` (exclusivo para el campo `exit_code`) |

---

## 4. Invariantes Globales del Sistema

1. **v1 permanece estrictamente congelado:** `schemas/runtime-event-v1.schema.json` (SHA-256 `8c58cd9661eb3e192d89a3480572486fd96fe24f5bdb3219e3053a807515cfe9`) es inmutable. Ningún cambio de v2 puede alterar su estructura, sus validaciones ni su baseline.
2. **Cero regresiones en la suite v1:** Los 47 tests unitarios y de integración de v1 deben continuar pasando con 100% de éxito de forma incondicional.
3. **Aislamiento absoluto de suites:** Las futuras suites de validación de v2 operarán sobre fixtures y esquemas v2 aislados, sin alterar ni compartir los fixtures normativos de v1.
4. **Prohibición de shims sintéticos en producción:** Ningún componente de ingestión o normalización en producción ejecutará conversiones con pérdidas.
