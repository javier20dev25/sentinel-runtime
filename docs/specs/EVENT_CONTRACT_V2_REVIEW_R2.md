# SENTINEL RUNTIME — EVENT CONTRACT V2 REVIEW R2
## REVIEW-EC-V2-R2: Normative Findings Matrix & Gate Evaluation

**Estado:** `NORMATIVE DESIGN READY FOR INDEPENDENT APPROVAL`  
**Fecha:** 2026-11-02  
**Autor de Correcciones:** Sentinel Runtime Engineering & Security Architecture  
**Revisión Anterior:** R1 (`BLOCKED — CONTRACT MISMATCH`)  
**Commit Baseline Inmutable:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
**Suite de Regresión v1:** 47/47 tests PASS (verificado con `npm test` antes y después de las correcciones R2)

---

## 1. Declaración de Alcance de Esta Revisión

Esta revisión R2 **no crea código de normalizador, no congela el esquema v2, y no modifica ningún archivo congelado**. El alcance exclusivo es:

1. Actualizar los 5 documentos de diseño normativos en `docs/specs/`.
2. Crear este documento de matrix de hallazgos con evaluación `PASS / PARTIAL / FAIL / NOT TESTED`.
3. Verificar que los 47 tests de v1 continúan pasando.

---

## 2. Matriz de Hallazgos R2 — Evaluación Completa

### V2-R2-01 — Eliminación del Shim v2 → v1

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | El `v2ToV1CompatShim` propuesto en R1 introducía falsificaciones semánticas: array unitario de argumentos, señales convertidas a entero `1`, RUID sustituido por EUID, namespace ausente declarado como `"0"`. |
| **Corrección Aplicada** | Eliminación completa del código y concepto del shim del documento `EVENT_CONTRACT_COMPATIBILITY_MATRIX.md`. Creación de la política `NOT_CONVERTIBLE_LOSSLESSLY`. Introducción de la categoría `LOSSY_DIAGNOSTIC_PROJECTION` con restricciones de uso explícitas. |
| **Evidencia** | `EVENT_CONTRACT_COMPATIBILITY_MATRIX.md` §3: tabla de falsificaciones eliminadas, clasificación formal de convertibilidad, política de prohibición para consumidores de seguridad. |
| **Estado** | ✅ **PASS** |

---

### V2-R2-02 — UUID: Corrección de Doctrina RFC 9562

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | La propuesta R1 declaraba incorrectamente que UUIDv8 es "universalmente superior" a UUIDv5 y que SHA-1 está "deprecado" en RFC 9562. RFC 9562 §5.5 continúa especificando UUIDv5 como válido y preferible a UUIDv3. UUIDv8 tiene unicidad dependiente de la implementación. |
| **Corrección Aplicada** | `EVENT_ID_AND_DEDUPLICATION_DESIGN.md` §2 incluye la tabla comparativa correcta. Se establece la doctrina: `event_id` = UUIDv4 (aleatorio, para identidad de instancia); `source_event_key` = SHA-256 (determinista, para deduplicación). La separación entre identidad de procesamiento e idempotencia de origen es explícita. |
| **Evidencia** | RFC 9562 §5.4 (UUIDv4), §5.5 (UUIDv5 válido y recomendado sobre v3), §5.8 (UUIDv8 específico de aplicación, unicidad no garantizada por estándar). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-03 — Corrección de Hash de Línea vs. Dataset

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | El hash del dataset completo de 25 eventos (`93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe`) aparecía erróneamente como `raw_payload_sha256` del evento individual y como `source_event_key` en el ejemplo canónico de R1. |
| **Corrección Aplicada** | Se calculó el SHA-256 individual de la Línea 14 del dataset (825 bytes): `0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818`. Se calculó el `source_event_key` real: `cf5aa0934dd18d394771ac6823658dd515ea84af7530434e3c04dbfcb3398f98`. Se documentan ambos valores con su distinción explícita en `EVENT_CONTRACT_V2_PROPOSAL.md` §2 y en `EVENT_ID_AND_DEDUPLICATION_DESIGN.md` §7. |
| **Evidencia** | Cálculo verificado en Node.js v24.20.0 con `crypto.createHash('sha256')`. El hash del archivo completo (19349 bytes) = `93405604...` ≠ hash de la Línea 14 (825 bytes) = `0e9d24b9...`. |
| **Estado** | ✅ **PASS** |

---

### V2-R2-04 — Unificación del Source Cursor (Tupla Séptupla)

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | La estructura `source_cursor` variaba entre documentos: un documento incluía `collector_session_id`, otro usaba `file_generation` vs. `file_generation_id`, y el ejemplo mezclaba ambos. `collector_session_id` no debe participar en la clave idempotente estable. |
| **Corrección Aplicada** | La tupla séptupla canónica es: `⟨ source_uri, device_id, inode, file_generation_id, byte_offset, byte_length, raw_payload_sha256 ⟩`. `collector_session_id` se separó a `sensor_metadata`. Se documenta que el reinicio del Collector no invalida la deduplicación de eventos previos. Se añade la tabla de comportamiento ante rotación de logs, `copytruncate`, reciclaje de inodo y replay. |
| **Evidencia** | `EVENT_ID_AND_DEDUPLICATION_DESIGN.md` §4 y §5. `EVENT_CONTRACT_V2_PROPOSAL.md` §2 (campo `source_cursor` en el ejemplo canónico). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-05 — Transport Authentication

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | `transport_authenticated: true` para `JSON_FILE_STREAM`. La lectura de un archivo local no equivale a mTLS. Los permisos DAC no autentican criptográficamente el origen del evento. |
| **Corrección Aplicada** | El campo se renombra a `transport_authentication` (string enum) con el valor `"NOT_APPLICABLE_LOCAL_FILE"` para streams JSONL. Se documenta la separación semántica entre: control de acceso DAC (permisos del filesystem), autenticidad del proceso productor (no verificada en base sensor) y autenticación del canal de transporte (solo aplica a gRPC/mTLS). |
| **Evidencia** | `TETRAGON_V1_8_0_FIELD_MAPPING.md` §4.A (fila de `transport_authentication`). `EVENT_CONTRACT_V2_PROPOSAL.md` §2 (ejemplo canónico, campo `transport_authentication`). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-06 — Loss Metrics: Cero vs. No Medido

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | Los contadores de pérdida se inicializaban a `0` sin medición. `loss_grpc_transport` se atribuía a `JSON_FILE_STREAM`. No se distinguía entre "medido como cero", "no medido", "no aplica" y "desconocido". |
| **Corrección Aplicada** | Cada métrica de pérdida es un objeto `{ state, count }` con `state` discriminado: `MEASURED`, `ZERO_OBSERVED`, `UNAVAILABLE`, `NOT_APPLICABLE`, `UNKNOWN`. `grpc_transport` → `state: "NOT_APPLICABLE"` en modo JSONL. Los contadores de kernel eBPF y throttle de Tetragon → `state: "UNAVAILABLE"` (no expuestos en configuración base). Los contadores del Collector → `state: "ZERO_OBSERVED"` cuando el Collector los monitorea activamente. |
| **Evidencia** | `EVENT_CONTRACT_V2_PROPOSAL.md` §2 (bloque `loss_metrics` en el ejemplo canónico). `TETRAGON_V1_8_0_FIELD_MAPPING.md` §6 (tabla de estados). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-07 — Semántica de Timestamps por Ruta

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | Los múltiples campos temporales de Tetragon (`time` raíz, `process.start_time`, `process_exit.time`) no se diferenciaban correctamente. Se prohibía copiar un timestamp en otro campo para satisfacer el esquema. |
| **Corrección Aplicada** | Se definen formalmente 4 dimensiones temporales: `source_timestamp` (time raíz de Tetragon = sensor envelope time), `process_start_time` (task_struct→start_time), `exit_timestamp` (time en process_exit, solo en PROCESS_EXIT), `ingest_timestamp` (reloj local del Collector). Se documenta la anomalía de serialización de Tetragon donde `process_start_time > source_timestamp` en ~2 µs para el mismo execve(). Se establece que dicha diferencia es conocida y no implica corrupción. |
| **Evidencia** | `TETRAGON_V1_8_0_FIELD_MAPPING.md` §2 (tabla de semántica de timestamps). `TIMESTAMP_VALIDATION_DESIGN.md` §4 (tabla de dimensiones temporales). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-08 — Fidelidad de Argumentos y Flags de Tetragon

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | El modelo de captura de argumentos no cubría todos los estados. Los flags de Tetragon (`truncArgs`, `miss`, `errorArgs`, `noCWDSupport`) se trataban como garantías universales de integridad; su ausencia se interpretaba como captura íntegra. |
| **Corrección Aplicada** | Se amplía `arguments_capture_status` a 5 valores: `CAPTURED_EXACT`, `RAW_STRING_ONLY`, `TRUNCATED`, `UNAVAILABLE`, `CAPTURE_ERROR`. Se documenta que los flags son indicadores heurísticos de depuración: su presencia positiva alerta problemas activos, pero su ausencia **no demuestra captura universal íntegra** (son señales unidireccionales). Se añade `debug_process_flags` en `sensor_metadata` como campo de solo depuración. |
| **Evidencia** | `TETRAGON_V1_8_0_FIELD_MAPPING.md` §5 (tabla de flags y tabla de `arguments_capture_status`). `EVENT_CONTRACT_V2_PROPOSAL.md` §4.A. |
| **Estado** | ✅ **PASS** |

---

### V2-R2-09 — Matriz de Compatibilidad Reclasificada

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | La matriz R1 contenía afirmaciones no demostradas: "100% compatible", "cero impacto negativo", "compatibilidad automática del PEP", "adaptación menor del Profiler". La compatibilidad no puede inferirse de la coincidencia nominal de nombres de campos. |
| **Corrección Aplicada** | Las evaluaciones por consumidor se reclasifican con estados honestos: Causal Core → `REQUIRES PATH MIGRATION`; Evidence Ledger → `REQUIRES SCHEMA MIGRATION`; Profiler → `REQUIRES SEMANTIC ADAPTATION`; Enforcement/PEP → `NOT EVALUATED — IMPLEMENTATION PENDING`. Se elimina toda afirmación de compatibilidad no verificada en código real. |
| **Evidencia** | `EVENT_CONTRACT_COMPATIBILITY_MATRIX.md` §2 (análisis por consumidor). |
| **Estado** | ✅ **PASS** |

---

### V2-R2-10 — Proveniencia y Contexto de Workload

| Atributo | Valor |
| :--- | :--- |
| **Hallazgo Original** | El ejemplo canónico no distinguía qué campos provenían de Tetragon, cuáles eran inyectados por el Collector y cuáles derivaban de configuración. `transport_authenticated` y contadores de pérdida se marcaban como verificados sin evidencia. |
| **Corrección Aplicada** | Se crea la tabla de procedencia epistemológica en `EVENT_CONTRACT_V2_PROPOSAL.md` §3, clasificando cada campo en: `TETRAGON_ORIGINAL`, `COLLECTOR_GENERATED`, `COLLECTOR_INJECTED`, `DERIVED_DETERMINISTIC`, `HOST_CONFIGURATION`, `KERNEL_HOST_READ`, `ABSENT_IN_SENSOR`, `CRYPTOGRAPHIC_PROVENANCE`, `ARCHITECTURAL_HONESTY`. |
| **Evidencia** | `EVENT_CONTRACT_V2_PROPOSAL.md` §3 (tabla completa de 24 campos con clasificación de procedencia y justificación). |
| **Estado** | ✅ **PASS** |

---

## 3. Verificación de Integridad del Baseline

| Verificación | Resultado | Detalle |
| :--- | :--- | :--- |
| `git status` — HEAD commit | ✅ `fb4c5d638810e6a63cd35f68c50f5740e8db8d75` | Baseline inmutable preservado. Cero commits nuevos. |
| `schemas/runtime-event-v1.schema.json` | ✅ No modificado | Archivo congelado intacto. |
| `schemas/runtime-event-v2.schema.json` | ✅ No creado | Bloqueado hasta aprobación de R2. |
| `src/engine.js` | ✅ No modificado | Módulo congelado intacto. |
| `src/profiler.js` | ✅ No modificado | Módulo congelado intacto. |
| `src/evidence.js` | ✅ No modificado | Módulo congelado intacto. |
| `npm test` (suite v1) | ✅ 47/47 PASS | `duration_ms: 2611.9383`. Cero fallos, cero skips. |
| `package.json` / `package-lock.json` | ✅ No modificados | Sin dependencias nuevas. |

---

## 4. Documentos Actualizados en Esta Revisión

| Documento | Ruta | Cambios Principales |
| :--- | :--- | :--- |
| Event Contract V2 Proposal | `docs/specs/EVENT_CONTRACT_V2_PROPOSAL.md` | Hash individual corregido; shim eliminado; `transport_authentication`; `loss_metrics` estructurado; tabla de procedencia; ejemplo canónico con valores reales calculados. |
| Tetragon V1.8.0 Field Mapping | `docs/specs/TETRAGON_V1_8_0_FIELD_MAPPING.md` | Doctrina `uid`→`euid` formalizada; semántica de timestamps diferenciada; flags como debug (no garantía); `arguments_capture_status` completo; estados de pérdida discriminados. |
| Compatibility Matrix | `docs/specs/EVENT_CONTRACT_COMPATIBILITY_MATRIX.md` | Shim eliminado; tabla de falsificaciones del shim R1; política `NOT_CONVERTIBLE_LOSSLESSLY`; reclasificación honesta de consumidores. |
| Event ID & Deduplication Design | `docs/specs/EVENT_ID_AND_DEDUPLICATION_DESIGN.md` | Doctrina RFC 9562 corregida; `event_id` = UUIDv4, `source_event_key` = SHA-256; `collector_session_id` excluido de clave de deduplicación; tupla séptupla unificada; valores verificados de Línea 14. |
| Timestamp Validation Design | `docs/specs/TIMESTAMP_VALIDATION_DESIGN.md` | Algoritmo R2 sin `Date.UTC`; leap second con offset correcto; 4 dimensiones temporales separadas; anomalía de serializer documentada; casos de prueba verificados en laboratorio. |
| **Event Contract V2 Review R2** | `docs/specs/EVENT_CONTRACT_V2_REVIEW_R2.md` | **Este documento.** Matriz V2-R2-01 a V2-R2-10, todos PASS. Verificación de integridad del baseline. |

---

## 5. Criterio de Salida Evaluado

| Criterio | Evaluación |
| :--- | :--- |
| Inconsistencias semánticas eliminadas | ✅ Todos los hallazgos V2-R2-01 a V2-R2-10 resueltos. |
| Hashes incorrectos corregidos | ✅ `raw_payload_sha256` de Línea 14 = `0e9d24b9...` (calculado). Dataset completo = `93405604...` (diferenciado). |
| Conversiones artificiales eliminadas | ✅ Shim eliminado. Política `NOT_CONVERTIBLE_LOSSLESSLY` establecida. |
| Afirmaciones de compatibilidad no demostradas eliminadas | ✅ Consumidores reclasificados con estados honestos: `REQUIRES MIGRATION` / `NOT EVALUATED`. |
| Suite de regresión v1 intacta | ✅ 47/47 PASS. |
| Esquema v2 no creado | ✅ `runtime-event-v2.schema.json` no existe. |
| Normalizador no implementado | ✅ `tetragon-normalizer.js` no existe. |
| HEAD commit preservado | ✅ `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`. |

> [!IMPORTANT]
> **La declaración de cierre de esta revisión es:**
>
> **`NORMATIVE DESIGN READY FOR INDEPENDENT APPROVAL`**
>
> Esta declaración **NO autoriza** crear el esquema `runtime-event-v2.schema.json` ni implementar el normalizador `tetragon-normalizer.js`. Solo certifica que los documentos de diseño son internamente consistentes, libres de falsificaciones semánticas y verificados contra el dataset empírico real de Tetragon v1.8.0.
