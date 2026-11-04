# SENTINEL RUNTIME — IMPLEMENTATION REPORT 001A-R2
## Event Contract Security Hardening

**Rol:** Independent Software Security Engineer / Implementer  
**Fase:** Implementation Phase 001A-R2 — Security Hardening  
**Fecha:** 2026-11-02  
**Baseline Git:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
**Rama:** `feature/runtime-event-contract-v1`  
**Veredicto:** **PASS CONDICIONADO** (Requisitos 001A-R2 cerrados; límites globales y autenticación diferidos a 001B)

---

## 1. Resumen Ejecutivo y Alcance

En cumplimiento de las instrucciones de la revisión adversaria `001A-R1` y los términos de autorización de `Implementation Phase 001A-R2`, se aplicó un endurecimiento de seguridad sobre el esquema JSON ([`schemas/runtime-event-v1.schema.json`](file:///C:/Users/sleyt/sentinel-runtime/schemas/runtime-event-v1.schema.json)), las utilidades de tipos ([`src/contracts/event-types.js`](file:///C:/Users/sleyt/sentinel-runtime/src/contracts/event-types.js)), el validador estricto ([`src/contracts/validate-event.js`](file:///C:/Users/sleyt/sentinel-runtime/src/contracts/validate-event.js)) y el arnés de pruebas ([`test/contracts/event-contract.test.js`](file:///C:/Users/sleyt/sentinel-runtime/test/contracts/event-contract.test.js)).

Todas las correcciones respetaron estrictamente las restricciones innegociables:
- **0 commits realizados** en Git (HEAD inmutable en `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`).
- **0 modificaciones** a otros repositorios del ecosistema (`sentinel-cloud`, `sentinel-cli`, `sentinel-oracle`, `sentinel-audit`).
- **0 modificaciones** a los módulos históricos de Sentinel Runtime (`src/engine.js`, `src/profiler.js`, `src/evidence.js`).
- **0 dependencias nuevas** agregadas (`ajv@^8.20.0` única dependencia externa).
- **0 fixtures eliminados o sobrescritos** (42 fixtures en `test/fixtures/events/v1/` conservados y evaluados al 100%).
- **Fase 001B (Normalizador Tetragon) y Causal Core permanecen bloqueados**.

---

## 2. Matriz de Trazabilidad y Estado Definitivo de Hallazgos (H-01 a H-08)

Esta matriz preserva de forma estricta la identificación y numeración original de la auditoría `001A-R1`:

| Identificador Original R1 | Clasificación | Componente Afectado | Descripción del Problema | Tratamiento en 001A-R2 | Estado Definitivo |
|---|:---:|---|---|---|:---:|
| **H-01** (uint64 overflow) | MEDIUM | `validate-event.js`, `event-types.js` | Desbordamiento numérico: aceptación de valores mayores a $2^{64}-1$ (ej. `18446744073709551616`). | Verificación algorítmica con `BigInt` contra $2^{64}-1$ (`18446744073709551615n`) y rechazo estricto. | **FIXED** |
| **H-02** (ceros iniciales) | LOW | `runtime-event-v1.schema.json`, `event-types.js` | Ceros iniciales no canónicos (`"007"`, `"0123"`) y `Number` mayores a $2^{53}-1$. | Regex canónica decimal `^(0\|[1-9][0-9]{0,19})$`. Solo se admiten strings decimales canónicos o números seguros ($\le 2^{53}-1$). `"0"` es el único cero válido. | **FIXED** |
| **H-03** (claves duplicadas) | ARCHITECTURAL LIMITATION | Capa de ingestión wire / Parser JSON | `validateEvent` opera sobre objetos JS post-parseo. `JSON.parse` de V8 colapsa claves duplicadas reteniendo la última sin error; los revivers operan post-parse. | Requiere un tokenizador/parser en la frontera de transporte wire que rechace duplicados en texto JSON antes de construir el objeto JS (RFC 8785). No aplica a gRPC Protobuf. Diferido a la frontera de red. | **DEFERRED TO 001B** |
| **H-04** (NUL byte en rutas) | HIGH | `runtime-event-v1.schema.json` | Inyección de byte NUL (`\0` / `U+0000`) en rutas permitía truncamiento y evasión en syscalls nativas en C. | Creación de `$defs/linuxPath` con regex `^[^\u0000]+$`. Preserva caracteres válidos POSIX (`\n`, `\t`, espacios) y rechaza el terminador C. | **FIXED** |
| **H-05** (memoria y DoS) | MEDIUM | `runtime-event-v1.schema.json` | Strings y arrays sin cotas permitían agotar el heap. | Restricciones de campo individuales implementadas (`maxLength: 4096` puntos de código, `maxLength: 131072`, `maxItems: 1024`, cotas k8s). El presupuesto global de bytes en wire stream queda diferido. | **PARTIALLY MITIGATED** |
| **H-06** (inconsistencia host) | LOW | `runtime-event-v1.schema.json` | `workload_type: "HOST_PROCESS"` admitía `container_id` no nulo. | Regla condicional `allOf` (`if-then`): si `workload_type === "HOST_PROCESS"`, exige obligatoriamente `container_id: null`. | **FIXED** |
| **H-07** (autenticidad probatoria) | ARCHITECTURAL LIMITATION | `validate-event.js`, arquitectura | Conformidad de esquema vs. autenticidad de telemetría de kernel. El validador certifica sintaxis, no atestación criptográfica del emisor. | La advertencia estructurada ante eventos sintéticos no sustituye la autenticación del canal. Los permisos DAC de un socket UNIX no equivalen a atestación criptográfica frente a root (A3). | **DOCUMENTED LIMITATION / DEFERRED TO TRANSPORT AUTHENTICATION** |
| **H-08** (warnings omitidos) | LOW | `validate-event.js` | Omisión de advertencias ante fuentes no calibradas (`unknown_source`, `other_provider`, `transport_authenticated: false`). | Emisión de advertencias estructuradas en el array `warnings` ante fuentes no calibradas o transporte no autenticado. | **FIXED** |

---

## 3. Precisiones Técnicas sobre Límites y Metodología

### 3.1 Puntos de Código Unicode (`maxLength`) vs. Límites de Bytes del Kernel
- **JSON Schema `maxLength` (Draft 2020-12 / RFC 8259)**:
  - La especificación define la restricción `maxLength` evaluando **puntos de código Unicode** (Unicode code points).
  - No mide bytes UTF-8 codificados ni unidades UTF-16. En secuencias de caracteres multibyte, un string de 4,096 puntos de código Unicode puede representar significativamente más de 4,096 bytes codificados en memoria o almacenamiento.
  - La ordenación lexicográfica de RFC 8785 (JCS) utiliza unidades de código UTF-16 para comparar nombres de propiedades, siendo una operación canónica independiente de la validación de longitud de esquema.
- **`PATH_MAX` en Linux**:
  - El estándar POSIX y el kernel Linux definen `PATH_MAX` como un límite estricto de **4,096 bytes** (incluyendo el byte NUL terminador `\0`), evaluado a nivel de sistema de archivos y VFS.
- **`MAX_ARG_STRLEN` y `ARG_MAX` en Linux**:
  - En el kernel Linux, `MAX_ARG_STRLEN` está restringido por el tamaño de página del sistema (`32 * PAGE_SIZE`, típicamente 128 KB en arquitecturas x86_64 con páginas de 4 KB).
  - Por su parte, `ARG_MAX` impone una cota agregada superior para todo el bloque combinado de argumentos (`argv`) y variables de entorno (`envp`).
- **Conclusión Normativa**:
  - Los límites `maxLength: 4096` y `maxLength: 131072` definidos en el contrato v1 son **restricciones conservadoras de esquema a nivel de aplicación**, y no deben describirse como verificaciones idénticas a los límites de bajo nivel del kernel del sistema operativo host.

### 3.2 Mitigación Parcial del Vector DoS (H-05) y Presupuesto Wire
- Las cotas de campo individuales impiden payloads unitarios infinitos.
- Sin embargo, un evento que sature simultáneamente todas las cotas máximas (1,024 argumentos de 131,072 caracteres) puede superar los 134 MB de texto. Si dicho payload se somete a `JSON.parse()` en Node.js, V8 saturará el heap antes de que Ajv pueda intervenir.
- Por tanto, la protección definitiva contra DoS exige un **presupuesto global de bytes a nivel de frame de red (ej. 1 MB a 4 MB)** implementado en la capa de lectura de stream de la **Fase 001B**, antes de la deserialización JSON.

### 3.3 Delimitación de Claves Duplicadas (H-03) en la Frontera de Red
- La vulnerabilidad de claves duplicadas pertenece al **transporte JSON serializado en texto**, donde V8 en `JSON.parse` colapsa propiedades duplicadas reteniendo el último valor.
- Esta limitación no aplica al transporte gRPC / Protobuf, el cual es binario y se rige por tags numéricos y reglas de serialización protobuf.
- En la Fase 001B, la ingestión de flujos JSON exigirá un tokenizador/parser en streaming que rechace duplicados en bytes raw según RFC 8785 antes de instanciar objetos JS.

### 3.4 Metodología de Validación: Determinismo en Lote vs. Concurrencia
- La función `validateEvent()` es enteramente **síncrona** y dependiente de CPU.
- En la Suite 9 de pruebas, la ejecución de 500 llamadas agrupadas mediante `Promise.resolve().then(...)` sobre un `Promise.all()` evalúa las llamadas de manera síncrona en el bucle de eventos antes del drenado de microtareas.
- Dicha prueba demuestra **determinismo estricto, reproducibilidad y ausencia de estado mutable en un lote de 500 llamadas consecutivas**, pero no concurrencia multihilo paralela real (la cual requeriría worker threads independientes).

### 3.5 Autenticidad de Telemetría vs. Fronteras de Permisos Locales
- Un evento validado con éxito demuestra únicamente conformidad con el contrato estructural JSON Schema.
- Un socket de dominio UNIX protegido por permisos de sistema de archivos (ej. `0600 root:root`) constituye una frontera de control de acceso discrecional (DAC) local contra procesos no privilegiados en el host.
- Sin embargo, los permisos de socket **no constituyen una atestación criptográfica del proceso emisor frente a un adversario con control de root (nivel A3)**. La confianza probatoria requiere mecanismos de atestación externa y canales autenticados en el modelo de amenazas.

---

## 4. Evidencia de Ejecución de Pruebas

- **`test/contracts/event-contract.test.js`:** 45 / 45 tests pasados (100%).
- **`test/engine.test.js`:** 2 / 2 tests pasados (100%).
- **`npm test`:** **47 / 47 tests pasados (100%)**.
- **Fixtures evaluados:** 42 / 42 (14 valid, 14 incomplete con advertencias, 14 invalid rechazados).

---

## 5. Dictamen de Cierre

- **Veredicto:** **PASS CONDICIONADO**
- **Cierre de Alcance:** Requisitos de seguridad del contrato de eventos formalmente concluidos.
- **Siguiente Fase:** Fase 001B (Normalización Tetragon) permanece **BLOQUEADA**.
