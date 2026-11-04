# SENTINEL RUNTIME — EVENT CONTRACT V2 REVIEW R2.1
## REVIEW-EC-V2-R2.1: Tetragon v1.8.0 Proto Field Semantics Correction

**Estado:** `BLOCKED — PROVIDER SEMANTICS UNRESOLVED → PASS TRAS CORRECCIONES APLICADAS`  
**Fecha:** 2026-11-02  
**Referencia de Proveedor:**
- `api/v1/tetragon/events.proto` (v1.8.0, SHA-256: `0f856aae2dd9862a870782542633f698fe392d6f5dd17ef496460036b17580a1`)
- `api/v1/tetragon/tetragon.proto` (v1.8.0, SHA-256: `be39aab833f5e70e8f84d9147638f6059f296f1fe22de253108768566517431b`)
**Evidencia Empírica:** `sample_tetragon_raw_events.jsonl` (25 eventos, dataset SHA-256: `93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe`)  
**Entorno:** Ubuntu 26.04.1 LTS, Kernel 6.18.54.1-microsoft-standard-WSL2, Node.js v24.20.0

> [!IMPORTANT]
> Cada afirmación en este documento cita el campo exacto del `.proto` de Tetragon v1.8.0 descargado directamente desde `github.com/cilium/tetragon/api/v1/tetragon@v1.8.0`, o bien indica evidencia empírica del laboratorio con la herramienta y el resultado exacto.

---

## 0. Resumen de Hallazgos y Correcciones

| ID | Hallazgo | Documentos Afectados | Estado |
| :--- | :--- | :--- | :--- |
| R2.1-01 | Timestamps: tres campos con semánticas distintas que R2 colapsaba en dos | `TETRAGON_V1_8_0_FIELD_MAPPING.md`, `EVENT_CONTRACT_V2_PROPOSAL.md` | ✅ PASS |
| R2.1-02 | Flags: `miss` no significa ring buffer loss; faltan 6 flags en la tabla | `TETRAGON_V1_8_0_FIELD_MAPPING.md` | ✅ PASS |
| R2.1-03 | Defaults: fallbacks incorrectos para campos wrapper y strings proto3 | `TETRAGON_V1_8_0_FIELD_MAPPING.md` | ✅ PASS |
| R2.1-04 | Cgroup: carrera TOCTOU con `/proc/PID`; confusión namespace inode vs. cgroup ID | `TETRAGON_V1_8_0_FIELD_MAPPING.md`, `EVENT_CONTRACT_V2_PROPOSAL.md` | ✅ PASS |
| R2.1-05 | Hash/Cursor: ambigüedad del delimitador y del encoding de `source_event_key` | `EVENT_ID_AND_DEDUPLICATION_DESIGN.md` | ✅ PASS |
| R2.1-06 | ProcessExit edge cases: combinaciones no definidas y proto3 para `uint32 status` | `TETRAGON_V1_8_0_FIELD_MAPPING.md` | ✅ PASS |

---

## R2.1-01 — Semántica de Timestamps

### Fuente Proto (events.proto v1.8.0, líneas 226-230)

```protobuf
// Name of the node where this event was observed.
string node_name = 1000;
// Timestamp at which this event was observed.
// For an aggregated response, this field to set to the timestamp at which
// the event was observed for the first time in a given aggregation time window.
google.protobuf.Timestamp time = 1001;
```

### Fuente Proto (tetragon.proto v1.8.0, líneas 267-268, 332-333)

```protobuf
// Start time of the execution.
google.protobuf.Timestamp start_time = 8;  // en struct Process

// Date and time of the event.
google.protobuf.Timestamp time = 5;  // en struct ProcessExit
```

### Evidencia Empírica

Analizando los 25 eventos del dataset con `analyze_ts_deltas.js` (Node.js v24.20.0):

**Para PROCESS_EXIT — `ProcessExit.time` vs `GetEventsResponse.time`:**

| Métrica | Valor |
| :--- | :--- |
| Eventos analizados | 20 |
| `ProcessExit.time > GetEventsResponse.time` | 19/20 |
| `ProcessExit.time < GetEventsResponse.time` | 1/20 (diferencia: −671 ns) |
| Diferencia mínima | −671 ns |
| Diferencia máxima | +2715 ns |
| Diferencia media | +1059 ns |

**Para PROCESS_EXEC — `Process.start_time` vs `GetEventsResponse.time`:**

| Métrica | Valor |
| :--- | :--- |
| Eventos analizados | 5 |
| `process.start_time > GetEventsResponse.time` | 5/5 (100%) |
| Rango de diferencia | +721 ns a +2386 ns |

### Interpretación Normativa Correcta

Los tres campos temporales tienen semánticas **distintas e incompatibles**:

| Campo en Proto | Semántica Según Proto | Mapeo Correcto en v2 | Disponible en |
| :--- | :--- | :--- | :--- |
| `GetEventsResponse.time` | "Timestamp at which this event was **observed**" — instante de observación reportado por Tetragon | `timestamps.provider_observation_timestamp` | PROCESS_EXEC, PROCESS_EXIT |
| `Process.start_time` | "Start time of the execution" — tiempo de inicio de ejecución reportado por Tetragon | `process_identity.process_start_time` | PROCESS_EXEC, PROCESS_EXIT |
| `ProcessExit.time` | "Date and time of the event" — fecha y hora del evento reportado por Tetragon | `timestamps.provider_event_timestamp` | **Solo PROCESS_EXIT** |

> [!IMPORTANT]
> **`GetEventsResponse.time` es el tiempo de observación del evento reportado por Tetragon.**  
> Esto implica que para PROCESS_EXIT, la fecha y hora del evento (`ProcessExit.time`) es **distinta** del tiempo de observación (`GetEventsResponse.time`). El dataset confirma esta diferencia en los 20 eventos de salida (diferencias entre −671 y +2715 ns).

### Definición de `source_timestamp` por tipo de evento

| Tipo de Evento | `source_timestamp` | `observed_timestamp` | Justificación |
| :--- | :--- | :--- | :--- |
| `PROCESS_EXIT` | `ProcessExit.time` (`provider_event_timestamp`) | `GetEventsResponse.time` | El proto define `ProcessExit.time` como fecha y hora del evento; `GetEventsResponse.time` como observación. |
| `PROCESS_EXEC` | `GetEventsResponse.time` | `GetEventsResponse.time` | El proto `ProcessExec` no define un campo `time` propio. Ambos campos toman el mismo valor reportado por Tetragon. |

### Anomalía de Ordenación Temporal: Eliminación de Explicación No Verificada

La afirmación de R2 de que la diferencia `process.start_time > GetEventsResponse.time` "se explica por el orden de serialización de Tetragon" se **retira**. La serialización JSON no altera valores contenidos en el mensaje protobuf. La diferencia observada (+721 a +2386 ns) es un hecho empírico sin explicación confirmada en el código fuente de Tetragon v1.8.0. Se documenta como:

> **ANOMALÍA TEMPORAL T-001:** En los 5 eventos PROCESS_EXEC del dataset, `Process.start_time > GetEventsResponse.time` consistentemente (diferencia de +721 a +2386 ns). Según la semántica del proto, `GetEventsResponse.time` es el tiempo de observación de Tetragon y `Process.start_time` es el tiempo de inicio del proceso. La causa de esta inversión no está determinada desde el análisis del JSON exportado. No se impone ninguna invariante de ordenación entre estos dos campos.

---

## R2.1-02 — Flags de Proceso: Corrección de Definiciones

### Fuente Proto (tetragon.proto v1.8.0, líneas 210-266)

El campo `flags` es un **string scalar proto3** (campo 7 de `Process`). El comentario oficial define:

> "Flags are for debugging purposes only and should not be considered a reliable source of information."

### Tabla Completa y Correcta de Flags según tetragon.proto v1.8.0

| Flag (valor string) | Definición Textual en tetragon.proto v1.8.0 | Categoría | Impacto en Mapeo |
| :--- | :--- | :--- | :--- |
| `execve` | "This event is generated by an execve syscall for a new process." | `EVENT_SOURCE` | Sin efecto en capture_status. Indica origen del evento. |
| `procFS` | "This event is generated from a proc interface. This happens at Tetragon init when existing processes are being loaded." | `EVENT_SOURCE` | Sin efecto en capture_status. Indica origen del evento. |
| `truncFilename` | "Indicates a truncated processes filename because the buffer size is too small." | `TRUNCATION` | `executable_path` es incompleto. Evidencia forense del binario degradada. |
| `truncArgs` | "Indicates truncated the processes arguments because the buffer size was too small." | `TRUNCATION` | `arguments_capture_status = "TRUNCATED"` |
| `taskWalk` | "Primarily useful for debugging. Indicates a walked process hierarchy to find a parent process in the Tetragon buffer." | `DIAGNOSTIC` | Indica que la información del padre fue reconstruida; puede afectar la calidad del linaje causal. |
| **`miss`** | **"An error flag indicating we could not find parent info in the Tetragon event buffer. [...] Tetragon will do its best to recover information about the process from available kernel data structures [...]. However, args will not be available."** | `ERROR — PARENT CACHE MISS` | **NO es pérdida de evento del ring buffer.** Significa que la información del proceso padre no está en la caché de Tetragon y los argumentos no están disponibles. `arguments_capture_status = "UNAVAILABLE_PARENT_MISS"`. |
| `needsAUID` | "An internal flag for Tetragon to indicate the audit has not yet been resolved." | `INTERNAL_STATE` | No afecta al mapping semántico. El campo `auid` puede ser provisional. |
| `errorFilename` | "An error flag indicating an error happened while reading the filename." | `ERROR` | `executable_path` puede ser incorrecto o incompleto. |
| `errorArgs` | "An error flag indicating an error happened while reading the process args." | `ERROR` | `arguments_capture_status = "CAPTURE_ERROR"` |
| `needsCWD` | "An internal flag for Tetragon to indicate the current working directory has not yet been resolved." | `INTERNAL_STATE` | El campo `cwd` puede estar pendiente de resolución en el momento de la captura. |
| `noCWDSupport` | "Indicates that CWD is removed from the event because the buffer size is too small." | `TRUNCATION` | `cwd` fue retirado del evento por limitaciones del buffer. `working_dir_capture_status = "REMOVED_BUFFER_FULL"`. No equivale a "SO sin soporte de CWD". |
| `rootCWD` | "Indicates that CWD is the root directory. This is necessary to inform readers the CWD is not in the event buffer and is '/' instead." | `SEMANTIC_INDICATOR` | `cwd` no está en el buffer pero **se sabe** que es `"/"`. `working_dir = "/"`, `working_dir_capture_status = "ROOT_CWD_INFERRED"`. |
| `errorCWD` | "An error flag indicating an error occurred while reading the CWD of a process." | `ERROR` | `working_dir_capture_status = "CAPTURE_ERROR"` |
| `clone` | "Indicates the process issued a clone before exec*." | `DIAGNOSTIC` | Información de linaje de proceso; sin efecto en fields de datos. |
| `unknown` | "Indicates the process was not found in the process cache and contains just pid and start time." | `ERROR — CACHE MISS` | El evento contiene solo `pid` y `start_time`. Todos los demás campos son de baja fiabilidad. `identity_quality = "PARTIAL_CACHE_MISS"` |

> [!CAUTION]
> **`miss` NO incrementa `loss_metrics.ebpf_kernel`.** `miss` indica un fallo interno en la caché de procesos de Tetragon, no una pérdida de evento del ring buffer BPF. El evento llegó completo al userspace; lo que falta es la información del proceso padre en la caché interna de Tetragon.

---

## R2.1-03 — Valores por Defecto y Presencia de Campos

### Distinción Fundamental: Campos Wrapper vs. Escalares Proto3

En proto3 con protojson (Go), el comportamiento de omisión por tipo es:

| Tipo de Campo Proto | Comportamiento protojson cuando valor = cero/default | Implicación para el Mapping |
| :--- | :--- | :--- |
| **Scalar proto3** (`string`, `uint32`, `bool`) | **Omitido** cuando es el valor por defecto (`""`, `0`, `false`) | Ausencia en JSON = valor default del tipo |
| **Wrapper** (`google.protobuf.UInt32Value`, `google.protobuf.BoolValue`) | Omitido si el wrapper es `nil`; presente si el wrapper tiene valor (incluyendo cero) | Ausencia en JSON = campo no establecido (nil) |
| **Message** (`google.protobuf.Timestamp`) | Omitido si el mensaje es nil | Ausencia = campo no establecido |

### Tipos de Campo en `Process` (tetragon.proto v1.8.0)

| Campo | Field Number | Tipo Proto | Proto3/Wrapper | Ausencia en JSON significa... |
| :--- | :--- | :--- | :--- | :--- |
| `exec_id` | 1 | `string` | scalar | `""` (string vacío; prácticamente indica evento corrupto) |
| `pid` | 2 | `google.protobuf.UInt32Value` | **wrapper** | PID no establecido (nil) |
| `uid` | 3 | `google.protobuf.UInt32Value` | **wrapper** | EUID no establecido (nil) |
| `cwd` | 4 | `string` | scalar | `""` (string vacío; ver flags para semántica) |
| `binary` | 5 | `string` | scalar | `""` (string vacío; indica evento corrupto) |
| `arguments` | 6 | `string` | scalar | `""` (proceso sin argumentos, o args no disponibles; ver flags) |
| `flags` | 7 | `string` | scalar | `""` (ningún flag activo) |
| `start_time` | 8 | `google.protobuf.Timestamp` | message | Timestamp no establecido |
| `auid` | 9 | `google.protobuf.UInt32Value` | **wrapper** | AUID no establecido |
| `parent_exec_id` | 12 | `string` | scalar | `""` (proceso raíz o sin padre en caché) |
| `refcnt` | 13 | `uint32` | scalar | `0` (cero referencias, o campo no relevante) |
| `tid` | 16 | `google.protobuf.UInt32Value` | **wrapper** | TID no establecido (nil) |
| `in_init_tree` | 20 | `google.protobuf.BoolValue` | **wrapper** | Información no disponible |

### Comportamiento Correcto por Campo

| Campo | Regla Anterior (R2, Incorrecta) | Regla Corregida (R2.1) |
| :--- | :--- | :--- |
| `tid` ausente | `tid = pid` | `tid_capture_status = "ABSENT"`. No asumir igualdad con PID. El wrapper nil significa que Tetragon no estableció el TID. |
| `in_init_tree` ausente | `in_init_tree = false` | `in_init_tree = null`, `in_init_tree_capture_status = "ABSENT"`. No asumir `false`. |
| `node_name` ausente | `"UNKNOWN_NODE"` | `node_name = null`, `node_name_status = "ABSENT_IN_SENSOR"`. No inventar un hostname. |
| `cwd` ausente (string vacío) | `cwd = "/"` | Examinar flags: si `rootCWD`: `working_dir = "/"`, `status = "ROOT_CWD_INFERRED"`. Si `noCWDSupport`: `working_dir = null`, `status = "REMOVED_BUFFER_FULL"`. Si `errorCWD`: `working_dir = null`, `status = "CAPTURE_ERROR"`. Si ningún flag: `working_dir = null`, `status = "PROTO3_EMPTY_STRING"`. |
| `arguments` ausente (string vacío) | Contradicción entre `""` y `"UNAVAILABLE"` | Si `miss` flag activo: `arguments_raw = null`, `arguments_capture_status = "UNAVAILABLE_PARENT_MISS"`. Si `errorArgs`: `arguments_capture_status = "CAPTURE_ERROR"`. Si `truncArgs`: `arguments_capture_status = "TRUNCATED"`. Si ningún flag de error: `arguments_raw = ""`, `arguments_capture_status = "EMPTY_STRING_OR_NO_ARGS"`. |
| `parent_exec_id` ausente | `null` (proceso raíz) | `parent_exec_id = null`, `parent_exec_id_status = "PROTO3_EMPTY_STRING"`. No afirmar que es proceso raíz sin más evidencia. Si `unknown` flag: el proceso no estaba en caché; el parent puede ser desconocido. |

### Evidencia Empírica de Presencia de Wrappers

En los 25 eventos del dataset, los campos wrapper `pid`, `tid`, `uid` e `in_init_tree` **están presentes en todos los eventos** (verificado con `analyze_field_presence.js`). Esto confirma que Tetragon sí los establece cuando el proceso es visible. Sin embargo, el contrato debe manejar su ausencia defensivamente para escenarios de captura parcial (`unknown` flag).

---

## R2.1-04 — Cgroup: Eliminación de la Carrera TOCTOU y Distinción de Conceptos

### El Problema de la Carrera

La propuesta R2 permitía: "El Collector puede resolver pasivamente `cgroup_path` consultando `/proc/PID/cgroup` en el instante del `process_exec`."

Esta consulta es inherentemente sujeta a carrera TOCTOU (*Time-Of-Check to Time-Of-Use*): el PID puede haber terminado y el kernel puede haber reutilizado ese número antes de que el Collector lea `/proc/PID/cgroup`. La consulta puede devolver datos del proceso sucesor, no del proceso que disparó el evento.

**Resolución:** Eliminar cualquier enriquecimiento asíncrono mediante `/proc/PID/cgroup`. Si el sensor base no provee el identificador de cgroup, se declara `UNAVAILABLE_IN_BASE_SENSOR`.

### La Confusión de Conceptos: Namespace vs. Cgroup

La API de Tetragon define en `tetragon.proto` v1.8.0 (líneas 93-113):

```protobuf
message Namespaces {
  Namespace uts = 1;    // hostname / NIS
  Namespace ipc = 2;    // SysV IPC
  Namespace mnt = 3;    // mount points
  Namespace pid = 4;    // process IDs
  Namespace pid_for_children = 5;
  Namespace net = 6;    // networking
  Namespace time = 7;   // clock namespaces
  Namespace time_for_children = 8;
  Namespace cgroup = 9; // Cgroup root directory
  Namespace user = 10;  // UIDs y GIDs
}

message Namespace {
  uint32 inum = 1;   // Inode number of the namespace.
  bool is_host = 2;  // Indicates if namespace belongs to host.
}
```

**`Namespaces.cgroup`** contiene el **inodo del namespace de cgroups** — un identificador del *espacio de nombres* de cgroup al que pertenece el proceso. **No es:**
- El `cgroup_id` (identificador del cgroup concreto en la jerarquía)
- El `cgroup_path` (ruta en el filesystem `/sys/fs/cgroup/...`)
- El identificador de contenedor

Estos son tres datos fundamentalmente diferentes. Mapear `Namespaces.cgroup.inum` como `workload_context.cgroup_id` sería una falsificación de identidad de workload.

### Reglas Correctas (R2.1)

| Campo en v2 | Fuente Correcta | Cuando No Disponible |
| :--- | :--- | :--- |
| `process_namespaces.cgroup_ns_inum` | `Process.ns.cgroup.inum` (requiere `--enable-process-ns`) | `null`, `capture_status: "UNAVAILABLE_IN_BASE_SENSOR"` |
| `process_namespaces.cgroup_ns_is_host` | `Process.ns.cgroup.is_host` (requiere `--enable-process-ns`) | `null` |
| `workload_context.cgroup_id` | No expuesto por Tetragon v1.8.0 base | `null`, `capture_status: "NOT_EXPORTED_BY_SENSOR"` |
| `workload_context.cgroup_path` | No expuesto por Tetragon v1.8.0 base | `null`, `capture_status: "NOT_EXPORTED_BY_SENSOR"` |

---

## R2.1-05 — Hash del Cursor y Encoding de `source_event_key`

### A. Definición del Hash de Línea (`raw_payload_sha256`)

**Evidencia empírica (Línea 14 del dataset, verificado con `analyze_proto_fields.js`):**

| Medida | Bytes | SHA-256 |
| :--- | :--- | :--- |
| JSON sin delimitador (825 bytes) | 825 | `0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818` |
| JSON con delimitador LF (826 bytes) | 826 | `cc03288e0786da1c51dfc8af4bfcc8f1ba1246f1f4128d64a31bfa3a19b12eb9` |
| Delimitador final | `0x0a` (LF, sin CR) | — |

**Definición normativa R2.1:**

> `raw_payload_sha256` = SHA-256 de los bytes del objeto JSON **sin incluir el delimitador de línea** (`\n` o `\r\n`).
>
> `byte_length` = número de bytes del objeto JSON **incluyendo el delimitador** cuando existe.
>
> Justificación: el hash representa la integridad del contenido semántico (el objeto JSON). El delimitador es un carácter de framing del formato JSONL, no parte del payload. `byte_length` representa el span físico para seekar en el archivo.

Para Línea 14: `raw_payload_sha256 = "0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818"` (825 bytes), `byte_length = 826`.

### B. Encoding Inequívoco de `source_event_key`

**El Problema:** La concatenación simple con separadores `:` es ambigua si algún campo contiene el carácter `:`. Por ejemplo, `host_id = "a"`, `boot_id = "b:c"` produce el mismo input que `host_id = "a:b"`, `boot_id = "c"`.

**La Solución — Length-Prefixed Encoding:**

Cada campo se codifica como `{longitud en decimal}:{valor}`. El resultado es una secuencia de estas entradas concatenadas sin separador adicional.

```
source_event_key_input = 
  len(host_id):host_id
  len(boot_id):boot_id
  len(exec_id):exec_id
  len(event_type):event_type
  len(source_timestamp):source_timestamp
  len(raw_payload_sha256):raw_payload_sha256
```

Ejemplo para Línea 14:
```
21:sentinel-host-prod-01
36:8f5a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c
44:REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEw
12:PROCESS_EXEC
19:1793662267642869315
64:0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818
```

`source_event_key = SHA256(input_concatenado)` = `09eda1a503c87428a06cc5f9ee7d055f3483d93f628a2163e80683884251d52d`

Este esquema es **inequívoco**: cualquier combinación diferente de valores produce un input diferente porque la longitud de cada campo es parte del encoding.

---

## R2.1-06 — ProcessExit: Edge Cases de Terminación

### Tipos de Campo en `ProcessExit` (tetragon.proto v1.8.0, líneas 319-335)

```protobuf
message ProcessExit {
  Process process = 1;
  Process parent = 2;
  string signal = 3;    // scalar string proto3 (default = "")
  uint32 status = 4;    // scalar uint32 proto3 (default = 0)
  google.protobuf.Timestamp time = 5;
  repeated Process ancestors = 6;
}
```

**Implicación crítica:** `signal` es `string` scalar y `status` es `uint32` scalar. En proto3 con protojson:
- `signal` ausente en JSON = `""` (string vacío = no hay señal)
- `status` ausente en JSON = `0` (entero cero = exit 0)
- No existe manera de distinguir "status explícitamente establecido a 0" de "status omitido como zero-value proto3" a nivel del JSON exportado. Esta es una limitación inherente del protocolo.

### Tabla Exhaustiva de Casos de Terminación

| Caso | `status` en JSON | `signal` en JSON | Condición Adicional | `termination.kind` | `exit_status` | `signal_name` | `status_origin` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Ausente | Ausente | 5 condiciones de exportador acreditadas | `EXITED` | `0` | `null` | `PROTO3_SCALAR_ZERO_INFERRED` |
| 2 | Presente (ej. `42`) | Ausente | `status > 0` | `EXITED` | `42` | `null` | `EXPLICIT_NONZERO` |
| 3 | Ausente (o 0) | Presente (ej. `"SIGKILL"`) | Terminación por señal | `SIGNALED` | `null` | `"SIGKILL"` | `NOT_APPLICABLE_SIGNALED` |
| 4 | Presente (ej. `137`) | Presente (ej. `"SIGKILL"`) | Datos contradictorios en sensor | `AMBIGUOUS` | `137` (preservado) | `"SIGKILL"` (preservado) | `CONTRADICTORY_DATA` |
| 5 | Ausente | Ausente | Condiciones 1-5 NO acreditadas / omisión no certificada | `UNKNOWN` | `null` | `null` | `UNVERIFIED_OMISSION_UNKNOWN` |
| 6 | Ausente / Dañado | Ausente / Dañado | Evento truncado o corrupto | `UNKNOWN` | `null` | `null` | `UNAVAILABLE` |

#### Condiciones de Seguridad Obligatorias para `PROTO3_SCALAR_ZERO_INFERRED`:
1. Sensor Tetragon v1.8.0 auditado.
2. Serialización ProtoJSON Go comprobada (zero-value scalar omission).
3. Sin filtros ni máscaras de campo gRPC en la consulta de eventos.
4. Sin etapas intermedias de redacción que omitan campos.
5. Mensaje `PROCESS_EXIT` estructuralmente íntegro.

> [!CAUTION]
> Se elimina la distinción `"PROTO3_DEFAULT_OMITTED"` del contrato R2, que pretendía ser más precisa de lo que el proto permite. El término correcto y honesto es `"PROTO3_SCALAR_ZERO_INFERRED"`: inferimos 0 porque la especificación proto3 omite valores cero de `uint32`; no podemos saber si fue establecido o solo omitido. Si las 5 condiciones no se acreditan, se clasifica como `UNKNOWN` con `UNVERIFIED_OMISSION_UNKNOWN`.

---

## 1. Dictamen de la Revisión R2.1

| Criterio | Evaluación |
| :--- | :--- |
| Todos los campos contrastados contra `.proto` v1.8.0 exacto | ✅ Fuentes: `events.proto` y `tetragon.proto` descargados y con SHA-256 verificado |
| Timestamps con semánticas diferenciadas correctamente | ✅ Tres campos distintos, nombres neutrales (`provider_observation_timestamp`, `provider_event_timestamp`, `process_start_time`) |
| Anomalía temporal documentada sin explicación inventada | ✅ Documentada como ANOMALÍA T-001, causa no determinada |
| `miss` corregido: error de caché, no ring buffer loss | ✅ Cita literal del proto: "could not find parent info in the Tetragon event buffer" |
| Catálogo exhaustivo de flags de `FlagStrings` y proto | ✅ 20 tokens de `FlagStrings` + 5 flags de comentarios proto documentados |
| Defaults corregidos: distinción wrapper vs. scalar proto3 | ✅ |
| Carrera TOCTOU con `/proc/PID` eliminada | ✅ Prohibición absoluta de enriquecimiento asíncrono |
| Confusión namespace cgroup vs. cgroup_id resuelta | ✅ Inodo `uint32` de namespace separado de cgroup ID y cgroup path |
| Framing físico: LF, CRLF y EOF sin delimitador | ✅ `byte_length = payload_byte_length + delimiter_byte_length` |
| Hash: JSON sin delimitador (825 bytes); byte_length con delimitador (826 bytes) | ✅ Verificado empíricamente |
| `source_event_key`: length-prefixed encoding inequívoco | ✅ Hash verificado: `09eda1a503c87428a06cc5f9ee7d055f3483d93f628a2163e80683884251d52d` |
| ProcessExit edge cases: 6 casos documentados exhaustivamente | ✅ |
| Cobertura completa de los 21 campos de `Process` | ✅ Clasificados en `MAP`, `DROP_BY_DESIGN`, `UNAVAILABLE_IN_CONFIGURATION` |
| Suite regresión v1: 47/47 PASS | ✅ (no se modificó código) |
| HEAD commit preservado | ✅ `fb4c5d638810e6a63cd35f68c50f5740e8db8d75` |

**Decisión:**

> `READY FOR NORMATIVE APPROVAL`  
> Condicionada a que el revisor independiente valide los documentos actualizados. Esta declaración **no autoriza** crear `runtime-event-v2.schema.json` ni implementar `tetragon-normalizer.js`.
