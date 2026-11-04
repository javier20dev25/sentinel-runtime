# SENTINEL RUNTIME — TETRAGON v1.8.0 FIELD MAPPING SPECIFICATION
## MAPPING-TETRAGON-V1-8-0r2.3: Formal Mapping from Tetragon eBPF JSON to Event Contract v2 (Revision R2.3)

**Estado:** `NORMATIVE SPECIFICATION FOR INDEPENDENT APPROVAL (R2.3)`  
**Fecha:** 2026-11-02  
**Sensor Objetivo:** Cilium Tetragon v1.8.0 (Exportación JSON, Linux eBPF)  
**Destino:** Sentinel Runtime Event Contract v2 (`docs/specs/EVENT_CONTRACT_V2_PROPOSAL.md`)  
**Autor:** Sentinel Runtime Engineering & Security Architecture  
**Referencia API y Código Fuente:** [Tetragon v1.8.0 Go API](https://pkg.go.dev/github.com/cilium/tetragon/api/v1/tetragon@v1.8.0), `pkg/encoder/encoder.go`, `cmd/tetragon/main.go`, [ProtoJSON Go reference](https://protobuf.dev/programming-guides/json/)

---

## 1. Alcance y Principios Innegociables de Mapeo

Este documento establece las reglas canónicas de transformación de telemetría en crudo de Cilium Tetragon v1.8.0 a Event Contract v2. Cada regla es o bien **demostrada empíricamente** en el laboratorio WSL2 (kernel `6.18.54.1-microsoft-standard-WSL2`), o bien **derivada de la API oficial documentada**.

### Principios Innegociables

1. **Preservación Literal:** Ningún identificador opaco del sensor (`exec_id`, `parent_exec_id`) ni cadena de texto original (`arguments`, `binary`) será alterado, decodificado, recodificado, fragmentado ni fabricado sintéticamente.
2. **Prohibición Absoluta de `split`:** Se prohíbe `split(" ")`, `split(/\s+/)` o cualquier operador léxico similar para fabricar un `argv` desde `arguments`.
3. **Inferencia Condicionada y Atestada:** La inferencia de `exit_status = 0` aplica **exclusivamente** cuando tanto `status` como `signal` están simultáneamente ausentes en el JSON del evento `process_exit`, comportamiento verificado y documentado en Tetragon v1.8.0 + protojson Go (proto3 zero-value omission). La condición de activación debe ser comprobable en el binario de Tetragon auditado.
4. **Flags como Debug, No como Garantía:** Los valores de `process.flags` (`"execve clone"`, `"procFS"`, `"rootcwd"`, `"truncArgs"`, `"miss"`, `"errorArgs"`, `"noCWDSupport"`) son **metadatos heurísticos de depuración interna del probe eBPF**, no garantías normativas de completitud ni integridad universal. Su presencia positiva puede alertar problemas de captura; su ausencia **no demuestra** que la captura fue íntegra para todo proceso en el sistema.
5. **Separación de Timestamps:** Los múltiples campos temporales de Tetragon tienen semánticas distintas e incompatibles entre sí. Se prohíbe copiar un timestamp en otro campo simplemente para satisfacer un esquema.
6. **Procedencia Transparente:** Todo campo que no provenga directamente de Tetragon debe ser clasificado explícitamente como inyectado por el Collector, derivado determinísticamente, o ausente en el sensor.

---

## 2. Semántica de los Timestamps de Tetragon v1.8.0

### Fuentes Proto (v1.8.0)

- **`GetEventsResponse.time`** (events.proto, campo 1001): `"Timestamp at which this event was observed."` — Instante de **observación** del evento reportado por Tetragon.
- **`Process.start_time`** (tetragon.proto, campo 8 de `Process`): `"Start time of the execution."` — Tiempo de inicio de ejecución reportado por Tetragon (no se afirma correspondencia con estructuras internas del kernel sin trazabilidad de código).
- **`ProcessExit.time`** (tetragon.proto, campo 5 de `ProcessExit`): `"Date and time of the event."` — Fecha y hora del evento de terminación reportado por Tetragon (no se asume toma directa en un hook de kernel sin prueba de código).

### Tabla de Mapping de Timestamps

| Campo en JSON de Tetragon | Semántica Según Proto v1.8.0 | Mapeo en Event Contract v2 | Disponible en |
| :--- | :--- | :--- | :--- |
| `time` (raíz, `GetEventsResponse.time`) | "Timestamp at which this event was **observed**" — Instante de observación reportado por Tetragon. | `timestamps.provider_observation_timestamp` | PROCESS_EXEC, PROCESS_EXIT |
| `process.start_time` | "Start time of the execution" — Tiempo de inicio de ejecución reportado por Tetragon. | `process_identity.process_start_time` | PROCESS_EXEC, PROCESS_EXIT |
| `process_exit.time` (`ProcessExit.time`) | "Date and time of the event" — Fecha y hora del evento reportado por Tetragon. | `timestamps.provider_event_timestamp` | **Solo PROCESS_EXIT** |
| *(Reloj del Collector)* | No proviene de Tetragon. Reloj local del Sentinel Collector. | `timestamps.ingest_timestamp` | PROCESS_EXEC, PROCESS_EXIT |

### Asignación de `source_timestamp` por Tipo de Evento

| Tipo de Evento | `source_timestamp` | `observed_timestamp` | Justificación |
| :--- | :--- | :--- | :--- |
| `PROCESS_EXIT` | `ProcessExit.time` (`provider_event_timestamp`) | `GetEventsResponse.time` (`provider_observation_timestamp`) | El proto define `ProcessExit.time` como fecha y hora del evento; `GetEventsResponse.time` como observación por Tetragon. Son distintos en todos los eventos del dataset. |
| `PROCESS_EXEC` | `GetEventsResponse.time` | `GetEventsResponse.time` | El mensaje `ProcessExec` no define un campo `time` propio (sin análogo a `ProcessExit.time`). Ambos campos reciben el mismo valor reportado por Tetragon. |

> [!IMPORTANT]
> **Evidencia empírica (20 eventos PROCESS_EXIT del dataset de laboratorio):**  
> `ProcessExit.time` ≠ `GetEventsResponse.time` en los 20 eventos (diferencias: −671 a +2715 ns, media: +1059 ns). Los dos campos capturan instantes distintos con ordenación no garantizada. No se puede tratar como el mismo timestamp.

### Anomalía Temporal T-001 (Sin Explicación Determinada)

**Observación:** En los 5 eventos PROCESS_EXEC del dataset, `Process.start_time > GetEventsResponse.time` consistentemente (+721 a +2386 ns). Según el proto, `GetEventsResponse.time` es tiempo de observación y `Process.start_time` es tiempo de creación del proceso.

**Estado:** Causa no determinada desde el análisis del JSON exportado. Se retira la afirmación anterior de que "se explica por el orden de serialización" — la serialización JSON no altera los valores de los campos protobuf ya calculados. **No se impone ninguna invariante de ordenación** entre `Process.start_time` y `GetEventsResponse.time`.

> [!NOTE]
> Se prohíbe asignar el mismo timestamp a campos con semánticas distintas para satisfacer artificialmente el esquema. Se prohíbe añadir invariantes temporales que los datos empíricos no confirman.

---

## 3. Doctrina de `process.uid` → `euid` (Corrección Doctrinal R2)

**Fuente normativa:** [Tetragon v1.8.0 Go API — `Process.uid`](https://pkg.go.dev/github.com/cilium/tetragon/api/v1/tetragon@v1.8.0#Process)

La API oficial de Tetragon v1.8.0 documenta:
```
// The uid of the user that started the process.
// This maps to the effective user ID (EUID) in the kernel.
uint32 uid = 5;
```

Por tanto:
- `Process.uid` de Tetragon → `process_identity.euid` en Event Contract v2.
- El RUID (`ruid`) **solo está disponible** cuando el Collector utiliza credenciales extendidas (`--enable-process-cred`), accesibles en `ProcessCredentials.uid`. En configuración base, se declara `null` con `credentials_capture_status: "EFFECTIVE_ONLY"`.
- Se prohíbe sustituir un `ruid` desconocido por el `euid` disponible. Son campos semánticamente distintos y potencialmente diferentes bajo `setuid(2)`.

---

## 4. Matriz Maestra de Mapeo de Campos

### A. Metadatos de Envoltorio y Raíz

| Campo Tetragon (JSON) | Tipo Tetragon | Destino en Event Contract v2 | Tipo en v2 | Transformación / Regla | Comportamiento si Ausente |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *(Raíz: `process_exec`)* | Objeto | `event_type` | String enum | `"PROCESS_EXEC"` | N/A (determina tipo de evento) |
| *(Raíz: `process_exit`)* | Objeto | `event_type` | String enum | `"PROCESS_EXIT"` | N/A (determina tipo de evento) |
| `time` (raíz) | String (RFC 3339 Nano) | `timestamps.provider_observation_timestamp` (y `source_timestamp` en PROCESS_EXEC) | String uint64 (nanos) | Conversión aritmética pura (algoritmo Hinnant). Cero uso de `Date.UTC`. | **FATAL**: Registro rechazado si falta. |
| `node_name` | String | `host_identity.node_name` | String | Preservación literal del hostname emitido por Tetragon. | `null` con `host_identity.node_name_status = "ABSENT_IN_SENSOR"`. **Prohibido sintetizar `"UNKNOWN_NODE"`**. |
| *(Configuración)* | N/A | `host_identity.host_id` | String | Aportado por la configuración persistente del nodo Sentinel. | Configuración obligatoria. |
| *(Lectura Kernel)* | N/A | `host_identity.boot_id` | String | Leído pasivamente de `/proc/sys/kernel/random/boot_id` por el Collector. | Error de configuración del entorno. |
| *(Collector)* | N/A | `sensor_metadata.collector_id` | String | Identidad persistente del agente Collector. | Generada por Collector. |
| *(Collector)* | N/A | `sensor_metadata.collector_session_id` | String | UUIDv4 del ciclo de vida del proceso Collector. **NO incluir en `source_event_key`** (cambiaría en cada reinicio e invalidaría la deduplicación). | Generada por Collector al inicio. |
| *(Fijo)* | N/A | `sensor_metadata.sensor_version` | String | `"v1.8.0"` (auditado en binario de Tetragon). | Fijo por sensor auditado. |
| *(Fijo)* | N/A | `sensor_metadata.transport_protocol` | String | `"JSON_FILE_STREAM"` para lectura de `/var/log/tetragon/tetragon.log`. | Fijo por mecanismo de transporte. |
| *(Architectural)* | N/A | `sensor_metadata.transport_authentication` | String | `"NOT_APPLICABLE_LOCAL_FILE"`. Se prohíbe `true` para archivos locales. | `"UNKNOWN"` si no puede determinarse. |

---

### B. Objeto `process` (Identidad de Proceso)

**Distinción fundamental — Tipos de campo en tetragon.proto v1.8.0:**

- **Campos wrapper** (`google.protobuf.UInt32Value`, `google.protobuf.BoolValue`): Ausencia en JSON = wrapper `nil` (campo no establecido por Tetragon).
- **Scalars proto3** (`string`, `uint32`): Ausencia en JSON = valor por defecto (`""`, `0`).

| Campo Tetragon (`process.*`) | Tipo Proto | Destino en Event Contract v2 | Transformación / Semántica | Comportamiento si Ausente |
| :--- | :--- | :--- | :--- | :--- |
| `exec_id` | `string` scalar | `process_identity.exec_id` | Preservación literal. Clave primaria de nodo en el DAG causal. | **FATAL**: string vacío indica evento corrupto. |
| `parent_exec_id` | `string` scalar | `process_identity.parent_exec_id` | Preservación literal. Clave de arista dirigida al padre. | `null` con `parent_exec_id_status: "PROTO3_EMPTY_STRING"`. No afirmar que es proceso raíz sin más evidencia (puede ser `unknown` flag). |
| `pid` | `UInt32Value` **wrapper** | `process_identity.pid` | Preservación literal de PID efímero del kernel. | `null` con `pid_status: "ABSENT"`. El wrapper nil indica que Tetragon no estableció el PID. |
| `tid` | `UInt32Value` **wrapper** | `process_identity.tid` | Preservación literal de Thread ID. | `null` con `tid_status: "ABSENT"`. **Prohibido asumir `tid = pid`**. |
| `start_time` | `Timestamp` message | `process_identity.process_start_time` | Conversión aritmética pura a nanosegundos epoch. | **FATAL**: Registro rechazado. |
| `binary` | `string` scalar | `process_identity.executable_path` | Preservación literal. | **FATAL**: string vacío indica evento corrupto. |
| `uid` | `UInt32Value` **wrapper** | `process_identity.euid` | **`Process.uid` de Tetragon = EUID.** Ver §3. | `null` con `euid_status: "ABSENT"`. El wrapper nil indica que Tetragon no estableció el EUID. |
| *(credentials.uid)* | `UInt32Value` **wrapper** | `process_identity.ruid` | RUID real. Solo con `--enable-process-cred`. | `null` con `credentials_capture_status: "EFFECTIVE_ONLY"`. Prohibido sustituir por EUID. |
| `cwd` | `string` scalar | `payload.working_dir` | Ver tabla de `working_dir_capture_status` en §5. | String vacío: examinar flags (`rootCWD`, `noCWDSupport`, `errorCWD`). **Prohibido asumir `"/"` sin flag `rootCWD`**. |
| `flags` | `string` scalar | `sensor_metadata.debug_process_flags` | **DEBUG METADATA ONLY.** Preservación literal de tokens emitidos por `FlagStrings`. Ver §5 para catálogo exhaustivo. | Cadena vacía `""` con `debug_process_flags_status: "NO_FLAGS_SET"`. |
| `in_init_tree` | `BoolValue` **wrapper** | `workload_context.in_init_tree` | Preservación literal. | `null` con `in_init_tree_status: "ABSENT"`. **Prohibido asumir `false`**. |
| `refcnt` | `uint32` scalar | `sensor_metadata.debug_refcnt` | Contador de referencias de caché interno de Tetragon. Debug metadata. | `0` (proto3 scalar default inferido). |
| `auid` | `UInt32Value` **wrapper** | `sensor_metadata.debug_auid` | Audit UID. Si es `4294967295` (0xFFFFFFFF), es `AU_NOAUDITID`. | `null` con `auid_status: "ABSENT"`. |

---

### C. Payload para `PROCESS_EXEC`

| Campo Tetragon | Destino en Event Contract v2 | Transformación | Comportamiento si Ausente |
| :--- | :--- | :--- | :--- |
| `process.binary` | `payload.binary` | Preservación literal. | **FATAL**: Obligatorio. |
| `process.arguments` | `payload.arguments_raw` | **Preservación literal sin ningún split ni transformación.** | `""` (cadena vacía). |
| *(no existe en v1.8.0 base)* | `payload.argv` | `null` explícito. El vector de punteros `execve(argv[])` no se expone en telemetría base. | N/A — siempre `null` en base sensor. |
| *(derivado de flags)* | `payload.arguments_capture_status` | Ver tabla §5. | `"RAW_STRING_ONLY"` por defecto. |

---

### D. Payload para `PROCESS_EXIT` (Modelo Discriminado de Terminación)

**Tipos de campo en `ProcessExit` (tetragon.proto v1.8.0):**
- `signal` (campo 3): `string` scalar proto3 → ausente en JSON cuando vacío (`""`)
- `status` (campo 4): `uint32` scalar proto3 → ausente en JSON cuando `0` (valor default)
- Consecuencia: **es imposible distinguir `status` establecido explícitamente a `0` de `status` omitido por ser el valor default proto3**. El contrato documenta esto con `status_origin: "PROTO3_SCALAR_ZERO_INFERRED"`.

La salida de Tetragon para `process_exit` se mapea bajo las siguientes reglas de precedencia comprobadas empíricamente en Tetragon v1.8.0 + protojson Go:

```
                  ┌───────────────────────────────┐
                  │ Tetragon process_exit event   │
                  └───────────────┬───────────────┘
                                  │
      ¿Existen simultáneamente "signal" (no vacío) Y "status" (> 0)?
                 /                                 \
             SÍ /                                   \ NO
               ▼                                     ▼
    ┌──────────────────────────┐     ¿Existe "signal" (string no vacío)?
    │ kind = "AMBIGUOUS"       │    /                         \
    │ exit_status = status     │SÍ /                           \ NO
    │ signal_name = signal     │  ▼                             ▼
    │ status_origin =          │┌──────────────────────────┐  ¿Existe "status" (uint32 > 0)?
    │ "CONTRADICTORY_DATA"     ││ kind = "SIGNALED"        │ /                          \
    └──────────────────────────┘│ signal_name = signal     │SÍ/                           \ NO
                                │ exit_status = null       │ ▼                              ▼
                                │ status_origin =          │┌────────────────────────┐  ¿Acredita Collector
                                │ "NOT_APPLICABLE_SIGNALED"││ kind = "EXITED"        │   las 5 condiciones de
                                └──────────────────────────┘│ exit_status = status   │   exportador certificado?
                                                            │ signal_name = null     │  /                   \
                                                            │ status_origin =        │ SÍ /               \ NO
                                                            │ "EXPLICIT_NONZERO"     │   ▼                 ▼
                                                            └────────────────────────┘ ┌─────────────────┐ ┌─────────────────┐
                                                                                       │ kind = "EXITED" │ │ kind = "UNKNOWN"│
                                                                                       │ exit_status = 0 │ │ exit_status=null│
                                                                                       │ signal_name=null│ │ signal_name=null│
                                                                                       │ status_origin = │ │ status_origin = │
                                                                                       │ "PROTO3_SCALAR_ │ │ "UNVERIFIED_    │
                                                                                       │ ZERO_INFERRED"  │ │ OMISSION_       │
                                                                                       └─────────────────┘ │ UNKNOWN"        │
                                                                                                           └─────────────────┘
```

#### Condiciones de Seguridad Obligatorias para la Inferencia de Cero (`PROTO3_SCALAR_ZERO_INFERRED`)

La inferencia de `exit_status = 0` **no es incondicional**. Solo es válida cuando el Sentinel Collector acredita fehacientemente las 5 condiciones siguientes con respaldo en el código fuente de Tetragon v1.8.0:
1. **Identidad del Proveedor Auditada:** El sensor emisor es Cilium Tetragon v1.8.0 (auditado en binario/build).
2. **Serialización Comprobada en Código (`pkg/encoder/encoder.go:169-174`):** El serializador JSON de Tetragon instancia `protojson.MarshalOptions{ UseProtoNames: true }` sin activar `EmitUnpopulated: true`. En la especificación oficial de ProtoJSON Go (`google.golang.org/protobuf/encoding/protojson`), los campos proto3 con valor por defecto escalar (`uint32 status = 0`, `string signal = ""`) son invariablemente omitidos del payload emitido.
3. **Ausencia de Filtros de Campo en Exportador (`cmd/tetragon/main.go:870,882`):** En la configuración base de Tetragon para exportación a archivo (`--export-filename /var/log/tetragon/tetragon.log`), la estructura `tetragon.GetEventsRequest` se inicializa con `FieldFilters: nil`. Se comprueba que no existen field masks ni filtros gRPC activos que hayan expurgado campos del evento.
4. **Integridad del Pipeline de Transporte:** No existen intermediarios de redacción, agregación, truncamiento o filtrado que hayan podido expurgar campos del payload JSONL.
5. **Conformidad Estructural:** El evento es un mensaje `PROCESS_EXIT` sintácticamente íntegro, cerrado con delimitador válido y sin flags de error de framing.

Si **cualquiera** de estas cinco condiciones no puede ser demostrada y acreditada por el Collector, la ausencia de ambos campos **no debe inferirse como éxito (0)**: debe asignarse `kind = "UNKNOWN"`, `exit_status = null`, `signal_name = null`, `status_origin = "UNVERIFIED_OMISSION_UNKNOWN"`.

| Condición en Tetragon JSON | `termination.kind` | `termination.exit_status` | `termination.signal_name` | `termination.status_origin` |
| :--- | :--- | :--- | :--- | :--- |
| `signal` presente + `status` presente (>0) | `"AMBIGUOUS"` | valor literal | valor literal | `"CONTRADICTORY_DATA"` |
| `signal` presente + `status` ausente (o 0) | `"SIGNALED"` | `null` | valor literal | `"NOT_APPLICABLE_SIGNALED"` |
| `signal` ausente + `status` presente (>0) | `"EXITED"` | N (>0) | `null` | `"EXPLICIT_NONZERO"` |
| Ambos ausentes (condiciones 1-5 acreditadas) | `"EXITED"` | `0` | `null` | `"PROTO3_SCALAR_ZERO_INFERRED"` |
| Ambos ausentes (condiciones 1-5 NO acreditadas) | `"UNKNOWN"` | `null` | `null` | `"UNVERIFIED_OMISSION_UNKNOWN"` |
| Evento truncado / corrupto / no interpretable | `"UNKNOWN"` | `null` | `null` | `"UNAVAILABLE"` |

> [!CAUTION]
> Se prohíbe explícitamente: `exit_code: (exit_status ?? 0)` y `signal: (signal_name ? 1 : null)`.  
> Esas conversiones son falsificaciones de evidencia: convierten `"SIGKILL"` en `{ exit_code: 0, signal: 1 }`.

| Campo Tetragon | Destino en Event Contract v2 | Regla de Normalización |
| :--- | :--- | :--- |
| `signal` | `payload.termination.signal_name` | Preservación literal. Si presente y sin `status > 0`: `kind = "SIGNALED"`, `exit_status = null`. |
| `status` | `payload.termination.exit_status` | Si presente y sin `signal`: copiado numéricamente. `kind = "EXITED"`, `status_origin = "EXPLICIT_NONZERO"`. |
| *(datos contradictorios)* | `payload.termination` | Si `signal` y `status > 0` presentes: `kind = "AMBIGUOUS"`, `status_origin = "CONTRADICTORY_DATA"`. Ambos preservados. |
| *(ambos ausentes, certificado)* | `payload.termination` | `exit_status = 0`, `kind = "EXITED"`, `status_origin = "PROTO3_SCALAR_ZERO_INFERRED"`. |
| *(ambos ausentes, no certificado)* | `payload.termination` | `exit_status = null`, `kind = "UNKNOWN"`, `status_origin = "UNVERIFIED_OMISSION_UNKNOWN"`. |
| `time` (en `process_exit`) | `timestamps.provider_event_timestamp` | Conversión aritmética pura. **Distinto de `GetEventsResponse.time`.** Ver §2. |

---

## 5. Especificación Exhaustiva de Flags de Captura (`process.flags`)

Los flags de `process.flags` en Tetragon son indicadores heurísticos internos del probe eBPF. Citando textualmente el `.proto` oficial de Tetragon v1.8.0:  
> **"Flags are for debugging purposes only and should not be considered a reliable source of information. They hold various information about which syscalls generated events, use of internal Tetragon buffers, errors and more."**

### A. Discrepancia Normativa: Proto Documentado vs. Código Go Serializado

Existe una desarmonización reconocida explícitamente en el propio código fuente de Tetragon v1.8.0 (`pkg/reader/exec/exec.go:10`):
```go
// TODO: Harmonize these with the API docs (Flags field in tetragon.Process)
var FlagStrings = map[uint32]string{ ... }
```
Por tanto, la especificación normativa de Sentinel Runtime distingue obligatoriamente entre:
1. `proto_documented_name`: Nombre conceptual que figura en los comentarios de `tetragon.proto`.
2. `serialized_token_v1_8_0`: Token literal de texto emitido por `FlagStrings` en el campo `process.flags` del JSON.
3. `source_location`: Archivo, línea y constante en el código de Tetragon v1.8.0.
4. `capture_effect`: Impacto real sobre la integridad o disponibilidad del dato.
5. `normalizer_action`: Regla estricta que Sentinel aplica ante el token.

### B. Catálogo Exhaustivo de Tokens Emitidos por `FlagStrings` (Tetragon v1.8.0)

| `proto_documented_name` | `serialized_token_v1_8_0` | `source_location` | `capture_effect` | `normalizer_action` |
| :--- | :--- | :--- | :--- | :--- |
| `execve` | `execve` | `pkg/reader/exec/exec.go:12`<br>`api.EventExecve` (`0x01`) | Evento generado nativamente por syscall de la familia `execve*`. | Preservar en `sensor_metadata.debug_process_flags`. Atesta generación live. |
| `procFS` | `procFS` | `pkg/reader/exec/exec.go:13`<br>`api.EventProcFS` (`0x04`) | Proceso precargado desde `/proc` al inicializar el daemon Tetragon. | Preservar en metadata; catalogar `identity_quality = "INITIAL_PROCFS_LOAD"`. |
| *(no en comentarios proto)* | `errorEnvs` | `pkg/reader/exec/exec.go:14`<br>`api.EventErrorEnvs` (`0x08`) | Error en kernel al leer o almacenar variables de entorno del proceso. | `environment_variables = null`, `env_capture_status = "CAPTURE_ERROR"`. |
| `truncArgs` | `truncArgs` | `pkg/reader/exec/exec.go:15`<br>`api.EventTruncArgs` (`0x10`) | Argumentos de ejecución truncados por límite del buffer eBPF en kernel. | Asignar `arguments_capture_status = "TRUNCATED"`. Preservar texto truncado. |
| **`miss`** | **`miss`** | `pkg/reader/exec/exec.go:16`<br>`api.EventMiss` (`0x40`) | **Fallo de caché interna de Tetragon para hallar el proceso padre.** El kernel recupera datos básicos pero los argumentos no están disponibles. | Asignar `arguments_capture_status = "UNAVAILABLE_PARENT_MISS"`. **NO contar como pérdida de ring buffer eBPF** (`loss_metrics.ebpf_kernel` permanece inalterado). |
| `errorFilename` | `errorFilename` | `pkg/reader/exec/exec.go:17`<br>`api.EventErrorFilename` (`0x100`) | Error al leer la ruta del archivo ejecutable desde el kernel. | Degradar confianza de `executable_path`. Marcar `path_capture_status = "CAPTURE_ERROR"`. |
| `errorArgs` | `errorArgs` | `pkg/reader/exec/exec.go:18`<br>`api.EventErrorArgs` (`0x200`) | Error al leer los argumentos del proceso desde las estructuras del kernel. | Asignar `arguments_capture_status = "CAPTURE_ERROR"`, `arguments_raw = null`. |
| `noCWDSupport` *(discrepancia)* | **`nocwd`** | `pkg/reader/exec/exec.go:19`<br>`api.EventNoCWDSupport` (`0x800`) | CWD removido del evento por saturación o buffer insuficiente. No indica falta de soporte del SO. | Asignar `working_dir = null`, `working_dir_capture_status = "REMOVED_BUFFER_FULL"`. Match por token `nocwd`. |
| `rootCWD` *(discrepancia)* | **`rootcwd`** | `pkg/reader/exec/exec.go:20`<br>`api.EventRootCWD` (`0x1000`) | El CWD del proceso es `/`; Tetragon no lo incluye en el buffer para optimizar espacio. | Asignar `working_dir = "/"`, `working_dir_capture_status = "ROOT_CWD_INFERRED"`. Match por token `rootcwd`. |
| `errorCWD` | `errorCWD` | `pkg/reader/exec/exec.go:21`<br>`api.EventErrorCWD` (`0x2000`) | Error de lectura del CWD en el kernel. | Asignar `working_dir = null`, `working_dir_capture_status = "CAPTURE_ERROR"`. |
| `clone` | `clone` | `pkg/reader/exec/exec.go:22`<br>`api.EventClone` (`0x4000`) | El proceso realizó `clone()` antes de `exec*`. Si falta, hubo reemplazo directo sobre el mismo PID. | Preservar en metadata de depuración. Insumo para reconstrucción de linaje. |
| *(no en comentarios proto)* | `errorCgroupName` | `pkg/reader/exec/exec.go:23`<br>`api.EventErrorCgroupName` (`0x010000`) | Fallo al resolver el nombre del cgroup en kernel. Afecta container ID / docker. | Declarar `cgroup_capture_status = "RESOLVER_ERROR_CGROUP_NAME"`, `container_id = null`. |
| *(no en comentarios proto)* | `errorCgroupID` *(discrepancia casing)* | `pkg/reader/exec/exec.go:24`<br>`api.EventErrorCgroupId` (`0x200000`) | Fallo al resolver el cgroup ID numérico en kernel. | Asignar `cgroup_capture_status = "RESOLVER_ERROR_CGROUP_ID"`. |
| *(no en comentarios proto)* | `errorCgroupSubsysCgrp` | `pkg/reader/exec/exec.go:25`<br>`api.EventErrorCgroupSubsysCgrp` (`0x040000`) | Fallo de lectura del subsistema de cgroup específico. | Registrar en diagnóstico de sensor. |
| *(no en comentarios proto)* | `errorCgroupSubsys` | `pkg/reader/exec/exec.go:26`<br>`api.EventErrorCgroupSubsys` (`0x080000`) | Fallo general de subsistema cgroup en kernel. | Registrar en diagnóstico de sensor. |
| *(no en comentarios proto)* | `errorCgroups` | `pkg/reader/exec/exec.go:27`<br>`api.EventErrorCgroups` (`0x100000`) | Fallo múltiple de resolución de cgroups. | Registrar en diagnóstico de sensor. |
| *(no en comentarios proto)* | `errorPathResolutionCwd` *(discrepancia const)* | `pkg/reader/exec/exec.go:28`<br>`api.EventErrorPathComponents` (`0x400000`) | Error en resolución de componentes de path del CWD en el probe eBPF. | Asignar `working_dir = null`, `working_dir_capture_status = "PATH_RESOLUTION_ERROR"`. |
| *(no en comentarios proto)* | `dataFilename` | `pkg/reader/exec/exec.go:29`<br>`api.EventDataFilename` (`0x800000`) | Nombre de ejecutable transferido por canal desacoplado de datos. | Preservar en metadata; valida reensamblado de ruta de ejecutable. |
| *(no en comentarios proto)* | `dataArgs` | `pkg/reader/exec/exec.go:30`<br>`api.EventDataArgs` (`0x1000000`) | Argumentos transferidos por canal desacoplado de datos. | Preservar en metadata; valida reensamblado de argv. |
| *(no en comentarios proto)* | `inInitTree` | `pkg/reader/exec/exec.go:31`<br>`api.EventInInitTree` (`0x2000000`) | Proceso en el árbol init (pid=1) de su contenedor. | Correlacionar con `workload_context.in_init_tree = true`. |

### C. Flags en Comentarios del Proto NO Emitidos por `FlagStrings`

Los siguientes flags están descritos en los comentarios de `tetragon.proto`, pero **no tienen entrada en el mapa `FlagStrings`** de Tetragon v1.8.0. El normalizador Sentinel no debe esperar su aparición como tokens textuales:

| Flag en Comentarios Proto | Estado en `pkg/reader/exec/exec.go` | Motivo Técnico / Procedencia |
| :--- | :--- | :--- |
| `truncFilename` | **NO EMITIDO en FlagStrings** | No está en el mapa `FlagStrings`. En v1.8.0, el truncamiento de nombre se reporta mediante otros mecanismos o errorFilename. |
| `taskWalk` | **NO EMITIDO en FlagStrings** | Flag conceptual de depuración de recorrido de jerarquía; no se serializa como token de texto en v1.8.0. |
| `needsAUID` | **NO EMITIDO en FlagStrings** | Flag interno del hook eBPF de kernel (`api.EventNeedsAUID`). Nunca viaja al userspace. |
| `needsCWD` | **NO EMITIDO en FlagStrings** | Flag interno del hook eBPF (`api.EventNeedsCWD = 0x400`). Indica resolución pendiente dentro del probe, no en userspace. |
| `unknown` | **NO EMITIDO en FlagStrings** | Proceso ausente de caché interna. Tetragon emite el evento con campos mínimos (`pid`, `start_time`), sin token `unknown`. |

> [!IMPORTANT]
> La tabla anterior **no debe considerarse cerrada ni garantía universal**: Tetragon evoluciona entre versiones y sus flags son metadatos de depuración heurísticos. El normalizador Sentinel debe tratar cualquier token no reconocido en `process.flags` como metadato informativo opaco (`UNKNOWN_DEBUG_FLAG`), sin alterar la validez estructural del evento.

### D. Tabla de Valores de `arguments_capture_status` (R2.2)

| Valor | Condición de Activación | Implicación |
| :--- | :--- | :--- |
| `"CAPTURED_EXACT"` | Sensor capturó `argv[]` como vector estructurado de punteros (no disponible en base v1.8.0). | Fidelidad máxima. `argv` array presente. |
| `"RAW_STRING_ONLY"` | `arguments` presente en JSON, sin flags de error ni truncamiento. | String concatenado. `argv = null`. |
| `"TRUNCATED"` | Token `truncArgs` activo en `process.flags`. | Argumentos incompletos. Evidencia degradada. |
| `"UNAVAILABLE_PARENT_MISS"` | Token `miss` activo en `process.flags`. | Args no disponibles por fallo de caché del padre. No es pérdida de ring buffer. |
| `"EMPTY_STRING_OR_NO_ARGS"` | `arguments` ausente en JSON (proto3 empty string), sin flags de error. | Proceso sin argumentos o Tetragon reportó cadena vacía. |
| `"CAPTURE_ERROR"` | Token `errorArgs` activo en `process.flags`. | Error del probe. Datos no confiables. |

### E. Tabla de Valores de `working_dir_capture_status` (R2.2)

| Valor | Condición de Activación |
| :--- | :--- |
| `"PRESENT"` | `cwd` presente como string no vacío en JSON, sin flags conflictivos. |
| `"ROOT_CWD_INFERRED"` | Token literal `rootcwd` activo; `cwd` ausente del buffer pero se sabe que es `/`. |
| `"REMOVED_BUFFER_FULL"` | Token literal `nocwd` activo; `cwd` retirado por limitaciones del buffer. |
| `"PROTO3_EMPTY_STRING"` | `cwd` ausente en JSON (string vacío), sin flags explicativos. Causa indeterminada. |
| `"CAPTURE_ERROR"` | Token literal `errorCWD` activo. |
| `"PATH_RESOLUTION_ERROR"` | Token literal `errorPathResolutionCwd` activo. |

---

## 6. Modelo de Métricas de Pérdida con Estados Discriminados

Se abandona el modelo de contadores inicializados arbitrariamente en `0`. Cada métrica de pérdida porta un campo `state` que describe honestamente el estado de instrumentación:

| Estado | Semántica |
| :--- | :--- |
| `"MEASURED"` | El contador fue incrementado activamente por un mecanismo de instrumentación confirmado. |
| `"ZERO_OBSERVED"` | El contador fue leído de una fuente real y devolvió cero durante el período de observación. |
| `"UNAVAILABLE"` | El mecanismo de instrumentación existe en la especificación del sensor pero no está expuesto en esta configuración. |
| `"NOT_APPLICABLE"` | La métrica no tiene sentido semántico en el transporte actual (ej. `grpc_transport` en `JSON_FILE_STREAM`). |
| `"UNKNOWN"` | No se pudo determinar si el mecanismo existe, está activo o fue invocado. |

---

## 7. Manejo de Capacidades Opcionales de Tetragon v1.8.0

1. **Namespaces de Proceso (`--enable-process-ns`):**
   - Si está inactivo (configuración base auditada): `process_namespaces.capture_status = "UNAVAILABLE_IN_BASE_SENSOR"`, con `pid_ns: null`, `mnt_ns: null`, `net_ns: null`.
   - Se prohíbe sustituir namespaces ausentes por `"0"` — el namespace cero no existe en producción.
   - Si está activo: se mapean los inodos de namespace (`Namespace.inum`, tipo de origen `uint32` en proto) representados como cadenas decimales en el contrato v2.
   - **Disponibilidad:** La documentación de Tetragon especifica `--enable-process-ns` para eventos `process_exec` y `process_kprobe`. **No se promete disponibilidad equivalente en `process_exit`** sin evidencia experimental adicional.

2. **Credenciales Extendidas (`--enable-process-cred`):**
   - Si está inactivo: `credentials_capture_status = "EFFECTIVE_ONLY"`, `euid = process.uid`, `ruid = null`.
   - Si está activo: se extraen `ruid`, `rgid`, `suid`, `fsuid` desde `ProcessCredentials`.

3. **Cgroups — Distinción de Tres Conceptos Incompatibles:**

   > [!CAUTION]
   > **PROHIBICIÓN ABSOLUTA DE ENRIQUECIMIENTO ASÍNCRONO:** Leer `/proc/PID/cgroup` de forma asíncrona en el instante del `process_exec` introduce una carrera TOCTOU (Time-Of-Check-Time-Of-Use). El PID puede haber muerto, sido reusado o migrado a otro cgroup entre el instante del evento del kernel y la lectura de `/proc`. Esta práctica queda **eliminada permanentemente** del diseño.

   Los tres conceptos relacionados con cgroups que Tetragon v1.8.0 puede exponer son **semánticamente distintos e incompatibles**. No deben ser confundidos ni sustituidos entre sí:

   | Concepto | Proto v1.8.0 | Semántica | Mapeo en Event Contract v2 | Estado |
   | :--- | :--- | :--- | :--- | :--- |
   | **Cgroup namespace inode** | `Namespaces.cgroup` → `Namespace { inum uint32, is_host bool }` (`--enable-process-ns`) | Número de inodo del **namespace de cgroup** del proceso — identifica el espacio de nombres de aislamiento, **no** el cgroup ID ni su path. | `process_namespaces.cgroup_ns_inum` | `"UNAVAILABLE_IN_BASE_SENSOR"` sin `--enable-process-ns` |
   | **Cgroup ID** | No existe campo en tetragon.proto v1.8.0 | Identificador numérico del cgroup al que pertenece el proceso (de `cgroupfs`). **No exportado por Tetragon v1.8.0 base.** | `workload_context.cgroup_id` | `null`, `capture_status: "NOT_EXPORTED_BY_SENSOR"` |
   | **Cgroup path** | No existe campo en tetragon.proto v1.8.0 | Ruta jerárquica del cgroup (ej. `/system.slice/tetragon.service`). **No exportado por Tetragon v1.8.0 base.** | `workload_context.cgroup_path` | `null`, `capture_status: "NOT_EXPORTED_BY_SENSOR"` |

   **Reglas normativas:**
   - `workload_context.cgroup_id = null` con `capture_status = "NOT_EXPORTED_BY_SENSOR"` — siempre, en configuración base auditada.
   - `workload_context.cgroup_path = null` con `capture_status = "NOT_EXPORTED_BY_SENSOR"` — siempre, en configuración base auditada.
   - `process_namespaces.cgroup_ns_inum`: disponible solo con `--enable-process-ns`; si inactivo, `null` con `capture_status = "UNAVAILABLE_IN_BASE_SENSOR"`.
   - Fuente: `tetragon.proto` v1.8.0, mensaje `Namespaces` (campo 10 de `Process`), mensaje `Namespace`.

---

## 8. Cobertura Completa de Campos del Mensaje `Process` (R2.2-08)

Clasificación exhaustiva de los 21 campos del mensaje `Process` en `tetragon.proto` v1.8.0 (líneas 200–308):

| Campo Proto | Tag | Tipo Proto | Decisión Sentinel v2 | Justificación Normativa |
| :--- | :--- | :--- | :--- | :--- |
| `exec_id` | 1 | `string` scalar | **`MAP`** | Clave primaria opaca del nodo en el grafo causal. |
| `pid` | 2 | `UInt32Value` wrapper | **`MAP`** | PID efímero del kernel. `null` si wrapper nil. |
| `uid` | 3 | `UInt32Value` wrapper | **`MAP`** | Effective UID (`ProcessCredentials.euid`). `null` si nil. |
| `cwd` | 4 | `string` scalar | **`MAP`** | Directorio de trabajo, correlacionado con tokens literales `rootcwd`/`nocwd`. |
| `binary` | 5 | `string` scalar | **`MAP`** | Ruta del ejecutable. `FATAL` si vacío. |
| `arguments` | 6 | `string` scalar | **`MAP`** | Argumentos crudos sin split. `arguments_raw`. |
| `flags` | 7 | `string` scalar | **`MAP`** | Preservado como metadato heurístico de depuración en `sensor_metadata.debug_process_flags`. |
| `start_time` | 8 | `Timestamp` message | **`MAP`** | Tiempo de inicio de ejecución reportado por Tetragon. |
| `auid` | 9 | `UInt32Value` wrapper | **`MAP`** | Audit UID. `null` si nil. Preservado en `sensor_metadata.debug_auid`. |
| `pod` | 10 | `Pod` message | **`DROP_BY_DESIGN`** | Metadatos de Kubernetes Pod (labels, namespace, container). En el alcance de host Linux de Sentinel Runtime no aplican; se declaran `null` en `workload_context.k8s_metadata`. |
| `docker` | 11 | `string` scalar | **`DROP_BY_DESIGN`** | Documentado en proto como: `"The 15 first digits of the container ID."` **Es un prefijo truncado de 15 caracteres, NO un identificador completo de contenedor**. Sentinel prohíbe taxativamente usar identificadores truncados como identidad de workload. Se declara `container_id = null`. |
| `parent_exec_id` | 12 | `string` scalar | **`MAP`** | Clave de arista dirigida al proceso padre. |
| `refcnt` | 13 | `uint32` scalar | **`MAP`** | Contador de referencias de caché interna de Tetragon. Preservado en `sensor_metadata.debug_refcnt`. |
| `cap` | 14 | `Capabilities` message | **`UNAVAILABLE_IN_CONFIGURATION`** | Conjuntos permitted, effective, inheritable. No exportados en telemetría JSON base de Tetragon v1.8.0. |
| `ns` | 15 | `Namespaces` message | **`UNAVAILABLE_IN_CONFIGURATION`** | Inodos `uint32` de namespaces. Requiere `--enable-process-ns`. Documentado para exec/kprobe; no garantizado en exit. |
| `tid` | 16 | `UInt32Value` wrapper | **`MAP`** | Thread ID. `null` si nil. Prohibido asumir `tid = pid`. |
| `process_credentials` | 17 | `ProcessCredentials` message | **`UNAVAILABLE_IN_CONFIGURATION`** | RUID, RGID, SUID, FSUID. Requiere `--enable-process-cred`. Si activo, `ruid` se mapea; en base es `null`. |
| `binary_properties` | 18 | `BinaryProperties` message | **`DROP_BY_DESIGN`** | Metadatos binarios avanzados (setuid/setgid bits en archivo). Solo presentes en ProcessExec; no requeridos en v2 base. |
| `user` | 19 | `UserRecord` message | **`DROP_BY_DESIGN`** | Información de usuario resuelta desde `/etc/passwd`. El propio proto documenta: *"Note that this resolution happens in user-space, which means that mapping might have changed between the in-kernel BPF hook being executed and the username resolution."* Introduce carrera TOCTOU; Sentinel descarta esta resolución y confía en EUID/RUID del kernel. |
| `in_init_tree` | 20 | `BoolValue` wrapper | **`MAP`** | Preservado como booleano en `workload_context.in_init_tree`. `null` si wrapper nil. |
| `environment_variables` | 21 | `repeated EnvVar` message | **`DROP_BY_DESIGN`** | Variables de entorno del proceso. Omitidas por diseño en el contrato base para evitar fugas de credenciales/secretos en logs forenses. |
