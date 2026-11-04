# SENTINEL RUNTIME — EVENT CONTRACT V2 (NORMATIVE PROPOSAL)
## SPEC-EVENT-V2r2.3: Tetragon v1.8.0 Compatibility & Lossless Telemetry Contract (Revision R2.3)

**Estado:** `NORMATIVE SPECIFICATION FOR INDEPENDENT APPROVAL (R2.3)`  
**Fecha:** 2026-11-02  
**Baseline de Referencia Inmutable:** `schemas/runtime-event-v1.schema.json` (Commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`, SHA-256 `8c58cd9661eb3e192d89a3480572486fd96fe24f5bdb3219e3053a807515cfe9`, 19,586 bytes, 652 líneas)  
**Autor:** Sentinel Runtime Engineering & Security Architecture  
**Sensor de Referencia:** Cilium Tetragon v1.8.0 (Linux eBPF en Ubuntu 26.04.1 LTS / Kernel 6.18.54.1-microsoft-standard-WSL2)  
**Dataset Empírico Certificado:** `sample_tetragon_raw_events.jsonl` (25 eventos, SHA-256 del dataset completo: `93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe`)

---

## 1. Justificación de Ruptura de Contrato (v1 $\longrightarrow$ v2)

La confrontación empírica directa de `runtime-event-v1.schema.json` contra telemetría real del kernel Linux extraída de Cilium Tetragon v1.8.0 demostró incompatibilidades estructurales y de tipos que impiden una evolución dentro de una versión menor retrocompatible (`v1.1.0`).

De acuerdo con las directivas de integridad forense y seguridad epistemológica de Sentinel Runtime:
> **"Un normalizador no debe convertir información incompleta o incierta en información aparentemente certera. Cuando los tipos o semánticas del kernel no coinciden con el esquema, se corrige el contrato mediante versionado mayor normativo (v2); se prohíbe taxativamente falsificar el dato o introducir shims sintéticos."**

### Breaking Changes Normativos respecto a v1

| Dominio | Definición en Event Contract v1 | Defecto / Imposibilidad Empírica en Kernel | Nueva Definición en Event Contract v2 (R2.3) | Impacto SemVer |
| :--- | :--- | :--- | :--- | :--- |
| **`PROCESS_EXEC.payload.arguments`** | Obligatorio como `array` de strings (`"type": "array"`). | Tetragon emite `Process.arguments` como una única cadena continua (`string`). Un `split(" ")` corrompe cadenas con comillas y espacios; un array unitario `[raw_string]` inventa límites de argv que el kernel nunca atestó. | Se separa en:<br>1. `arguments_raw`: string literal original del sensor.<br>2. `argv`: array nullable (`null` en sensor base).<br>3. `arguments_capture_status`: enum con discriminación de fidelidad. | **BREAKING CHANGE** (Sustitución de clave de array obligatorio por campos fieles). |
| **`PROCESS_EXIT.payload.exit_code`** | Obligatorio como `integer` (`"required": ["exit_code"]`). | En ProtoJSON v2 de Go, cuando `status == 0`, la clave es omitida por defecto (proto3 zero-value omission). Cuando el proceso muere por señal (`SIGKILL`, `SIGTERM`), el código de salida POSIX estándar no existe. | Se sustituye por un objeto discriminado `termination`: <br>`kind`: `"EXITED"` \| `"SIGNALED"` \| `"AMBIGUOUS"` \| `"UNKNOWN"`<br>`exit_status`: integer \| null<br>`signal_name`: string \| null<br>`status_origin`: enum de procedencia comprobada. | **BREAKING CHANGE** (Sustitución de clave escalar obligatoria por objeto discriminado). |
| **`PROCESS_EXIT.payload.signal`** | `integer` o `null` (`"type": ["integer", "null"]`). | Tetragon emite el nombre literal POSIX de la señal como string (ej. `"SIGKILL"`, `"SIGTERM"`). Forzar tablas enteras de mapeo (`SIGKILL -> 9`) introduce ambigüedades de plataforma. | `termination.signal_name` preserva la cadena literal POSIX (`string`). Se garantiza fidelidad absoluta sin conversión arbitraria. | **BREAKING CHANGE** (Cambio de tipo escalar entero a string literal). |
| **`process_identity.uid` vs `euid`** | Exigía `uid` y `euid` como enteros obligatorios. | La API de Tetragon documenta formalmente que `Process.uid` representa el Effective UID (`euid`) del kernel. El UID real (`ruid`) reside en `ProcessCredentials.uid`, no exportado en la telemetría por defecto. | `euid` es el campo primario obligatorio de privilegios DAC. `ruid` es nullable con `credentials_capture_status: "EFFECTIVE_ONLY"`. | **SEMANTIC BREAKING** (Aclaración doctrinal del campo primario). |
| **`process_namespaces` y `workload_context`** | Exigía `pid_ns`, `mnt_ns`, `net_ns` obligatorios. | Tetragon v1.8.0 base no exporta inodos de namespaces sin habilitar la flag experimental `--enable-process-ns`. Forzar su presencia obligaba a inventar `"0"`. | Se modela un objeto con `capture_status`: `"UNAVAILABLE_IN_BASE_SENSOR"` y campos `null` explícitos. Se prohíbe inventar namespaces. | **SEMANTIC BREAKING** (Flexibilización de nulabilidad declarada). |
| **Modelo de Pérdidas (`loss_metrics`)** | Contadores enteros inicializados arbitrariamente a `0`. | Imposible certificar pérdidas cero en buffers de kernel o transportes no instrumentados. Inicializar a `0` sin medir constituye una afirmación falsa. | Modelo estructurado con `state` discriminado (`MEASURED`, `ZERO_OBSERVED`, `UNAVAILABLE`, `NOT_APPLICABLE`, `UNKNOWN`) y contador nullable. | **BREAKING CHANGE** (Reestructuración de métricas a estados honestos). |
| **Transporte y Autenticación** | `transport_authenticated: true` en archivos locales. | La lectura de un archivo local JSONL no equivale a un canal autenticado criptográficamente (mTLS). | `transport_authentication: "NOT_APPLICABLE_LOCAL_FILE"`. Se desacopla DAC de autenticación de canal. | **SEMANTIC RECLASSIFICATION** (Honestidad de transporte). |

---

## 2. Event Contract v2 — Ejemplo Canónico Certificado (Línea 14 de Telemetría Real)

El siguiente evento corresponde a la normalización fiel de la **Línea 14** del dataset empírico real `sample_tetragon_raw_events.jsonl` capturado en el laboratorio WSL2 (ejecución de `/usr/bin/umount` por el proceso PID 1310):

> **Distinción Criptográfica Fundamental:**
> - **SHA-256 del Dataset Completo (25 eventos):** `93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe`
> - **SHA-256 de los Bytes Crudos de esta Línea (825 bytes):** `0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818`

```json
{
  "schema_version": "2.0.0",
  "event_id": "8f3b2a1c-9d4e-4f7b-8a2c-1e0f3b5a7c9d",
  "source_event_key": "09eda1a503c87428a06cc5f9ee7d055f3483d93f628a2163e80683884251d52d",
  "event_type": "PROCESS_EXEC",
  "source_provider": "tetragon",
  "source_event_type": "process_exec",
  
  "host_identity": {
    "host_id": "sentinel-host-prod-01",
    "boot_id": "8f5a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c",
    "node_name": "DESKTOP-KI5APP4"
  },
  
  "timestamps": {
    "source_timestamp": "1793662267642869315",
    "provider_observation_timestamp": "1793662267642869315",
    "provider_event_timestamp": null,
    "observed_timestamp": "1793662267642869315",
    "ingest_timestamp": "1793662267649000000",
    "time_precision": "NANOSECONDS",
    "_note_process_exit": "Para PROCESS_EXIT: source_timestamp = provider_event_timestamp = ProcessExit.time; provider_observation_timestamp = GetEventsResponse.time (distintos). provider_event_timestamp = null solo para PROCESS_EXEC."
  },
  
  "sensor_metadata": {
    "sensor_name": "tetragon",
    "sensor_version": "v1.8.0",
    "sensor_build": "linux-amd64",
    "collector_id": "collector-agent-local-01",
    "collector_session_id": "sess-6a1e8c9b-3f2d-4e5a-8b1c-9d0e1f2a3b4c",
    "transport_protocol": "JSON_FILE_STREAM",
    "transport_authentication": "NOT_APPLICABLE_LOCAL_FILE",
    "debug_process_flags": "execve rootcwd",
    "debug_refcnt": 0
  },
  
  "process_identity": {
    "exec_id": "REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEw",
    "parent_exec_id": "REVTS1RPUC1LSTVBUFA0OjM4NjY0MjU0NTkyMDoxMzEw",
    "pid": 1310,
    "tid": 1310,
    "process_start_time": "1793662267642871299",
    "executable_path": "/usr/bin/umount",
    "executable_digest": null,
    "euid": 0,
    "ruid": null,
    "credentials_capture_status": "EFFECTIVE_ONLY",
    "process_namespaces": {
      "capture_status": "UNAVAILABLE_IN_BASE_SENSOR",
      "pid_ns": null,
      "mnt_ns": null,
      "net_ns": null
    },
    "identity_quality": "VERIFIED_OPAQUE"
  },
  
  "workload_context": {
    "workload_type": "HOST_PROCESS",
    "workload_id": "host://sentinel-host-prod-01",
    "cgroup_path": null,
    "cgroup_id": null,
    "cgroup_capture_status": "NOT_EXPORTED_BY_SENSOR",
    "container_id": null,
    "k8s_metadata": null,
    "in_init_tree": false
  },
  
  "payload": {
    "binary": "/usr/bin/umount",
    "arguments_raw": "/tmp -c",
    "argv": null,
    "arguments_capture_status": "RAW_STRING_ONLY",
    "working_dir": "/",
    "env_sensitive": null
  },
  
  "source_cursor": {
    "source_uri": "file:///var/log/tetragon/tetragon.log",
    "device_id": 2051,
    "inode": 145829,
    "file_generation_id": 1,
    "byte_offset": 9872,
    "byte_length": 826,
    "payload_byte_length": 825,
    "delimiter_byte_length": 1,
    "raw_payload_sha256": "0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818"
  },
  
  "loss_metrics": {
    "ebpf_kernel": {
      "state": "UNAVAILABLE",
      "count": null,
      "source_reference": "bpf_perf_event_output_drops"
    },
    "sensor_throttle": {
      "state": "UNAVAILABLE",
      "count": null,
      "source_reference": "tetragon_export_queue_drops"
    },
    "grpc_transport": {
      "state": "NOT_APPLICABLE",
      "count": null,
      "source_reference": "json_file_stream_active"
    },
    "log_rotation": {
      "state": "ZERO_OBSERVED",
      "count": 0,
      "source_reference": "cursor_file_generation_tracker"
    },
    "parser_reject": {
      "state": "ZERO_OBSERVED",
      "count": 0,
      "source_reference": "collector_schema_validator"
    },
    "runtime_queue": {
      "state": "ZERO_OBSERVED",
      "count": 0,
      "source_reference": "memory_ring_buffer"
    }
  }
}
```

---

## 3. Matriz de Procedencia y Clasificación Epistemológica de Campos

Para garantizar transparencia total entre lo observado en el kernel y lo enriquecido por la infraestructura, cada campo del contrato se clasifica en una de las siguientes 5 categorías de procedencia:

| Campo en Event Contract v2 | Valor en Ejemplo | Categoría de Procedencia | Justificación / Fuente Primaria |
| :--- | :--- | :--- | :--- |
| `schema_version` | `"2.0.0"` | `CONTRACT_METADATA` | Versión formal del contrato. |
| `event_id` | `"8f3b2a1c-..."` | `COLLECTOR_GENERATED` | UUIDv4 (RFC 9562 §5.4) generado por el Collector para la instancia normalizada. |
| `source_event_key` | `"09eda1a5..."` | `DERIVED_DETERMINISTIC` | $\text{SHA256}(\text{length-prefixed}(\text{host\_id}, \text{boot\_id}, \text{exec\_id}, \text{type}, \text{ts}, \text{raw\_sha256}))$. |
| `event_type` | `"PROCESS_EXEC"` | `TETRAGON_ORIGINAL` | Mapeo 1:1 de la clave raíz `process_exec` de Tetragon. |
| `source_provider` | `"tetragon"` | `COLLECTOR_INJECTED` | Declaración de origen del adaptador. |
| `host_identity.host_id` | `"sentinel-host-prod-01"`| `HOST_CONFIGURATION` | Identificador estático aprovisionado en la configuración de Sentinel. |
| `host_identity.boot_id` | `"8f5a2b1c-..."` | `KERNEL_HOST_READ` | Leído pasivamente por Collector desde `/proc/sys/kernel/random/boot_id`. |
| `host_identity.node_name` | `"DESKTOP-KI5APP4"` | `TETRAGON_ORIGINAL` | Campo `node_name` emitido en la raíz del JSON por Tetragon. |
| `timestamps.source_timestamp` | `"1793662267642869315"` | `TETRAGON_ORIGINAL` | En EXEC: `GetEventsResponse.time`. En EXIT: `ProcessExit.time` (`provider_event_timestamp`). |
| `timestamps.provider_observation_timestamp` | `"1793662267642869315"` | `TETRAGON_ORIGINAL` | `GetEventsResponse.time` ("Timestamp at which this event was observed"). |
| `timestamps.provider_event_timestamp` | `null` (en EXEC) | `TETRAGON_ORIGINAL` | En EXIT: `ProcessExit.time` ("Date and time of the event"). Null en EXEC. |
| `timestamps.observed_timestamp` | `"1793662267642869315"` | `TETRAGON_ORIGINAL` | Alias normativo de observación (`GetEventsResponse.time`). |
| `timestamps.ingest_timestamp` | `"1793662267649000000"` | `COLLECTOR_GENERATED` | Marca de reloj local del Collector en el instante de lectura de la línea. |
| `sensor_metadata.collector_session_id` | `"sess-6a1e8c9b-..."` | `COLLECTOR_GENERATED` | UUID de ciclo de vida del proceso Collector (excluido de `source_event_key`). |
| `sensor_metadata.transport_authentication` | `"NOT_APPLICABLE_LOCAL_FILE"` | `ARCHITECTURAL_HONESTY` | Rechazo expreso de declarar `true` ante lectura de archivo local. |
| `sensor_metadata.debug_process_flags` | `"execve rootcwd"` | `TETRAGON_ORIGINAL` | Copia literal de tokens emitidos por `FlagStrings`. Indicador heurístico de depuración. |
| `sensor_metadata.debug_refcnt` | `0` | `PROTO3_SCALAR_ZERO_INFERRED` | Contador de referencias de caché interna de Tetragon. Valor 0 proto3 inferido. |
| `process_identity.exec_id` | `"REVTS1RPUC1LST..."` | `TETRAGON_ORIGINAL` | Identificador de instancia opaco emitido por el kernel eBPF de Tetragon. |
| `process_identity.euid` | `0` | `TETRAGON_ORIGINAL` | Extraído de `process.uid` de Tetragon (documentado como EUID en API v1.8.0). |
| `process_identity.ruid` | `null` | `ABSENT_IN_SENSOR` | No emitido por Tetragon base sin `--enable-process-cred`. Se preserva `null`. |
| `workload_context.cgroup_id` | `null` | `NOT_EXPORTED_BY_SENSOR` | No exportado por Tetragon v1.8.0 base. Prohibido TOCTOU asíncrono en /proc. |
| `workload_context.cgroup_path` | `null` | `NOT_EXPORTED_BY_SENSOR` | No exportado por Tetragon v1.8.0 base. Prohibido TOCTOU asíncrono en /proc. |
| `payload.arguments_raw` | `"/tmp -c"` | `TETRAGON_ORIGINAL` | Cadena continua exacta de `process.arguments`. Cero split artificial. |
| `payload.argv` | `null` | `ABSENT_IN_SENSOR` | No capturado como vector de punteros en telemetría base. Declarado `null`. |
| `payload.arguments_capture_status` | `"RAW_STRING_ONLY"` | `DERIVED_DETERMINISTIC` | Estado que atesta que solo se dispone del string concatenado original. |
| `source_cursor.byte_offset` | `9872` | `COLLECTOR_INSPECTED` | Desplazamiento en bytes del inicio de la línea 14 en el archivo. |
| `source_cursor.byte_length` | `826` | `COLLECTOR_INSPECTED` | Longitud total del frame físico incluyendo delimitador. |
| `source_cursor.payload_byte_length` | `825` | `COLLECTOR_INSPECTED` | Longitud en bytes del objeto JSON parseado (sin delimitador). |
| `source_cursor.delimiter_byte_length` | `1` | `COLLECTOR_INSPECTED` | Longitud en bytes del delimitador (`0x0a` LF = 1 byte; CRLF = 2 bytes). |
| `source_cursor.raw_payload_sha256` | `"0e9d24b9..."` | `CRYPTOGRAPHIC_PROVENANCE`| Hash SHA-256 de los 825 bytes exactos de la línea 14 (sin delimitador). |

---

## 4. Especificación Detallada de los Payloads v2

### A. Payload para `PROCESS_EXEC`
```json
{
  "binary": "/usr/bin/curl",
  "arguments_raw": "-sI https://example.com",
  "argv": null,
  "arguments_capture_status": "RAW_STRING_ONLY",
  "working_dir": "/opt/sentinel/workload",
  "env_sensitive": null
}
```

- **`arguments_raw`:** Texto literal capturado por el probe del kernel. Prohibido aplicar splits sintéticos o suposiciones de quoting.
- **`argv`:** Vector de argumentos estructurado. Es `null` a menos que una política eBPF especializada capture directamente la tabla `char *argv[]` en memoria de kernel.
- **`arguments_capture_status`:** Enum con los siguientes valores rigurosos:
  - `"CAPTURED_EXACT"`: El sensor capturó el vector original de `execve`.
  - `"RAW_STRING_ONLY"`: El sensor entregó únicamente la concatenación de argumentos como string (Tetragon v1.8.0 base).
  - `"TRUNCATED"`: Los argumentos excedieron el buffer del sensor en kernel (`truncArgs`).
  - `"UNAVAILABLE"`: Proceso sin argumentos o información no provista por el kernel.
  - `"CAPTURE_ERROR"`: Error reportado por el probe eBPF durante la captura (`errorArgs`).

### B. Payload para `PROCESS_EXIT` (Modelo Discriminado de Terminación)
Sustituye la ambigüedad del escalar `exit_code` mediante un objeto discriminado `termination`:

```json
{
  "termination": {
    "kind": "EXITED",
    "exit_status": 0,
    "signal_name": null,
    "status_origin": "PROTO3_SCALAR_ZERO_INFERRED"
  }
}
```

#### Vocabulario Canónico Normativo (Enums):
- **`termination.kind`:** `["EXITED", "SIGNALED", "AMBIGUOUS", "UNKNOWN"]`
- **`termination.status_origin`:** `["PROTO3_SCALAR_ZERO_INFERRED", "EXPLICIT_NONZERO", "NOT_APPLICABLE_SIGNALED", "CONTRADICTORY_DATA", "UNAVAILABLE", "UNVERIFIED_OMISSION_UNKNOWN"]`

#### Condiciones de Seguridad Obligatorias para la Inferencia de Cero (`PROTO3_SCALAR_ZERO_INFERRED`)
La inferencia de `exit_status = 0` no aplica por mera ausencia de claves. Solo es válida cuando el Collector acredita fehacientemente las 5 condiciones siguientes:
1. **Identidad del Proveedor Auditada:** Cilium Tetragon v1.8.0.
2. **Serialización Comprobada en Código (`pkg/encoder/encoder.go:169-174`):** El serializador JSON usa `protojson.MarshalOptions{ UseProtoNames: true }` con `EmitUnpopulated: false` por omisión, omitiendo escalares en valor cero (`status = 0`, `signal = ""`).
3. **Ausencia de Filtros de Campo (`cmd/tetragon/main.go:870,882`):** La exportación estándar a archivo inicializa `FieldFilters: nil`. No existen filtros ni máscaras gRPC que supriman campos del evento.
4. **Integridad del Pipeline de Transporte:** Ausencia de etapas intermedias de redacción, truncamiento o transformación que puedan omitir claves.
5. **Conformidad Estructural:** Estructura de evento `PROCESS_EXIT` íntegra y sin errores de framing.

Si cualquiera de estas condiciones no puede ser demostrada, la ausencia de ambos campos debe catalogarse como `UNKNOWN` con `status_origin: "UNVERIFIED_OMISSION_UNKNOWN"`.

#### Discriminación Exhaustiva de Casos:

1. **Terminación Exit Cero (Acreditada bajo las 5 Condiciones):**
   ```json
   {
     "termination": {
       "kind": "EXITED",
       "exit_status": 0,
       "signal_name": null,
       "status_origin": "PROTO3_SCALAR_ZERO_INFERRED"
     }
   }
   ```
   *Condición:* Tanto `status` como `signal` ausentes en JSON; las 5 condiciones del Collector acreditadas.

2. **Terminación Exit No-Cero (Explícita en JSON):**
   ```json
   {
     "termination": {
       "kind": "EXITED",
       "exit_status": 42,
       "signal_name": null,
       "status_origin": "EXPLICIT_NONZERO"
     }
   }
   ```
   *Condición:* Clave `"status": 42` presente explícitamente en el JSON; `signal` ausente.

3. **Terminación por Señal (ej. `SIGKILL` o `SIGTERM`):**
   ```json
   {
     "termination": {
       "kind": "SIGNALED",
       "exit_status": null,
       "signal_name": "SIGKILL",
       "status_origin": "NOT_APPLICABLE_SIGNALED"
     }
   }
   ```
   *Condición:* Clave `"signal": "SIGKILL"` presente como cadena literal; `status` ausente o 0. Se prohíbe inventar `exit_status = 0` o convertir `"SIGKILL"` a entero `1`.

4. **Terminación Contradictoria (Status > 0 Y Signal simultáneamente presentes):**
   ```json
   {
     "termination": {
       "kind": "AMBIGUOUS",
       "exit_status": 137,
       "signal_name": "SIGKILL",
       "status_origin": "CONTRADICTORY_DATA"
     }
   }
   ```
   *Condición:* Tanto `signal` como `status > 0` presentes en el JSON. Se preservan ambos valores crudos sin pérdida forense.

5. **Omisión No Acreditada (Status y Signal ausentes sin certificar condiciones 1-5):**
   ```json
   {
     "termination": {
       "kind": "UNKNOWN",
       "exit_status": null,
       "signal_name": null,
       "status_origin": "UNVERIFIED_OMISSION_UNKNOWN"
     }
   }
   ```

6. **Terminación Anómala / Corrupta:**
   ```json
   {
     "termination": {
       "kind": "UNKNOWN",
       "exit_status": null,
       "signal_name": null,
       "status_origin": "UNAVAILABLE"
     }
   }
   ```

---

## 5. Prohibición Absoluta de Shims Sintéticos y Regla de Inconvertibilidad

1. **Rechazo del Shim de Compatibilidad:**
   - Se elimina de forma permanente cualquier propuesta de adaptador bidireccional automático v2 $\to$ v1.
   - Forzar conversiones donde `arguments` se convierte en `[arguments_raw]`, `SIGKILL` se traduce a `{ exit_code: 0, signal: 1 }`, o namespaces ausentes se declaran como `"0"` constituye una **falsificación de evidencia forense**.

2. **Política `NOT_CONVERTIBLE_LOSSLESSLY`:**
   - Cualquier evento v2 que carezca de un `argv[]` capturado de forma exacta o cuya terminación no corresponda a un código de salida numérico estándar POSIX se clasifica formalmente como:
     $$\text{Status de Conversión: } \mathbf{NOT\_CONVERTIBLE\_LOSSLESSLY}$$
   - Se prohíbe que el pipeline de seguridad, el motor de correlación de amenazas o el PEP admitan conversiones con pérdidas.

3. **Vista de Diagnóstico con Pérdidas (`LOSSY_DIAGNOSTIC_PROJECTION`):**
   - Únicamente admisible para herramientas de visualización de consola o depuración humana interactiva.
   - Debe portar un encabezado obligatorio `projection_mode: "LOSSY_UNVERIFIED"` y declarar la lista explícita de campos sintéticos o degradados en `synthetic_fields: ["payload.arguments", "payload.exit_code"]`.
   - **Prohibido taxativamente su uso para enforcement, bloqueos o auditoría judicial.**

---

## 6. Reglas de Inmutabilidad y Próximos Pasos

- **`schemas/runtime-event-v1.schema.json`:** Permanece **ESTRICTAMENTE CONGELADO** en commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`.
- **`schemas/runtime-event-v2.schema.json`:** No se creará hasta que la presente especificación R2 reciba dictamen aprobatorio formal e independiente.
- **Implementación (`tetragon-normalizer.js`):** Continúa **BLOQUEADA**.
