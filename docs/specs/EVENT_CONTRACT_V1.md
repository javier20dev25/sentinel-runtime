# SENTINEL RUNTIME — EVENT CONTRACT V1
**Normative Specification & Telemetry Schema**  
*Document ID:* `SPEC-EVENT-V1`  
*Status:* `FROZEN_FOR_REVIEW`  
*Baseline Reference:* Commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Target Release:* Sentinel Runtime v1.0.0-alpha  
*Classification:* Technical Normative Contract

> **Implementation boundary:** This is a historical v1 compatibility contract. Its enforcement scenarios are design proposals, not current product behavior. The current runtime is observe-only. The v1 spelling `CAPABILITY_CHANGE` is retained for compatibility and must not be treated as proof of a capability mutation when sourced from `cap_capable`; v2 calls this family `CAPABILITY_CHECK`. See [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) and [`EVENT_CONTRACT_PROVENANCE_MATRIX.md`](./EVENT_CONTRACT_PROVENANCE_MATRIX.md).

---

## 1. Propósito y Alcance

Este documento define el contrato formal, determinista e inmutable para la representación de eventos de telemetría y seguridad en tiempo de ejecución para **Sentinel Runtime**.

El principio de diseño rector establece:  
> **El adaptador de telemetría es un transductor fiel, no una autoridad de decisión.**  
> Su responsabilidad exclusiva es capturar, normalizar y preservar la procedencia íntegra de los eventos del sistema operativo sin inferir intencionalidad maliciosa ni descartar evidencia.

Cualquier evento que ingrese al motor causal de Sentinel Runtime (`Causal Core`) debe conformar estrictamente este esquema. Los eventos malformados, truncados o con procedencia rota son rechazados o degradados explícitamente a estados de observabilidad degradada.

---

## 2. Estructura Conceptual del Evento Normalizado

El evento unificado se compone de cinco particiones ortogonales:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SENTINEL RUNTIME EVENT ENVELOPE                       │
├────────────────────────────────┬────────────────────────────────────────────┤
│ 1. Event Envelope              │ Identidad, versión, tipo y origen          │
├────────────────────────────────┼────────────────────────────────────────────┤
│ 2. Process Identity            │ exec_id opaco, parent_exec_id, pid, tid    │
├────────────────────────────────┼────────────────────────────────────────────┤
│ 3. Workload Context            │ container_id, cgroup_id, namespaces, k8s   │
├────────────────────────────────┼────────────────────────────────────────────┤
│ 4. Event Family Payload        │ Campos específicos de la familia de evento │
├────────────────────────────────┼────────────────────────────────────────────┤
│ 5. Provenance & Reliability    │ Timestamps, sensor, pérdida de eventos     │
└────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 3. Especificación Detallada de Campos

### A. Event Envelope (Metadatos Globales de Envoltura)

| Campo | Tipo | Obligatoriedad | Descripción Técnica y Reglas de Validación |
|---|---|---|---|
| `schema_version` | `string` | **Obligatorio** | Versión semver del esquema (ej. `"1.0.0"`). Debe coincidir exactamente con `^1\.[0-9]+\.[0-9]+$`. |
| `event_id` | `string` | **Obligatorio** | UUIDv7 (128 bits) ordenable temporalmente en formato canónico hexadecimal (`8-4-4-4-12`). Generado por el agente receptor si el sensor no provee uno unívoco. |
| `event_type` | `string` | **Obligatorio** | Uno de los tipos canónicos definidos en la sección **Event Families** (`EventType`). |
| `source_provider` | `string` | **Obligatorio** | Identificador del proveedor de telemetría: `"tetragon"`, `"ebpf_custom"`, `"linux_audit"`, `"synthetic_lab"`. |
| `source_event_type` | `string` | **Obligatorio** | Nombre nativo del evento reportado por el sensor (ej. `"PROCESS_EXEC"`, `"PROCESS_KPROBE"`, `"PROCESS_EXIT"`). |
| `source_event_id` | `string \| null`| **Opcional** | Identificador nativo del evento emitido por el sensor (si existe en su protocolo). |
| `host_id` | `string` | **Obligatorio** | Identificador del host físico o nodo (FQDN o hash SHA-256 de `/etc/machine-id`). |
| `boot_id` | `string` | **Obligatorio** | UUID del arranque del kernel (`/proc/sys/kernel/random/boot_id`). Inmutable durante el ciclo de vida del SO. |
| `source_timestamp` | `uint64` | **Obligatorio** | Época de captura en nanosegundos UTC proporcionada por el kernel o sensor de telemetría. |
| `observed_timestamp` | `uint64` | **Obligatorio** | Época en nanosegundos UTC en la que el ingestor de Sentinel Runtime leyó el evento. |
| `monotonic_timestamp`| `uint64 \| null`| **Condicional** | Nanosegundos `CLOCK_MONOTONIC` del kernel. Obligatorio si el proveedor es `"tetragon"`. |
| `sensor_version` | `string` | **Obligatorio** | Versión del binario del sensor (ej. `"tetragon-1.1.2"`). |
| `policy_id` | `string \| null`| **Opcional** | Identificador de la política de tracing o regla que capturó el evento (ej. `"tracingpolicy-file-sensitive"`). |
| `policy_version` | `string \| null`| **Opcional** | Hash o versión de la política activa que generó el evento. |

---

### B. Process Identity (Identidad Inmutable de Procesos)

> **REGLA DE ARQUITECTURA H-07 (TETRAGON OPACITY):**  
> El campo `exec_id` y su relación parental `parent_exec_id` entregados por Cilium Tetragon se tratan estrictamente como **identificadores opacos**. Sentinel Runtime **nunca** descompone, modifica, normaliza ni intenta recalcular la fórmula interna de `exec_id`. Se almacena de forma literal e inmutable.

| Campo | Tipo | Obligatoriedad | Descripción Técnica y Reglas de Manejo |
|---|---|---|---|
| `exec_id` | `string` | **Obligatorio** | Identificador unívoco opaco emitido por el sensor. En Tetragon es un string codificado. Si el sensor no soporta `exec_id`, el agente construye: `fallback_${boot_id}_${pid}_${start_time}` y marca `identity_quality: "DEGRADED_FALLBACK"`. |
| `parent_exec_id` | `string \| null`| **Condicional** | `exec_id` opaco del proceso padre directo. Nulo únicamente para procesos raíz (PID 1 o procesos nacidos antes del inicio del sensor). |
| `pid` | `uint32` | **Obligatorio** | Identificador de proceso en el espacio de usuario (TGID de kernel). |
| `tid` | `uint32` | **Obligatorio** | Identificador de hilo en el kernel (PID de kernel en `task_struct`). Si `pid == tid`, representa el hilo principal. |
| `process_start_time` | `uint64` | **Obligatorio** | Timestamp en nanosegundos del inicio del proceso (`start_time` en `task_struct` o nanosegundos desde boot). |
| `executable_path` | `string` | **Obligatorio** | Ruta absoluta resuelta por el sensor al archivo binario ejecutado. |
| `executable_digest` | `object \| null`| **Opcional** | Hash criptográfico del archivo binario ejecutable: `{ "algorithm": "sha256", "hex": "..." }`. |
| `uid` | `uint32` | **Obligatorio** | User ID real del proceso. |
| `euid` | `uint32` | **Obligatorio** | Effective User ID del proceso. |
| `process_namespace` | `object` | **Obligatorio** | Inodos de namespaces del proceso: `{ "pid_ns": uint64, "mnt_ns": uint64, "net_ns": uint64 }`. |
| `identity_quality` | `string` | **Obligatorio** | Calidad de la identidad: `"VERIFIED_OPAQUE"` (Tetragon nativo), `"DEGRADED_FALLBACK"` (sin `exec_id` nativo), o `"PARTIAL_ORPHAN"` (proceso existente sin padre conocido). |

**Tratamiento de Eventos con Identidad Incompleta:**  
Si un evento llega sin `exec_id` o sin `parent_exec_id` (por ejemplo, procesos preexistentes o pérdidas del probe `execve`), el ingestor asigna `identity_quality: "PARTIAL_ORPHAN"`. El motor causal prohíbe terminaciones destructivas automáticas sobre procesos con identidad huérfana parcial.

---

### C. Workload Context (Identidad y Contexto de Cargas de Trabajo)

Permite segregar inequívocamente la actividad del host, de contenedores individuales y de pods de Kubernetes:

| Campo | Tipo | Obligatoriedad | Descripción Técnica |
|---|---|---|---|
| `workload_type` | `string` | **Obligatorio** | `"HOST_PROCESS"`, `"CONTAINER"`, `"KUBERNETES_POD"`. |
| `container_id` | `string \| null`| **Condicional** | Identificador de 64 caracteres hex del runtime (Docker, containerd, CRI-O). Nulo si corre en el host. |
| `cgroup_id` | `uint64 \| string`| **Obligatorio** | Identificador numérico de inodo o ruta jerárquica del cgroup v2. |
| `mount_namespace` | `uint64` | **Obligatorio** | Inodo del `mnt_ns` (`/proc/<pid>/ns/mnt`). Clave para resolver rutas relativas en contenedor. |
| `pid_namespace` | `uint64` | **Obligatorio** | Inodo del `pid_ns` (`/proc/<pid>/ns/pid`). |
| `network_namespace` | `uint64` | **Obligatorio** | Inodo del `net_ns` (`/proc/<pid>/ns/net`). |
| `workload_id` | `string` | **Obligatorio** | Identificador lógico de perfil de Sentinel Runtime asignado al workload (ej. `"api-gateway-v2"`). |
| `k8s_metadata` | `object \| null`| **Opcional** | Metadatos de orquestación: `{ "pod_name": string, "namespace": string, "container_name": string, "pod_uid": string, "labels": object }`. |

---

### D. Event Families (Familias Canónicas de Eventos)

Se definen 14 familias normativas de eventos con semántica desacoplada:

1. `PROCESS_EXEC`: Invocación de `execve` / `execveat`. Contiene binario, argumentos completos (`args[]`), variables de entorno sensibles auditadas y credenciales de ejecución.
2. `PROCESS_EXIT`: Terminación del proceso (`exit` / `exit_group`). Contiene código de salida (`exit_code`) y señal de terminación (`signal`). Sella definitivamente la cadena del `exec_id`.
3. `FILE_OPEN_ATTEMPT`: Intento de apertura de archivo (`sys_enter_openat`, `security_file_open`). Contiene flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`) y ruta solicitada.  
   > *Regla Normativa:* `FILE_OPEN_ATTEMPT` **no** demuestra lectura ni modificación de contenido.
4. `FILE_OPEN_RESULT`: Resultado del kernel a la apertura de archivo. Contiene descriptor de archivo (`fd`) retornado o código de error negativo (`errno`).
5. `FILE_READ`: Operación efectiva de lectura sobre un descriptor (`sys_enter_read`, `readv`, o tracepoint de VFS). Contiene `fd`, `bytes_read`, offset, e inodo del archivo subyacente.
6. `NETWORK_CONNECT_ATTEMPT`: Intento de establecimiento de socket TCP/UDP (`sys_enter_connect`, hook en `tcp_connect`). Contiene socket family (`AF_INET`, `AF_INET6`), dirección destino, puerto destino y protocolo.  
   > *Regla Normativa:* `NETWORK_CONNECT_ATTEMPT` **no** demuestra conexión establecida ni transferencia de datos.
7. `NETWORK_CONNECT_RESULT`: Retorno del intento de conexión (`sys_exit_connect`, evento de handshake de Tetragon). Contiene `return_code` (`0` para éxito, `-EINPROGRESS`, `-ECONNREFUSED`, `-ETIMEDOUT`).
8. `NETWORK_SEND_ATTEMPT`: Proceso invoca syscall de transmisión (`sys_enter_sendto`, `sys_enter_write`, hook en `tcp_sendmsg`). Contiene tamaño de buffer solicitado (`bytes_requested`), socket fd y destino.
9. `NETWORK_SEND_RESULT`: Retorno de la syscall de envío en el kernel (`sys_exit_sendto`, `fexit/kretprobe` de `tcp_sendmsg`). Contiene `return_code` (número entero de bytes aceptados por la cola del socket o `-errno`).
10. `SOCKET_STATE_CHANGE`: Cambio de estado en la máquina de estados TCP del kernel (`TCP_SYN_SENT`, `TCP_ESTABLISHED`, `TCP_CLOSE`, `TCP_TIME_WAIT`).
11. `IDENTITY_CHANGE`: Modificación de credenciales de seguridad (`setuid`, `setgid`, `capset`).
12. `CAPABILITY_CHANGE` (legacy v1 spelling): compatibility family only. A `cap_capable` hook observes an authorization check; it does not prove capabilities were added or removed. Event Contract v2 uses `CAPABILITY_CHECK`.
13. `EVENT_LOSS`: Evento especial de diagnóstico emitido por el ingestor ante saturación de buffers de telemetría.
14. `SENSOR_HEALTH`: Evento periódico de latido (*heartbeat*) emitido por el daemon sensor con estadísticas operativas.

---

### E. Network Semantics & Taxonomía de Veredictos (H-08)

La semántica de red queda estrictamente estratificada. Sentinel Runtime prohíbe calificar tráfico como "exfiltración" sin pruebas verificables:

```text
[tcp_connect]           ──> OUTBOUND_ATTEMPT
                             │ (Handshake TCP en curso)
[tcp_connect == 0]      ──> OUTBOUND_ACTIVITY_OBSERVED
                             │ (Socket conectado / SYN-ACK recibido)
[tcp_sendmsg > 0 bytes] ──> OUTBOUND_TRANSFER_CORRELATED
                             │ (Bytes transferidos a destino no catalogado)
[Taint + Transfer]      ──> SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED
                             │ (Acceso sensible Y transferencia, sin procedencia verificada)
[Provenance D-03]       ──> SENSITIVE_DATA_EXFILTRATION_CONFIRMED
                             │ (Procedencia verificable del dato transmitido)
```

#### Definición Formal de Veredictos de Red (5 Niveles — AR-03):

1. `OUTBOUND_ATTEMPT`:  
   *Evidencia requerida:* Recepción de `NETWORK_CONNECT_ATTEMPT`.  
   *Significado:* La aplicación inició una petición de conexión. No implica que el socket se haya abierto ni que el host remoto responda. Incluye sockets non-blocking con `-EINPROGRESS`.  
   *Confianza Máxima:* `LOW`.  
   *Acción Permitida:* Solo registro (`RECORD_ONLY`) o incremento de telemetría (`INCREASE_LOGGING`).

2. `OUTBOUND_ACTIVITY_OBSERVED`:  
   *Evidencia requerida:* `NETWORK_CONNECT_RESULT` con `return_code == 0` o `SOCKET_STATE_CHANGE` a `TCP_ESTABLISHED`.  
   *Significado:* Conexión TCP establecida con éxito.  
   *Confianza Máxima:* `MEDIUM`.  
   *Acción Permitida:* Alerta o suspensión preventiva si el destino viola una política explícita de red.

3. `OUTBOUND_TRANSFER_CORRELATED`:  
   *Evidencia requerida:* Proceso con estado causal anómalo emite `NETWORK_SEND_RESULT` con `return_code > 0` (bytes aceptados por el kernel) hacia un host no catalogado.  
   *Significado:* Se verificó transmisión efectiva de datos a través del socket hacia un destino no autorizado. No se verifica el contenido de los bytes.  
   *Limitación Crítica:* El retorno positivo de `tcp_sendmsg` solo confirma copia a la cola de transmisión del kernel (`sk_buff`). No confirma recepción en destino ni contenido del payload.  
   *Confianza Máxima:* `MEDIUM`.  
   *Acción Permitida:* Aislamiento de red (`ISOLATE_NETWORK`) o suspensión de proceso (`SUSPEND_PROCESS`).

4. `SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED` (AR-03):  
   *Evidencia requerida (TODAS las siguientes):*  
   a) Acceso previo verificado a un recurso restringido (`FILE_READ` sobre secretos con `bytes_read > 0`).  
   b) Taint propagado a nivel `D-01` (potencial) o `D-02` (observado) en el Causal Evidence Graph.  
   c) Transmisión de bytes hacia un destino no autorizado (`NETWORK_SEND_RESULT` con `return_code > 0`).  
   *Significado:* Se observó acceso sensible Y transferencia de datos al exterior en el mismo proceso o cadena causal, pero **no se puede demostrar que los bytes transmitidos contenían el secreto leído**. El sensor de kernel no inspecciona el contenido del socket, especialmente en flujos cifrados (TLS).  
   *Confianza Máxima:* `HIGH`.  
   *Acción Permitida:* Contención preventiva y reversible: `ISOLATE_NETWORK` o `SUSPEND_PROCESS`. **No autoriza `TERMINATE_PROCESS`.**

5. `SENSITIVE_DATA_EXFILTRATION_CONFIRMED`:  
   *Evidencia requerida (TODAS las siguientes):*  
   a) Acceso previo verificado a un recurso restringido.  
   b) Relación causal `D-03` (`VERIFIED_DATA_PROVENANCE`) en el CEG: propagación verificada de taint (mismo hilo, IPC observado, o descriptor compartido con lectura confirmada).  
   c) Transmisión confirmada (`bytes_sent > 0`).  
   d) Evidencia adicional que vincule el contenido leído con la transmisión: correlación de volumen (bytes leídos ≈ bytes transmitidos en ventana temporal estrecha), hash de buffer capturado vía `returnCopy` (cuando esté disponible y el tráfico no esté cifrado), o patrón de comportamiento que excluya actividad legítima.  
   *Significado:* Exfiltración de datos sensibles demostrada con la máxima certeza disponible para un sensor de kernel. **Se reconoce que la certeza absoluta de contenido no es alcanzable sin DPI en texto plano o instrumentación de nivel de aplicación.**  
   *Confianza Máxima:* `VERIFIED` (sujeta a las limitaciones del sensor).  
   *Acción Permitida:* Contención activa (`TERMINATE_PROCESS`) bajo autorización de política explícita.

---

### F. Event Provenance & Metadatos Criptográficos

Para garantizar que un evento sea admisible en un expediente probatorio forense, debe incorporar metadatos de procedencia sin atribuir firmas locales inexistentes:

| Campo | Tipo | Obligatoriedad | Descripción Técnica |
|---|---|---|---|
| `provenance.sensor_id` | `string` | **Obligatorio** | Identificador unívoco del sensor emisor (ej. `"tetragon-daemon-node-04"`). |
| `provenance.transport_protocol`| `string` | **Obligatorio** | `"UNIX_DOMAIN_SOCKET"`, `"GRPC_TLS"`, `"JSON_FILE_STREAM"`. |
| `provenance.transport_authenticated`| `boolean`| **Obligatorio** | `true` si el canal de transporte usó autenticación mutua (mTLS o permisos de socket `0600` de root). |
| `provenance.collector_id` | `string` | **Obligatorio** | Identificador de la instancia de Sentinel Runtime que recibió el evento. |
| `provenance.ingest_timestamp` | `uint64` | **Obligatorio** | Nanosegundos de reloj del ingestor al recibir el payload crudo. |
| `provenance.raw_payload_sha256`| `string` | **Obligatorio** | Hash SHA-256 en hexadecimal del payload original crudo antes de la normalización. |

> **Nota sobre Firmas Digitales:**  
> Sentinel Runtime **no** genera una firma asimétrica en cada evento individual a nivel de sensor eBPF, ya que la sobrecarga criptográfica por syscall degradaría el rendimiento del kernel. La integridad probatoria se garantiza en la capa de almacenamiento mediante el **Evidence Ledger v1** (Hash-Chain RFC 8785 y checkpoints remotos firmados).

---

### G. Event Loss, Throttling & Confiabilidad (H-10)

El contrato define métricas independientes por subsistema para cuantificar la pérdida de telemetría:

```json
"loss_metrics": {
  "loss_ebpf_kernel": 0,
  "loss_tetragon_throttle": 0,
  "loss_grpc_transport": 0,
  "loss_log_rotation": 0,
  "loss_parser_reject": 0,
  "loss_runtime_queue": 0,
  "loss_storage_drop": 0
}
```

#### Regla de Contención ante Pérdida de Eventos:
Si en la ventana temporal $\Delta T = [t_{\text{start}}, t_{\text{now}}]$ de un proceso monitorizado se detecta cualquier incremento en los contadores de pérdida (`loss_* > 0`):
1. El motor causal **no puede emitir un veredicto destructivo** (`TERMINATE_PROCESS`) basado en supuestos de omisión.
2. El estado del workload se degrada automáticamente a `OBSERVABILITY_DEGRADED`.
3. Se genera un evento de auditoría `EVENT_LOSS` registrando el volumen y la fuente de la pérdida de telemetría.

---

## 4. Esquema JSON Formal (JSON Schema Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sentinel.security/schemas/v1/runtime-event.json",
  "title": "SentinelRuntimeEventV1",
  "type": "object",
  "required": [
    "schema_version",
    "event_id",
    "event_type",
    "source_provider",
    "source_event_type",
    "host_id",
    "boot_id",
    "source_timestamp",
    "observed_timestamp",
    "sensor_version",
    "process_identity",
    "workload_context",
    "provenance",
    "loss_metrics"
  ],
  "properties": {
    "schema_version": { "type": "string", "pattern": "^1\\.[0-9]+\\.[0-9]+$" },
    "event_id": { "type": "string", "format": "uuid" },
    "event_type": {
      "type": "string",
      "enum": [
        "PROCESS_EXEC", "PROCESS_EXIT",
        "FILE_OPEN_ATTEMPT", "FILE_OPEN_RESULT", "FILE_READ",
        "NETWORK_CONNECT_ATTEMPT", "NETWORK_CONNECT_RESULT",
        "NETWORK_SEND_ATTEMPT", "NETWORK_SEND_RESULT",
        "SOCKET_STATE_CHANGE", "IDENTITY_CHANGE", "CAPABILITY_CHANGE",
        "EVENT_LOSS", "SENSOR_HEALTH"
      ]
    },
    "source_provider": { "type": "string", "enum": ["tetragon", "ebpf_custom", "linux_audit", "synthetic_lab"] },
    "source_event_type": { "type": "string" },
    "source_event_id": { "type": ["string", "null"] },
    "host_id": { "type": "string" },
    "boot_id": { "type": "string" },
    "source_timestamp": { "type": "integer", "minimum": 0 },
    "observed_timestamp": { "type": "integer", "minimum": 0 },
    "monotonic_timestamp": { "type": ["integer", "null"] },
    "sensor_version": { "type": "string" },
    "policy_id": { "type": ["string", "null"] },
    "policy_version": { "type": ["string", "null"] },
    "process_identity": {
      "type": "object",
      "required": ["exec_id", "pid", "tid", "process_start_time", "executable_path", "uid", "euid", "process_namespace", "identity_quality"],
      "properties": {
        "exec_id": { "type": "string" },
        "parent_exec_id": { "type": ["string", "null"] },
        "pid": { "type": "integer", "minimum": 1 },
        "tid": { "type": "integer", "minimum": 1 },
        "process_start_time": { "type": "integer", "minimum": 0 },
        "executable_path": { "type": "string" },
        "executable_digest": {
          "type": ["object", "null"],
          "properties": {
            "algorithm": { "type": "string" },
            "hex": { "type": "string" }
          },
          "required": ["algorithm", "hex"]
        },
        "uid": { "type": "integer", "minimum": 0 },
        "euid": { "type": "integer", "minimum": 0 },
        "process_namespace": {
          "type": "object",
          "required": ["pid_ns", "mnt_ns", "net_ns"],
          "properties": {
            "pid_ns": { "type": "integer" },
            "mnt_ns": { "type": "integer" },
            "net_ns": { "type": "integer" }
          }
        },
        "identity_quality": { "type": "string", "enum": ["VERIFIED_OPAQUE", "DEGRADED_FALLBACK", "PARTIAL_ORPHAN"] }
      }
    },
    "workload_context": {
      "type": "object",
      "required": ["workload_type", "cgroup_id", "mount_namespace", "pid_namespace", "network_namespace", "workload_id"],
      "properties": {
        "workload_type": { "type": "string", "enum": ["HOST_PROCESS", "CONTAINER", "KUBERNETES_POD"] },
        "container_id": { "type": ["string", "null"] },
        "cgroup_id": { "type": ["string", "integer"] },
        "mount_namespace": { "type": "integer" },
        "pid_namespace": { "type": "integer" },
        "network_namespace": { "type": "integer" },
        "workload_id": { "type": "string" },
        "k8s_metadata": { "type": ["object", "null"] }
      }
    },
    "payload": { "type": "object" },
    "provenance": {
      "type": "object",
      "required": ["sensor_id", "transport_protocol", "transport_authenticated", "collector_id", "ingest_timestamp", "raw_payload_sha256"],
      "properties": {
        "sensor_id": { "type": "string" },
        "transport_protocol": { "type": "string" },
        "transport_authenticated": { "type": "boolean" },
        "collector_id": { "type": "string" },
        "ingest_timestamp": { "type": "integer" },
        "raw_payload_sha256": { "type": "string" }
      }
    },
    "loss_metrics": {
      "type": "object",
      "required": ["loss_ebpf_kernel", "loss_tetragon_throttle", "loss_grpc_transport", "loss_log_rotation", "loss_parser_reject", "loss_runtime_queue", "loss_storage_drop"],
      "properties": {
        "loss_ebpf_kernel": { "type": "integer", "minimum": 0 },
        "loss_tetragon_throttle": { "type": "integer", "minimum": 0 },
        "loss_grpc_transport": { "type": "integer", "minimum": 0 },
        "loss_log_rotation": { "type": "integer", "minimum": 0 },
        "loss_parser_reject": { "type": "integer", "minimum": 0 },
        "loss_runtime_queue": { "type": "integer", "minimum": 0 },
        "loss_storage_drop": { "type": "integer", "minimum": 0 }
      }
    }
  }
}
```

---

## 5. Ejemplos de Eventos Representativos

### Ejemplo 1: Evento Completo y Válido (`NETWORK_SEND_RESULT`)
```json
{
  "schema_version": "1.0.0",
  "event_id": "018f4a12-89b0-7d34-9214-e0b5f8842101",
  "event_type": "NETWORK_SEND_RESULT",
  "source_provider": "tetragon",
  "source_event_type": "PROCESS_KPROBE",
  "source_event_id": "9482014",
  "host_id": "worker-prod-az1-node09",
  "boot_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "source_timestamp": 1793628400123456789,
  "observed_timestamp": 1793628400125000000,
  "monotonic_timestamp": 84920491823,
  "sensor_version": "tetragon-1.1.2",
  "policy_id": "tp-tcp-sendmsg-monitor",
  "policy_version": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "process_identity": {
    "exec_id": "d29ya2VyLXByb2QtYXoxOjE4OTI4MTkyMzQ6NDAwMg==",
    "parent_exec_id": "d29ya2VyLXByb2QtYXoxOjE4OTI4MTkyMDA6NDAwMQ==",
    "pid": 4002,
    "tid": 4002,
    "process_start_time": 1793628399000000000,
    "executable_path": "/bin/bash",
    "executable_digest": {
      "algorithm": "sha256",
      "hex": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    },
    "uid": 1000,
    "euid": 1000,
    "process_namespace": {
      "pid_ns": 4026531836,
      "mnt_ns": 4026532210,
      "net_ns": 4026532215
    },
    "identity_quality": "VERIFIED_OPAQUE"
  },
  "workload_context": {
    "workload_type": "CONTAINER",
    "container_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "cgroup_id": 4096,
    "mount_namespace": 4026532210,
    "pid_namespace": 4026531836,
    "network_namespace": 4026532215,
    "workload_id": "production-api",
    "k8s_metadata": {
      "pod_name": "payment-api-7b8f9c-v28",
      "namespace": "production",
      "container_name": "api",
      "pod_uid": "f9e8d7c6-b5a4-3210-9876-543210fedcba",
      "labels": { "app": "payment", "tier": "backend" }
    }
  },
  "payload": {
    "socket_fd": 5,
    "family": "AF_INET",
    "destination_ip": "198.51.100.24",
    "destination_port": 4444,
    "protocol": "IPPROTO_TCP",
    "bytes_requested": 1024,
    "bytes_accepted_by_kernel": 1024,
    "return_code": 1024,
    "socket_state": "TCP_ESTABLISHED",
    "correlation_verdict": "OUTBOUND_TRANSFER_CORRELATED"
  },
  "provenance": {
    "sensor_id": "tetragon-daemon-node-09",
    "transport_protocol": "UNIX_DOMAIN_SOCKET",
    "transport_authenticated": true,
    "collector_id": "sentinel-runtime-agent-01",
    "ingest_timestamp": 1793628400124000000,
    "raw_payload_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
  },
  "loss_metrics": {
    "loss_ebpf_kernel": 0,
    "loss_tetragon_throttle": 0,
    "loss_grpc_transport": 0,
    "loss_log_rotation": 0,
    "loss_parser_reject": 0,
    "loss_runtime_queue": 0,
    "loss_storage_drop": 0
  }
}
```

### Ejemplo 2: Evento Incompleto con Observabilidad Degradada (`FILE_READ`)
```json
{
  "schema_version": "1.0.0",
  "event_id": "018f4a13-10ac-7111-8234-f1c2d3e4f506",
  "event_type": "FILE_READ",
  "source_provider": "tetragon",
  "source_event_type": "PROCESS_KPROBE",
  "source_event_id": "9482105",
  "host_id": "worker-prod-az1-node09",
  "boot_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "source_timestamp": 1793628405000000000,
  "observed_timestamp": 1793628405010000000,
  "monotonic_timestamp": null,
  "sensor_version": "tetragon-1.1.2",
  "policy_id": "tp-file-monitor",
  "policy_version": null,
  "process_identity": {
    "exec_id": "fallback_a1b2c3d4_8912_1793628300",
    "parent_exec_id": null,
    "pid": 8912,
    "tid": 8912,
    "process_start_time": 1793628300000000000,
    "executable_path": "/usr/bin/python3",
    "executable_digest": null,
    "uid": 0,
    "euid": 0,
    "process_namespace": {
      "pid_ns": 4026531836,
      "mnt_ns": 4026531840,
      "net_ns": 4026531845
    },
    "identity_quality": "PARTIAL_ORPHAN"
  },
  "workload_context": {
    "workload_type": "HOST_PROCESS",
    "container_id": null,
    "cgroup_id": 1,
    "mount_namespace": 4026531840,
    "pid_namespace": 4026531836,
    "network_namespace": 4026531845,
    "workload_id": "host-system-daemon",
    "k8s_metadata": null
  },
  "payload": {
    "fd": 3,
    "path": "/etc/shadow",
    "bytes_read": 512,
    "return_code": 512
  },
  "provenance": {
    "sensor_id": "tetragon-daemon-node-09",
    "transport_protocol": "JSON_FILE_STREAM",
    "transport_authenticated": false,
    "collector_id": "sentinel-runtime-agent-01",
    "ingest_timestamp": 1793628405008000000,
    "raw_payload_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  "loss_metrics": {
    "loss_ebpf_kernel": 142,
    "loss_tetragon_throttle": 15,
    "loss_grpc_transport": 0,
    "loss_log_rotation": 0,
    "loss_parser_reject": 0,
    "loss_runtime_queue": 0,
    "loss_storage_drop": 0
  }
}
```

---

## 6. Mapeo Canónico: Cilium Tetragon → Sentinel Runtime

| Evento Tetragon Nativo | EventType Sentinel Runtime | Extracción de Campos Clave | TracingPolicy Requerida |
|---|---|---|---|
| `PROCESS_EXEC` (código 1) | `PROCESS_EXEC` | `process.exec_id`, `process.parent_exec_id`, `process.binary`, `process.arguments` | Habilitado por defecto en Tetragon. |
| `PROCESS_EXIT` (código 5) | `PROCESS_EXIT` | `process.exec_id`, `process.exit_code`, `process.signal` | Habilitado por defecto en Tetragon. |
| `PROCESS_KPROBE` (`sys_enter_openat`) | `FILE_OPEN_ATTEMPT` | `args[1].string_val` (path), `args[2].int_val` (flags) | `TracingPolicy` con hook en `sys_enter_openat`. |
| `PROCESS_KPROBE` (`sys_exit_openat`) | `FILE_OPEN_RESULT` | `return_arg.int_val` (fd o `-errno`) | `TracingPolicy` con hook en `sys_exit_openat`. |
| `PROCESS_KPROBE` (`sys_enter_read`) | `FILE_READ` | `args[0].int_val` (fd), `args[2].size_val` | `TracingPolicy` con hook en `sys_enter_read`. |
| `PROCESS_KPROBE` (`tcp_connect`) | `NETWORK_CONNECT_ATTEMPT` | `sock.daddr`, `sock.dport`, `sock.family` | `TracingPolicy` con hook en `tcp_connect`. |
| `PROCESS_KPROBE` (`sys_exit_connect`) | `NETWORK_CONNECT_RESULT` | `return_arg.int_val` (`0` éxito, negativo error) | `TracingPolicy` con hook en `sys_exit_connect`. |
| `PROCESS_KPROBE` (`tcp_sendmsg`) | `NETWORK_SEND_ATTEMPT` | `sock.daddr`, `sock.dport`, `size` | `TracingPolicy` con hook en `tcp_sendmsg`. |
| `PROCESS_KPROBE` (`fexit/tcp_sendmsg`)| `NETWORK_SEND_RESULT` | `return_arg.int_val` (bytes aceptados en buffer) | `TracingPolicy` con hook `fexit` en `tcp_sendmsg`. |
| `PROCESS_THROTTLE` (código 18) | `EVENT_LOSS` | `throttle_info.count`, `throttle_info.window` | Habilitado con rate-limiting en Tetragon. |

---

## 7. Criterios de Aceptación Verificables para EVENT_CONTRACT_V1

- [ ] **AC-EV-01 (Conformidad de Esquema):** El 100% de los fixtures sintéticos y muestras reales de Tetragon deben validar sin errores contra el JSON Schema Draft 2020-12.
- [ ] **AC-EV-02 (Inmutabilidad de exec_id):** El ingestor no altera ni un solo byte de los strings `exec_id` y `parent_exec_id`.
- [ ] **AC-EV-03 (Segregación de Semántica de Red):** Ningún evento `NETWORK_CONNECT_ATTEMPT` o `NETWORK_CONNECT_RESULT` puede ser etiquetado con veredictos de exfiltración.
- [ ] **AC-EV-04 (Degradación ante Pérdida):** Si la suma de `loss_metrics > 0`, el ingestor marca `completeness: "DEGRADED"` en el sobre de telemetría.
- [ ] **AC-EV-05 (Rechazo de Procedencia Rota):** Si `raw_payload_sha256` no coincide con el digest SHA-256 del payload crudo entrante, el evento es rechazado de inmediato.
