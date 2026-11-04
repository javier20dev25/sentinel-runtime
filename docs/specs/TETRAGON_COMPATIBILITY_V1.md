# SENTINEL RUNTIME — TETRAGON COMPATIBILITY MATRIX V1 (REVISED)
**Technical Analysis: Cilium Tetragon Capabilities, Hooks & Kernel Constraints**  
*Document ID:* `SPEC-TETRAGON-V1r2`  
*Status:* `FROZEN_FOR_REVIEW`  
*Revision:* Architecture Review 001  
*Baseline Reference:* Commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Target Telemetry Engine:* Cilium Tetragon v1.0.x / v1.1.x / v1.2.x  
*Classification:* Technical Normative Contract

---

## 1. Propósito y Principio de Integración

Sentinel Runtime se integra como un motor causal y de observabilidad de capa superior, utilizando a Tetragon como su sensor de kernel primario en Linux. **Tetragon no es Sentinel Runtime.** El valor propio de Sentinel reside en la identidad contextual, la causalidad, el análisis de comportamiento, la evidencia y la coordinación con el ecosistema; no en la replicación de capacidades del sensor.

Este documento delimita estrictamente qué información puede ser provista de forma fiable por Tetragon según la versión del kernel Linux, qué hooks se requieren y cuáles son las limitaciones reales.

> **Principio Normativo:** Toda afirmación sobre Tetragon debe estar respaldada por documentación oficial o pruebas reproducibles. No se asumen capacidades no verificadas.

---

## 2. Canales de Ingesta: JSON Export vs. gRPC API

| Criterio | Exportador JSON (`JSON File Stream`) | Interfaz gRPC (`FineGuidanceSensors`) |
|---|---|---|
| **Punto de Conexión** | `/var/log/tetragon/tetragon.log` (o stdout) | `unix:///var/run/cilium/tetragon/tetragon.sock` |
| **Mecanismo de Consumo** | Lectura continua de JSON Lines con manejo de rotación de inodo. | RPC streaming `GetEvents(GetEventsRequest)`. |
| **Sobrecarga** | Media-Alta: serialización string + parseo JSON. | Baja: serialización binaria Protocol Buffers. |
| **Filtrado en Origen** | Limitado a la configuración global del demonio. | Avanzado: filtros por workload, namespace o tipo de evento. |
| **Manejo de Throttling** | Eventos de throttle como líneas JSON. | Notificaciones explícitas `RATE_LIMIT_INFO` y backpressure gRPC. |
| **Recomendación** | Laboratorio, depuración y fixtures. | **Estándar normativo para producción.** |

---

## 3. Perfiles de Compatibilidad de Kernel (AR-01)

La compatibilidad se define por capacidad, no por una versión única de kernel. Sentinel Runtime clasifica los hosts en tres perfiles operacionales:

### Perfil BASE: Observabilidad de Procesos

| Requisito | Valor | Justificación |
|---|---|---|
| Kernel Mínimo | Linux ≥ 4.19 | Tetragon documenta 4.19 como requisito mínimo de kernel. |
| CONFIG_BPF | `=y` | Soporte base de eBPF en el kernel. |
| CONFIG_BPF_SYSCALL | `=y` | Interfaz de syscall para carga de programas eBPF. |
| CONFIG_BPF_JIT | `=y` | JIT compiler para programas eBPF en runtime. |
| BTF (CONFIG_DEBUG_INFO_BTF) | **Obligatorio** | Tetragon requiere BTF para CO-RE (Compile Once — Run Everywhere). Sin `/sys/kernel/btf/vmlinux`, Tetragon **falla al iniciar** (`BTF discovery: default kernel btf file does not exist`). Distribuciones con BTF habilitado por defecto: Ubuntu 20.04+, RHEL/OL 8.6+, Amazon Linux 2023. |
| Eventos Disponibles | `PROCESS_EXEC`, `PROCESS_EXIT` | Eventos nativos estándar del sensor. |
| Hooks | kprobes estándar | Kprobes dependen de la existencia de símbolos en el kernel específico. |
| Capacidad Sentinel | Inventario de procesos, detección de binarios no catalogados, linaje padre-hijo. | |

### Perfil ADVANCED: Instrumentación de Archivos y Red

| Requisito | Valor | Justificación |
|---|---|---|
| Kernel Mínimo | Linux ≥ 5.4 (Recomendado ≥ 5.10 para LSM BPF) | Soporte maduro de kprobes en subsistemas TCP y VFS. |
| CONFIG_DEBUG_INFO_BTF | `=y` (Obligatorio) | Resolución eficiente de tipos sin cabeceras externas; necesario para TracingPolicies complejas. |
| CONFIG_BPF_LSM | `=y` (Opcional, recomendado ≥ 5.10) | Requerido para hooks en `security_file_open` que evitan TOCTOU en `sys_enter_openat`. Requiere además que `bpf` esté listado en la configuración `lsm=` del kernel. |
| TracingPolicy Requeridas | File: `sys_enter_openat`, `sys_exit_openat` (o `security_file_open` con LSM BPF). Red: `tcp_connect`, `tcp_sendmsg`, `tcp_close`. | |
| Hooks | kprobes + kretprobes | kretprobes para capturar valores de retorno de syscalls. |
| **fentry/fexit** | **NO disponible en este perfil** | **fentry/fexit requiere Linux ≥ 6.1 y BTF.** La documentación oficial de Tetragon establece este requisito. |
| Tracepoints | Preferidos sobre kprobes cuando están disponibles | Tracepoints ofrecen mayor estabilidad entre versiones de kernel según la documentación de Tetragon. |
| Capacidad Sentinel | Todo lo de BASE + monitoreo de accesos a archivos, semántica de red TCP (intentos, conexiones, transmisiones). | |

### Perfil ENFORCEMENT: Prevención y Contención en Kernel

| Requisito | Valor | Justificación |
|---|---|---|
| Kernel Mínimo | Linux ≥ 6.1 (Recomendado) | Soporte completo de fentry/fexit para captura de argumentos y retornos con mínima latencia. |
| CONFIG_DEBUG_INFO_BTF | `=y` (Obligatorio) | Necesario para todas las funcionalidades avanzadas. |
| CONFIG_BPF_LSM | `=y` (Obligatorio) | Enforcement vía políticas LSM BPF de Tetragon. |
| fentry/fexit | Disponible (solo observabilidad) | Permite captura atómica de argumentos de entrada y valores de retorno sin la penalización de kretprobes. |
| TracingPolicy con Enforcement | `sigkill`, `override` (anulación del valor de retorno) | **Enforcement requiere kprobes, no fentry.** fentry en Tetragon está limitado actualmente a observabilidad. Las acciones de prevención (`sigkill`, `override`) deben desplegarse mediante TracingPolicies basadas en kprobes. |
| Capacidad Sentinel | Todo lo de ADVANCED + contención preventiva en kernel, bloqueo de operaciones peligrosas antes de completarse. | |

### Matriz Consolidada de Capacidades por Kernel

| Capacidad | Kernel 4.19 | Kernel 5.4 | Kernel 5.10 | Kernel 5.15 | Kernel 6.1+ |
|---|:---:|:---:|:---:|:---:|:---:|
| `PROCESS_EXEC` / `PROCESS_EXIT` | ✅ | ✅ | ✅ | ✅ | ✅ |
| BTF (`/sys/kernel/btf/vmlinux`) | ⚠️ Raro | ⚠️ Opcional | ✅ Estándar | ✅ | ✅ |
| kprobes en syscalls | ✅ (si símbolos existen) | ✅ | ✅ | ✅ | ✅ |
| kretprobes (valores de retorno) | ⚠️ Limitado | ✅ | ✅ | ✅ | ✅ |
| Tracepoints | ✅ (limitados) | ✅ | ✅ | ✅ | ✅ |
| BPF LSM (`security_file_open`) | ❌ | ❌ | ✅ (con `CONFIG_BPF_LSM=y`) | ✅ | ✅ |
| **fentry / fexit** | ❌ | ❌ | ❌ | ❌ | ✅ (observabilidad) |
| Enforcement (kprobe `sigkill`/`override`) | ⚠️ Básico | ✅ | ✅ | ✅ | ✅ |
| Enforcement (fentry) | ❌ | ❌ | ❌ | ❌ | ❌ (no soportado por Tetragon) |
| BPF RingBuffer | ❌ | ❌ | ❌ | ✅ | ✅ |
| ARM64 fiabilidad | ❌ (bugs conocidos) | ❌ (bugs conocidos) | ✅ | ✅ | ✅ |
| **Perfil Sentinel** | ⚠️ BASE (si BTF existe) | ADVANCED (parcial) | ADVANCED | ADVANCED | ENFORCEMENT |

> **Corrección AR-01:** La versión anterior de esta especificación declaraba Linux 5.15 como suficiente para fentry/fexit. Esto es incorrecto según la documentación oficial de Tetragon, que establece Linux ≥ 6.1 como requisito para estas capacidades.

### Notas sobre Arquitectura de CPU
- **x86_64:** Plataforma primaria de desarrollo y pruebas de Tetragon. Máxima cobertura de hooks.
- **arm64 (aarch64):** Soportado por Tetragon; los kprobes y tracepoints disponibles pueden diferir según la compilación del kernel. Sentinel Runtime no debe asumir que la misma TracingPolicy produce resultados idénticos en ambas arquitecturas sin verificación explícita.

### Notas sobre Distribuciones Linux
- Las distribuciones enterprise (RHEL, SLES) pueden compilar el kernel sin `CONFIG_DEBUG_INFO_BTF` o `CONFIG_BPF_LSM` por defecto. Sentinel Runtime debe verificar dinámicamente la existencia de `/sys/kernel/btf/vmlinux` y los módulos LSM cargados (`cat /sys/kernel/security/lsm`) antes de desplegar TracingPolicies ADVANCED o ENFORCEMENT.

---

## 4. Catálogo de Eventos Nativos y TracingPolicies

### 4.1 Eventos Estándar Nativos (Sin TracingPolicy)

| Evento Tetragon | Código | Disponibilidad | Campos Relevantes |
|---|---|---|---|
| `PROCESS_EXEC` | 1 | Nativo (por defecto, Perfil BASE) | `process.exec_id`, `process.parent_exec_id`, `process.binary`, `process.arguments`, `process.uid`, `process.pod`, `process.docker` |
| `PROCESS_EXIT` | 5 | Nativo (por defecto, Perfil BASE) | `process.exec_id`, `process.status`, `process.signal`, `process.time` |

### 4.2 TracingPolicies para Perfil ADVANCED

#### A. Acceso a Archivos
- **Hook Primario:** `security_file_open` (Perfil ADVANCED con LSM BPF en kernel ≥ 5.10).
- **Hook Alternativo:** `sys_enter_openat` + `sys_exit_openat` (kprobes, kernel ≥ 4.19).
- **Advertencia TOCTOU:** En `sys_enter_openat`, un atacante puede manipular symlinks entre la captura de la ruta y la resolución VFS real. `security_file_open` opera después de la resolución, mitigando este riesgo.

#### B. Conexión de Red TCP
- **Hook:** `tcp_connect` (kprobe).
- **Semántica:** El kernel envía el paquete SYN. **No confirma conexión establecida.**
- **Conexiones Non-Blocking:** La aplicación puede recibir `-EINPROGRESS`. La confirmación real ocurre cuando el socket pasa a `TCP_ESTABLISHED` (observable vía `sock:inet_sock_set_state` o kprobe adicional).

#### C. Transmisión de Datos TCP
- **Hook:** `tcp_sendmsg` (kprobe en ADVANCED; fentry en ENFORCEMENT).
- **Captura de Retorno:** kretprobe (ADVANCED) o fexit (ENFORCEMENT, kernel ≥ 6.1).
- **Firma de Kernel:** `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`.
- **Limitación Crítica H-08:** Un retorno positivo de `tcp_sendmsg` solo demuestra que el kernel **aceptó bytes en su cola de transmisión** (`sk_buff`). No garantiza:
  - Que los bytes salieron de la NIC.
  - Que el host remoto los recibió.
  - Que el receptor envió un TCP ACK.
  - Que el contenido transmitido correspondía al secreto previamente leído.

#### D. Captura de Contenido de Buffers (`returnCopy`)
- Tetragon permite capturar el contenido de buffers vía `returnCopy` en TracingPolicies.
- **Limitaciones Documentadas:**
  - Solo se captura al momento del retorno de la función.
  - El tamaño de captura está limitado por configuración del sensor y restricciones del programa BPF.
  - No proporciona cobertura universal de todos los buffers de todas las aplicaciones.
  - Sentinel Runtime **no debe asumir** que puede reconstruir el contenido exacto de cada transmisión de socket.

---

## 5. Identidad de Proceso: `exec_id` (H-07)

### Contrato de Opacidad Estricta
1. `exec_id` se almacena **tal cual es entregado** por Tetragon. Sin descomposición.
2. `parent_exec_id` se utiliza para reconstruir relaciones de linaje. Sin inversión.
3. Sentinel Runtime registra adicionalmente `pid`, `tid`, `process_start_time` y `sensor_version` como metadatos de contexto.
4. Sentinel Runtime nunca reconstruye, recalcula ni depende de la fórmula interna de `exec_id`.

---

## 6. Detección de Pérdida de Eventos y Métricas de Confiabilidad (AR-04)

### 6.1 Métricas Prometheus Documentadas por Tetragon

| Métrica Tetragon | Tipo | Descripción |
|---|---|---|
| `tetragon_observer_ringbuf_events_lost_total` | Counter | Eventos perdidos por saturación del buffer de anillo eBPF en el kernel. |
| `tetragon_observer_ringbuf_queue_events_lost_total` | Counter | Eventos perdidos en la cola de eventos del observer. |
| `tetragon_bpf_missed_events_total` | Counter con etiquetas | Eventos BPF que fallaron al enviarse desde el kernel. |
| `tetragon_notify_overflowed_events_total` | Counter | Eventos descartados por overflow en la cola interna de notificaciones de Tetragon. |
| `tetragon_field_filter_failed_total` | Counter | Eventos descartados por fallos al aplicar filtros de campo. |

Estos nombres están verificados en el tag upstream v1.8.0. Esa versión también expone `tetragon_export_ratelimit_events_dropped_total` y `tetragon_events_export_failed_total`, pero pertenecen al exportador JSON y no cuentan pérdidas del stream gRPC de Sentinel. El counter `tetragon_observer_ringbuf_errors_total` es un contador de errores, no una cantidad de eventos perdidos.

### 6.2 Evento `PROCESS_THROTTLE` (Código 27)
- **Alcance Documentado:** `PROCESS_THROTTLE` se refiere al control de velocidad sobre los eventos base `PROCESS_EXEC` y `PROCESS_EXIT`. **No es un indicador universal de pérdida para todas las TracingPolicies.**
- **Regla Normativa:** Sentinel Runtime debe consumir `PROCESS_THROTTLE` como transición informativa de estado. No es un conteo de drops. `RATE_LIMIT_INFO` tiene un campo de conteo, pero el proto no define ventana ni semántica acumulativa, y el server v1.8.0 revisado no garantiza que lo emita en el stream gRPC; `sensor_throttle` queda `UNKNOWN` hasta observar un frame válido.

### 6.3 Mapeo a Contadores de Sentinel Runtime

| Fuente de Pérdida | Métrica Tetragon | Contador Sentinel `loss_metrics` |
|---|---|---|
| Buffer de anillo eBPF del kernel | `tetragon_observer_ringbuf_events_lost_total` | `ebpf_kernel` |
| Fallos de envío de eventos BPF | `tetragon_bpf_missed_events_total` | `tetragon_bpf_missed_events` |
| Overflow del listener | `tetragon_notify_overflowed_events_total` | `tetragon_listener_overflow` |
| Filtro de campos | `tetragon_field_filter_failed_total` | `tetragon_field_filter_drops` |
| Cola de eventos del observer | `tetragon_observer_ringbuf_queue_events_lost_total` | `tetragon_observer_queue_drops` |
| `RATE_LIMIT_INFO` recibido | `GetEventsResponse.rate_limit_info` | `sensor_throttle` (valor raw del frame; ventana desconocida; ausencia no implica cero) |
| Transporte gRPC (desconexión, timeout) | Reconexiones y gaps observados por Sentinel; no hay counter upstream equivalente | `grpc_transport` |
| Rotación de logs JSON | Eventos no leídos antes de truncamiento de inodo | `log_rotation` |
| Parser de Sentinel Runtime | Eventos recibidos con schema inválido o campos faltantes | `parser_reject` |
| Cola interna de Sentinel Runtime | Overflow de la cola del motor causal | `runtime_queue` |
| Persistencia SQLite | Fallos de escritura al Evidence Ledger | `storage_drop` |

> **Advertencia:** Los contadores de Tetragon son acumulativos. Sentinel calcula deltas solo si el gauge `process_start_time_seconds` prueba continuidad del proceso; un reinicio o una línea base ausente deja la ventana como desconocida. Sentinel no solicita `aggregation_options`, así que el buffer agregado opcional se omite y su dominio es `NOT_APPLICABLE` en el stream actual. Si se activa luego, hace falta añadir un counter verificable.

---

## 7. Criterios de Aceptación Verificables

- [ ] **AC-TET-01 (Opacidad):** `exec_id` consumido como string literal opaco sin alteraciones.
- [ ] **AC-TET-02 (Detección de Perfil):** Al iniciar, el adaptador debe verificar `uname -r`, `/sys/kernel/btf/vmlinux` y `/sys/kernel/security/lsm` para clasificar el host en BASE, ADVANCED o ENFORCEMENT.
- [ ] **AC-TET-03 (Red):** TracingPolicy de red captura `tcp_connect` para intentos y kretprobe/fexit de `tcp_sendmsg` para volumen de bytes.
- [ ] **AC-TET-04 (Throttling):** `PROCESS_THROTTLE` registra transiciones START/STOP; no incrementa cantidades de drops. Solo un frame `RATE_LIMIT_INFO` observado genera un conteo `sensor_throttle`, con ventana marcada desconocida.
- [ ] **AC-TET-05 (Deltas de Pérdida):** Los contadores de pérdida se evalúan por delta en ventana temporal, no por valor absoluto acumulado.
