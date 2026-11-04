# SENTINEL RUNTIME — SENSOR TAMPERING MODEL 001
## Sensor Manipulation, Observability Loss & Anti-Tampering Defense

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/SENSOR_TAMPERING_MODEL_001.md`  
**Axioma de Integridad:**  
> *Un sensor de seguridad que es manipulado o silenciado sin que el sistema lo perciba es peor que la ausencia de sensor, porque proporciona una falsa sensación de protección. Sentinel Runtime debe detectar la degradación o el cese de su capacidad de observación y tratar la pérdida de telemetría como un indicador crítico de seguridad.*

---

## 1. Modos de Falla y Vectores de Manipulación del Sensor

En un sistema basado en eBPF / Tetragon y espacio de usuario, los adversarios con privilegios (niveles A2 y A3) intentan evadir la telemetría mediante los siguientes vectores:

### 1.1 Desenganche de Sondas de Kernel (Probe Detachment)
- **Técnica:** Un atacante con privilegios administrativos o `CAP_SYS_ADMIN` en el host intenta descargar programas eBPF mediante `bpftool prog detach`, manipular enlaces BPF (`bpf_link`) o eliminar los puntos de enganche de kprobes y tracepoints (`fentry`/`fexit`).
- **Consecuencia:** Las syscalls se ejecutan en el kernel pero el programa eBPF no se dispara, creando un "punto ciego" total para el agente en espacio de usuario.
- **Detección Local:** Consulta periódica a través de la API de Tetragon / subsistema BPF verificando la lista de IDs de programas cargados. Si una sonda esperada desaparece, se emite inmediatamente `SENSOR_HEALTH (status: PROBE_DETACHED, severity: CRITICAL)`.

### 1.2 Eliminación o Modificación Furtiva de Políticas (Policy Tampering)
- **Técnica:** Modificación de archivos de configuración de TracingPolicies en disco (`/etc/tetragon/tetragon.conf.d/`) o llamadas a la API de Tetragon para deshabilitar selectivamente el monitoreo de redes o syscalls de apertura de archivos.
- **Consecuencia:** El daemon de Tetragon sigue vivo y reportando latidos, pero las reglas ya no capturan los eventos del atacante.
- **Detección Local:** Verificación criptográfica periódica del hash SHA-256 de las políticas activas en kernel frente a una especificación de referencia firmada. Discrepancia dispara `SENSOR_HEALTH (status: POLICY_TAMPERED)`.

### 1.3 Saturación Deliberada del Ring Buffer (Ring Buffer Overflow)
- **Técnica:** El adversario ejecuta un bucle cerrado de syscalls benignas ultrarrápidas (ej. millones de llamadas a `getpid()`, `stat()` o `open()` sobre archivos inexistentes) para saturar la cola en memoria compartida (BPF ring buffer / perf buffer).
- **Consecuencia:** Los eventos maliciosos reales se mezclan y se pierden en el kernel debido a desbordamiento de búfer (`dropped_events_ring_buffer > 0`).
- **Detección Local:** Monitoreo constante de los contadores del kernel exportados en `loss_metrics`. Si se incrementan los eventos descartados, transiciona inmediatamente a `OBSERVABILITY_DEGRADED`.

### 1.4 Desconexión del Stream gRPC / Bloqueo de Sockets Locales
- **Técnica:** Manipulación de reglas de firewall local (`iptables`/`nftables`) o cierre del socket UNIX local de comunicación entre Tetragon y Sentinel Runtime.
- **Consecuencia:** Tetragon opera en kernel pero los eventos no llegan al agente en espacio de usuario.
- **Detección Local:** Detección de error de transporte gRPC `UNAVAILABLE` o cese de eventos de stream por más de 3 segundos. Transiciona a `SENSOR_UNAVAILABLE`.

### 1.5 Terminación Violenta del Proceso Agente (`kill -9`)
- **Técnica:** El adversario con privilegios de root mata el proceso de Sentinel Runtime.
- **Límite Teórico Fundamental:** **El proceso terminado no puede auto-reportar su muerte.**
- **Requisito Obligatorio:** Requiere un **observador externo independiente** (Watchdog local o Sentinel Cloud).

---

## 2. Taxonomía Rigurosa de Estados de Supervisión Externa

Para evitar acusaciones infundadas de ataque ante fallas operacionales comunes, Sentinel Runtime y Sentinel Cloud diferencian formalmente los siguientes estados de supervisión:

| Estado de Supervisión | Definición Técnica | Causa Posible | Acción del Sistema |
|---|---|---|---|
| **`AGENT_UNRESPONSIVE`** | El proceso del agente en el host no responde a pings locales o IPC interno del watchdog. | Crash por OOM, deadlocks de hilo, `kill -9` de root. | Watchdog local intenta reinicio e informa anomalía. |
| **`NODE_UNREACHABLE`** | Sentinel Cloud deja de recibir latidos periódicos a través de la red externa. | Caída de red WAN, host apagado, corte de ISP. | Cloud marca nodo como no alcanzable. NO infiere compromiso malicioso automáticamente. |
| **`SENSOR_UNAVAILABLE`** | El agente está vivo, pero el daemon de Tetragon o el stream gRPC están caídos. | Tetragon crash, socket cerrado, error de kernel. | Transición local a `OBSERVABILITY_LOST`. Notificación a Cloud. |
| **`CLOUD_UNAVAILABLE`** | El agente está vivo y el sensor opera, pero no hay salida hacia Sentinel Cloud. | Partición de red, fallo del backend SaaS. | Transición a modo `STORE_AND_FORWARD` en SQLite local. |
| **`CONFIRMED_TAMPERING`** | Evidencia probatoria explícita de manipulación intencional (ej. discrepancia de hash en mapas BPF, desenganche forzado de sonda). | Adversario A3 en acción. | Alerta prioritaria máxima con evidencia forense anclada. |

---

## 3. Modos Operativos de Observabilidad y Cobertura Declarada

Se sustituye la noción no demostrable de "cobertura completa del host" por **cobertura declarada**:

```text
┌────────────────────────────────────────────────────────┐
│ 1. AGENT_ALIVE                                         │
│    Proceso de espacio de usuario activo.               │
├────────────────────────────────────────────────────────┤
│ 2. SENSOR_OPERATIONAL                                  │
│    Daemon Tetragon en ejecución con eBPF cargado.      │
├────────────────────────────────────────────────────────┤
│ 3. POLICY_OPERATIONAL                                  │
│    TracingPolicies activas y sin manipular.            │
├────────────────────────────────────────────────────────┤
│ 4. EVENT_STREAM_HEALTHY                                │
│    Canal gRPC/socket sin backpressure ni drop.         │
├────────────────────────────────────────────────────────┤
│ 5. OBSERVABILITY_HEALTHY_WITHIN_DECLARED_COVERAGE      │
│    Fuentes configuradas operativas y sin pérdida.      │
└────────────────────────────────────────────────────────┘
```

### Definición de Modos Globales de Operación:

```text
┌────────────────────────────────────────────────────────┐
│     OBSERVABILITY_HEALTHY_WITHIN_DECLARED_COVERAGE     │ ──► Cobertura declarada 100% activa. Pérdida = 0.
└───────────────────────────┬────────────────────────────┘
                            │ (Pérdida en ring buffer o latidos retrasados)
                            ▼
┌────────────────────────────────────────────────────────┐
│                 OBSERVABILITY_DEGRADED                 │ ──► Pérdida parcial cuantificada. Acciones
└───────────────────────────┬────────────────────────────┘     reversibles únicamente. Prohibido TERMINATE.
                            │ (Cese total de sensor > 5 segundos)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   OBSERVABILITY_LOST                   │ ──► Ceguera de sensor. Alerta de emergencia.
└────────────────────────────────────────────────────────┘     Fail-secure preventivo según política.
```

### Criterio de Fail-Secure vs. Fail-Open
1. **En Entornos Críticos de Producción (Fail-Secure Configurable):**
   - Si la observabilidad se pierde completamente (`OBSERVABILITY_LOST`) y existen eventos previos con sospecha activa (`TAINT`), la política de contención adaptativa puede aislar preventivamente la red del contenedor afectado para evitar una exfiltración a ciegas.
2. **En Entornos de Desarrollo / CI (Fail-Safe Auditable):**
   - El sistema no interrumpe la compilación pero marca el artefacto generado como **UNTRUSTED / UNATTESTED BUILD** debido a la falta de cobertura de observabilidad durante el ciclo de vida del proceso.
