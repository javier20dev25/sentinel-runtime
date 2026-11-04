# SENTINEL RUNTIME — FAILURE MODEL 001
## Resource Exhaustion, Infrastructure Failures & Operational Degradation

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/RUNTIME_FAILURE_MODEL_001.md`  
**Principio Operativo:**  
> *Un software de seguridad en ejecución debe estar preparado para fallar de forma predecible, segura y documentada. El agotamiento de memoria, CPU, disco o red no debe provocar bloqueos catastróficos silenciosos ni corromper la evidencia forense.*

---

## 1. Agotamiento y Presión de Memoria (Memory Exhaustion & OOM)

### 1.1 Escenarios de Presión en Espacio de Usuario (Node.js Heap)
- **Riesgo:** El atacante inyecta eventos con arrays masivos o el flujo de telemetría supera la tasa de procesamiento, causando que el proceso Node.js exceda su límite de heap (`--max-old-space-size`) y sea terminado por el OOM-Killer de Linux.
- **Mecanismos de Protección:**
  1. **Límite de Ingestión Wire (Phase 001B):** Descarte de tramas superiores a 4 MB antes de entrar al parser JSON.
  2. **Estructuras de Datos Acotadas (Sliding Window):** El Causal Evidence Graph en memoria mantiene una ventana temporal deslizante fija (por ejemplo, últimos 60 minutos de actividad de procesos o un máximo de 100,000 aristas activas). Las entidades inactivas se archivan en SQLite y se eliminan del heap.
  3. **Ajuste de Prioridad OOM (`oom_score_adj`):** El daemon de Sentinel se configura con `oom_score_adj = -900` para asegurar que el kernel prefiera terminar subprocesos de workloads antes de sacrificar el agente de seguridad.
  4. **Monitoreo Interno del Heap:** Si el uso de memoria de Node.js supera el 85% del límite asignado, el agente activa el modo de descarte controlado (`SHEDDING`), registrando `EVENT_LOSS` y reduciendo el análisis a eventos de alta severidad (`PROCESS_EXEC`, `NETWORK_CONNECT_ATTEMPT`).

---

## 2. Inanición y Presión de CPU (CPU Starvation & Throttling)

### 2.1 Escenarios de Sobrecarga de Procesador
- **Riesgo:** Un workload ejecuta cálculos criptográficos o una tormenta de procesos que satura el 100% de la CPU asignada en cgroups v2, provocando retrasos en la lectura del ring buffer eBPF y pérdida masiva de telemetría.
- **Mecanismos de Protección:**
  1. **Aislamiento de Cgroup para el Agente:** Sentinel Runtime debe ejecutarse en su propio cgroup (`system.slice/sentinel-runtime.service`) con cuota de CPU reservada (`cpu.weight: 200` o `cpu.max` garantizado), independiente del cgroup donde residen los workloads monitoreados.
  2. **Procesamiento Asíncrono no Bloqueante:** Todas las operaciones de cálculo pesado (cálculo de hashes SHA-256 de archivos en disco, serialización de reportes masivos) se delegan a `worker_threads` o se ejecutan de manera particionada para nunca bloquear el event loop principal de ingestión de eventos.

---

## 3. Almacenamiento Forense, Saturación de Disco y Retención

### 3.1 Distinción Conceptual: Tamper-Evidence vs. Availability vs. Completeness
- **Tamper-Evidence:** Capacidad de demostrar matemáticamente si un registro existente fue alterado.
- **Availability:** Capacidad de acceder al registro cuando se necesita.
- **Completeness:** Garantía de que no faltan registros intermedios en la serie histórica.

### 3.2 Protección contra Disco Lleno (ENOSPC) y Poda de Registros
- **Riesgo:** La acumulación masiva de eventos satura el sistema de archivos (`ENOSPC`), causando fallas en cascada tanto en el agente como en los workloads del host.
- **Revisión de la Poda FIFO (Eliminación de la Cota Arbitraria de 5 GB):**
  - Queda terminantemente prohibido podar bloques históricos sin garantizar la **completitud criptográfica**.
  - **Protocolo de Retención y Poda Condicionada:**
    1. Un bloque en la base de datos local SQLite WAL solo puede marcarse como elegible para purga de payload si ha recibido un acuse de recibo firmado desde Sentinel Cloud (`CONFIRMED_EXTERNAL_CHECKPOINT`).
    2. Al purgar el payload de un bloque sincronizado, **se conservan de forma permanente los metadatos del bloque y su hash SHA-256** en una tabla de cabeceras compacta (`ledger_headers`).
    3. Esto preserva la **cadena de hash ininterrumpida** en el host local, permitiendo verificar la completitud histórica sin almacenar gigabytes de payloads antiguos ya respaldados en la nube.
  3. **Spool Offline y Búfer Circular de Emergencia en RAM:**
     - Si el disco entra en condición crítica ($\ge 95\%$ de uso), las escrituras no esenciales en SQLite se pausan y los eventos críticos se mantienen en un búfer circular en memoria RAM de tamaño acotado (ej. 64 MB) mientras se emite una alerta prioritaria de almacenamiento.

---

## 4. Partición de Red e Interrupción de Conectividad (Network Partitions)

### 4.1 Escenarios de Pérdida de Conexión hacia Sentinel Cloud
- **Riesgo:** El host pierde conectividad a Internet, el atacante bloquea la salida HTTPS hacia Sentinel Cloud o el plano de control externo experimenta mantenimiento.
- **Mecanismos de Protección:**
  1. **Autonomía Operativa 100% Local:** El motor causal, la evaluación de políticas y los mecanismos de contención adaptativa operan de forma completamente autónoma en local sin requerir llamadas sincrónicas a la nube.
  2. **Cola Persistente Store-and-Forward:** Los bloques de evidencia generados se acumulan en la base de datos SQLite local en estado `PENDING_REPLICATION`.
  3. **Sincronización con Backoff Exponencial y Jitter:** Al restablecerse la conectividad, el cliente de sincronización transfiere los bloques pendientes en lotes acotados con reintentos controlados (`exponential backoff`), evitando tormentas de tráfico hacia la API de Sentinel Cloud.

---

## 5. Corrupción Forense y Fallas de I/O de Base de Datos

### 5.1 Escenarios de Apagado Forzado o Fallas de I/O
- **Riesgo:** Corte abrupto de energía, kernel panic o reinicio forzado del servidor mientras se escribía un bloque de evidencia en SQLite, arriesgando corrupción de datos (`SQLITE_CORRUPT`).
- **Mecanismos de Protección:**
  1. **Transacciones Atómicas ACID:** Cada bloque del Evidence Ledger se escribe dentro de una transacción atómica exclusiva (`BEGIN IMMEDIATE ... COMMIT`).
  2. **Integridad Verificable de Bloque:** Cada bloque contiene su propio hash SHA-256 interno y el hash del bloque predecesor. Si un bloque queda truncado por un corte eléctrico, el verificador detecta el bloque incompleto durante la secuencia de inicio y restaura el estado a partir del último bloque sellado válido.
  3. **Reporte de Anomalía:** Ante cualquier detección de bloque inconsistente tras un reinicio, se emite una alerta prioritaria de integridad hacia Sentinel Cloud indicando la recuperación forzada y el hash del punto de anclaje.
