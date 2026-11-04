# SENTINEL RUNTIME — ENGINEERING AUDIT 001 (REVISED & NORMALIZED)
**Evaluación Rigurosa de Seguridad de Sistemas, Resistencia a Evasión y Validación de Arquitectura**  
*Referencia de Commit Auditado (Baseline Inmutable):* `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Fecha de Emisión Original:* 2026-11-02  
*Fecha de Revisión Canónica:* 2026-11-02 (Revisión 002)  
*Auditor:* Principal Runtime Security Engineer / Systems Security Auditor  
*Dictamen de Auditoría:* **PROTOTIPO SINTÉTICO EN MEMORIA — NO APTO PARA PRODUCCIÓN (NOT READY FOR ENGINEERING)**  
*Condición Transversal Obligatoria:* Preservación absoluta y lectura exclusiva (read-only) de los repositorios congelados del ecosistema Sentinel (`sentinel-cloud`, `sentinel-cli`, `sentinel-oracle`, `sentinel-audit`).

---

## 1. Inventario y Trazabilidad de Capacidades Reales

A continuación se audita el estado real de cada módulo presente en el commit `fb4c5d6`:

| Capacidad Reportada | Archivo / Directorio | Estado Real | Justificación Técnica de Sistemas |
|---|---|---|---|
| **Definición de Tipos & Eventos** | `src/types.js` | **IMPLEMENTED (INCOMPLETO)** | Enumeraciones estáticas (`EventType`, `ThreatLevel`, `EnforcementAction`). Carece de contrato para telemetría de kernel (`exec_id`, `parent_exec_id`, `process_start_time`, `cgroup_id`, `mount_ns`, `bytes_sent`). |
| **Workload Profiler** | `src/profiler.js` | **STUB / VULNERABLE** | Validación por basename (`split('/').pop()`) y subcadena (`includes()`). Vulnerable a evasión por symlinks, rutas relativas no canónicas y binarios renombrados en rutas temporales. |
| **Motor Causal de Secuencias** | `src/engine.js` | **SIMULATED (EN MEMORIA)** | FSM síncrona en memoria indexada por `PID` entero simple (`Map<pid, chain>`). No maneja reciclaje de PIDs, ignora `PROCESS_EXIT`, carece de grafo de linaje multi-proceso y confunde intento de conexión con exfiltración. |
| **Evidence Ledger** | `src/evidence.js` | **STUB / VULNERABLE** | Utiliza `node:sqlite` plano con `INSERT` directo. **No existe hash encadenado**, ni serialización canónica, ni detección de manipulación de filas. Un atacante local con acceso al archivo SQLite puede reescribir o truncar la evidencia sin ser detectado. |
| **Sensor de Kernel / eBPF / Tetragon** | `pkg/sensor/` | **NO DEMOSTRADA / 0%** | Carpeta vacía en git. No existe adaptador para streams JSON o gRPC de Cilium Tetragon ni interactúa con tracepoints o kprobes. El 100% de los eventos probados son objetos JavaScript sintéticos creados en memoria. |
| **Enforcement Real sobre SO** | `pkg/enforcement/` | **SIMULATED / 0%** | Carpeta vacía en git. La función `onEnforce` en `engine.js` solo invoca un callback opcional que imprime a consola y guarda en SQLite. **No ejecuta `kill`, ni `pidfd_send_signal`, ni `SIGSTOP`, ni reglas de firewall (`nftables`)**. |
| **Autonomía Fail-Safe** | `src/engine.js` | **UNVERIFIED** | Al operar 100% en memoria local sin cliente de red ni integración con Sentinel Cloud, no existe desacoplamiento probado ante indisponibilidad remota. |

---

## 2. Autopsia Exhaustiva de Hallazgos Críticos (H-01 a H-05)

### Hallazgo H-01: Decisión Destructiva Prematura ante Intento de Conexión sin Evidencia de Exfiltración
- **Severidad Justificada:** **HIGH (Defecto de Diseño Causal) / Riesgo Operacional Crítico Latente**
- **Ubicación en Código:** `src/engine.js`, líneas 91–118
- **Fragmento de Código:**
  ```javascript
  // src/engine.js:91-108
  if (eventType === EventType.NETWORK_CONNECT) {
    const { host, port } = data;
    const isAllowed = profile.isNetworkDestinationAllowed(host, port);

    if (!isAllowed) {
      chain.stages.push('UNAUTHORIZED_EGRESS');
      chain.score += 30;

      // Si ya hay Spawn Inesperado + Lectura de Credenciales -> VIOLACIÓN CONFIRMADA
      if (chain.stages.includes('UNEXPECTED_SPAWN') && chain.stages.includes('RESTRICTED_FILE_READ')) {
        decision = {
          pid,
          workloadId,
          threatLevel: ThreatLevel.CONFIRMED_VIOLATION,
          action: EnforcementAction.TERMINATE_PROCESS,
          reason: `Cadena de Exfiltración Crítica: Spawn inesperado -> Lectura de secretos -> Conexión C2 a ${host}:${port}`
        };
      }
  ```
- **Capacidad Real Actual vs. Riesgo Futuro:**
  - *Qué hace el código actual:* Al recibir el evento sintético `NETWORK_CONNECT`, si la cadena del PID acumuló `UNEXPECTED_SPAWN` y `RESTRICTED_FILE_READ`, fija `decision.action = 'TERMINATE_PROCESS'`, asigna `threatLevel = 4` y llama a `this.onEnforce(decision)`. En los tests y labs actuales, esto únicamente imprime en consola y escribe una fila en SQLite.
  - *Qué NO puede hacer:* No envía señales POSIX, no aborta la llamada al sistema en el kernel, ni mata procesos en el sistema operativo.
  - *Riesgo Operacional Futuro:* Si se conecta un ejecutor real a `onEnforce` (e.g. `kill(pid, SIGKILL)`), cualquier handshake TCP fallido (SYN-RST, timeout, DNS erróneo) o conexión legítima de telemetría/health-check causará la muerte inmediata del proceso antes de constatar si se transmitió un solo byte de información sensible.
- **Condiciones de Reproducción:**
  - Proceso registra spawn no catalogado y lectura de archivo restringido.
  - Proceso emite evento `NETWORK_CONNECT` hacia un endpoint con 0 bytes transferidos o conexión rechazada.
- **Entrada de Prueba:**
  ```javascript
  engine.processEvent({ workloadId: 'w1', pid: 100, ppid: 1, eventType: EventType.PROCESS_EXEC, data: { binary: '/bin/sh' } });
  engine.processEvent({ workloadId: 'w1', pid: 100, ppid: 1, eventType: EventType.FILE_READ, data: { path: '/proc/self/environ' } });
  const decision = engine.processEvent({ workloadId: 'w1', pid: 100, ppid: 1, eventType: EventType.NETWORK_CONNECT, data: { host: '192.0.2.1', port: 9999 } });
  ```
- **Resultado Observado:** `decision.threatLevel === 4 (CONFIRMED_VIOLATION)` y `decision.action === 'TERMINATE_PROCESS'`.
- **Resultado Esperado de Ingeniería:** Un intento de conexión saliente no catalogada debe emitir como máximo `SUSPEND_PROCESS` o `ISOLATE_NETWORK` con retención temporal de sockets. La terminación destructiva no reversible solo debe autorizarse si se confirma transmisión efectiva de datos (`EventType.NETWORK_SEND` o telemetría eBPF de socket con `bytes_sent > 0`).

---

### Hallazgo H-02: Corrupción de Identidad y Contaminación Causal por Reutilización de PID (PID Recycling)
- **Severidad Justificada:** **HIGH (Defecto de Arquitectura de Identidad) / Riesgo de Daño Colateral Futuro**
- **Ubicación en Código:** `src/engine.js`, líneas 26–45
- **Fragmento de Código:**
  ```javascript
  // src/engine.js:32-44
  if (!this.processChains.has(pid)) {
    this.processChains.set(pid, {
      pid,
      ppid,
      workloadId,
      stages: [],
      score: 0,
      timeline: []
    });
  }

  const chain = this.processChains.get(pid);
  chain.timeline.push({ eventType, timestamp, data });
  ```
- **Capacidad Real Actual vs. Riesgo Futuro:**
  - *Qué hace el código actual:* Indexa el estado causal únicamente por el entero `pid`. No maneja `EventType.PROCESS_EXIT`, por lo que las cadenas de procesos terminados persisten indefinidamente en memoria.
  - *Qué NO puede hacer:* No interactúa con la tabla de procesos del kernel Linux ni con `pidfd`.
  - *Riesgo Operacional Futuro:* Si el sistema operativo recicla un PID (muy común en contenedores con tareas efímeras) y se conecta un ejecutor real, el nuevo proceso inocente heredará el historial malicioso del proceso extinto, siendo terminado destructivamente (`SIGKILL`) ante cualquier acción menor.
- **Condiciones de Reproducción:**
  - Proceso atacante con PID 5000 realiza `PROCESS_EXEC` y `FILE_READ`.
  - Proceso 5000 termina y se emite `PROCESS_EXIT`.
  - El sistema operativo asigna el PID 5000 a un nuevo proceso benigno que realiza una conexión saliente legítima a un host no listado en el baseline.
- **Entrada de Prueba:**
  ```javascript
  engine.processEvent({ workloadId: 'w1', pid: 5000, ppid: 1, eventType: EventType.PROCESS_EXEC, data: { binary: '/bin/sh' } });
  engine.processEvent({ workloadId: 'w1', pid: 5000, ppid: 1, eventType: EventType.FILE_READ, data: { path: '/proc/self/environ' } });
  engine.processEvent({ workloadId: 'w1', pid: 5000, ppid: 1, eventType: EventType.PROCESS_EXIT, data: {} });
  // Reutilización de PID por nuevo proceso:
  const res = engine.processEvent({ workloadId: 'w1', pid: 5000, ppid: 1, eventType: EventType.NETWORK_CONNECT, data: { host: 'api.partner.com', port: 443 } });
  ```
- **Resultado Observado:** `res.threatLevel === 4`, `res.action === 'TERMINATE_PROCESS'`, razón: `'Cadena de Exfiltración Crítica: Spawn inesperado -> Lectura de secretos -> Conexión C2...'`.
- **Resultado Esperado de Ingeniería:** La identidad debe basarse en un identificador compuesto e inmutable emitido por el sensor o kernel:
  $$\text{ProcessID} = \text{boot\_id} \mathbin{\Vert} \text{cgroup\_id} \mathbin{\Vert} \text{process\_start\_time} \mathbin{\Vert} \text{pid}$$
  (o el campo unívoco `exec_id` de Tetragon). Al recibir `PROCESS_EXIT`, la cadena activa debe sellarse y desasociarse del PID numérico.

---

### Hallazgo H-03: Evasión Trivial del Workload Profiler por Ausencia de Normalización Canónica y Verificación de Inodo
- **Severidad Justificada:** **HIGH (Vulnerabilidad de Bypass de Política de Seguridad)**
- **Ubicación en Código:** `src/profiler.js`, líneas 38–46
- **Fragmento de Código:**
  ```javascript
  // src/profiler.js:38-46
  isBinaryAllowed(binaryPath) {
    const base = binaryPath.split(/[/\\]/).pop();
    return this.allowedBinaries.has(base);
  }

  isPathRestricted(filePath) {
    const normalized = filePath.replace(/\\/g, '/');
    return this.restrictedPaths.some(restricted => normalized.includes(restricted));
  }
  ```
- **Pruebas de Reproducción y Verificación Exacta:**
  1. **Evasión por Enlace Simbólico (Symlink):**
     - *Condición:* Atacante enlaza `/app/config.json` -> `/proc/self/environ`. El sensor reporta la ruta del archivo abierto (`/app/config.json`).
     - *Entrada:* `profile.isPathRestricted('/app/config.json')`.
     - *Resultado Observado:* `false` (Evasión confirmada).
     - *Resultado Esperado:* `true` (Resolución del target real mediante `realpath` en el namespace de montaje).
  2. **Evasión por Ruta Relativa sin Prefijo `/`:**
     - *Condición:* Lectura relativa desde el directorio raíz o de trabajo: `etc/passwd` o `etc/shadow`.
     - *Entrada:* `profile.isPathRestricted('etc/passwd')`.
     - *Resultado Observado:* `false` (Evasión confirmada, pues la lista contiene `'/etc/passwd'` y `'etc/passwd'.includes('/etc/passwd')` falla por el `/` faltante).
     - *Resultado Esperado:* `true` (Normalización a ruta canónica absoluta antes de evaluar).
  3. **Comportamiento ante Directory Traversal (`..`):**
     - *Caso A:* `/app/../../proc/self/environ`. Resultado: `true` (coincidencia fortuita de string debido a que la subcadena `/proc/self/environ` está contenida en el texto).
     - *Caso B:* `app/../etc/passwd`. Resultado: `false` (Evasión confirmada, al carecer de `/` inicial).
  4. **Evasión de Binario por Nombre Base (Basename Spoofing):**
     - *Condición:* Atacante copia `/bin/bash` o `/usr/bin/nc` a `/tmp/node` o `/dev/shm/node`.
     - *Entrada:* `profile.isBinaryAllowed('/tmp/node')`.
     - *Resultado Observado:* `true` (Evasión confirmada; el profiler solo evalúa `'node'`).
     - *Resultado Esperado:* `false` (Validación de ruta absoluta canónica y hash SHA-256 del binario ejecutable).
- **Advertencia de Sistemas sobre Namespaces:** En entornos de contenedores, la invocación de `fs.realpath()` en el host es insuficiente y potencialmente errónea, ya que las rutas dependen del `mount_ns` (`mnt`) y del `rootfs` del contenedor. La resolución canónica debe realizarse en el espacio de nombres de montaje del proceso (`/proc/<pid>/root/...`).

---

### Hallazgo H-04: Ausencia Total de Integridad Criptográfica en el Evidence Ledger
- **Severidad Justificada:** **HIGH (Defecto de Seguridad Forense y Garantía Probatoria)**
- **Ubicación en Código:** `src/evidence.js`, líneas 16–45
- **Fragmento de Código:**
  ```javascript
  // src/evidence.js:31-45
  recordIncident(decision, evidence = {}) {
    const stmt = this.db.prepare(`
      INSERT INTO incidents (timestamp, workload_id, pid, threat_level, action, reason, evidence_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(...);
  }
  ```
- **Condiciones de Reproducción:**
  - Registro de un incidente crítico en el ledger.
  - Ejecución de comandos DML (`UPDATE`, `DELETE`) directamente sobre la base de datos SQLite sin claves ni firmas.
- **Entrada de Prueba:**
  ```javascript
  const l = new EvidenceLedger(':memory:');
  l.recordIncident({ workloadId: 'w1', pid: 10, threatLevel: 4, action: 'TERMINATE_PROCESS', reason: 'Critical breach' }, {});
  l.db.exec("UPDATE incidents SET action = 'RECORD_ONLY', threat_level = 1, reason = 'Benign activity'");
  ```
- **Resultado Observado:** Los registros se modifican silenciosamente. El ledger devuelve los datos manipulados sin emitir advertencia alguna ni fallo de paridad.
- **Resultado Esperado de Ingeniería:** El ledger debe ser *tamper-evident*, implementando serialización canónica RFC 8785, secuencia monotónica, hash encadenado ($H_n = \text{SHA256}(H_{n-1} \mathbin{\Vert} \text{Record}_n \mathbin{\Vert} \text{Seq}_n)$), verificación al arranque y checkpoints exportados a un anclaje externo.

---

### Hallazgo H-05: Fragmentación del Árbol Causal en Bifurcaciones Multiproceso
- **Severidad Justificada:** **MEDIUM (Defecto de Linaje Causal en el Motor)**
- **Ubicación en Código:** `src/engine.js`, líneas 21–45
- **Fragmento de Código:**
  ```javascript
  // src/engine.js:23-43
  processEvent(event) {
    const { workloadId, pid, ppid, eventType, timestamp, data } = event;
    ...
    if (!this.processChains.has(pid)) {
      this.processChains.set(pid, { ... });
    }
    const chain = this.processChains.get(pid);
  ```
- **Distinción Técnica de Sistemas: Threads vs. Procesos:**
  - *Threads (Hilos POSIX):* Creados vía `clone()` con banderas `CLONE_THREAD | CLONE_VM`. Comparten el mismo espacio de memoria y el mismo Thread Group ID (`tgid`), que en espacio de usuario corresponde al `PID`. Si el sensor reporta `tgid`, los threads colisionan en la misma cadena; si reporta `tid`, se fragmentan.
  - *Procesos Hijos / Nietos:* Creados vía `fork()` / `execve()`. Obtienen un nuevo `PID` independiente y su `ppid` apunta al proceso padre.
- **Condiciones de Reproducción:**
  - Proceso hijo `PID 6002` (hijo de Node `PID 6001`) ejecuta `/bin/bash` y lee `/proc/self/environ`.
  - Proceso `PID 6002` bifurca un subproceso nieto `PID 6003` para ejecutar la conexión externa `malicious.com:8080`.
- **Entrada de Prueba:**
  ```javascript
  engine.processEvent({ workloadId: 'w1', pid: 6002, ppid: 6001, eventType: EventType.PROCESS_EXEC, data: { binary: '/bin/bash' } });
  engine.processEvent({ workloadId: 'w1', pid: 6002, ppid: 6001, eventType: EventType.FILE_READ, data: { path: '/proc/self/environ' } });
  const ev3 = engine.processEvent({ workloadId: 'w1', pid: 6003, ppid: 6002, eventType: EventType.NETWORK_CONNECT, data: { host: 'malicious.com', port: 8080 } });
  ```
- **Resultado Observado:** `ev3.threatLevel === 3 (SUSPICIOUS)`, `ev3.action === 'ISOLATE_NETWORK'`. La cadena crítica no se activa para el subproceso nieto.
- **Resultado Esperado de Ingeniería:** El motor debe mantener un Directed Acyclic Graph (DAG) de procesos. Al inicializar `PID 6003` con `PPID 6002`, debe heredar el contexto causal de contaminación (taint) de su ancestro, evaluando la secuencia agregada y alcanzando `ThreatLevel.CONFIRMED_VIOLATION`.

---

## 3. Matriz Canónica Definitiva de Gates de Aceptación (G0 a G10)

Esta matriz constituye el estándar único y definitivo de evaluación para Sentinel Runtime. Se eliminan todas las ambigüedades y discrepancias previas:

| Gate | Criterio Canónico Definitivo | Estado en `fb4c5d6` | Veredicto Técnico & Diagnóstico |
| :--- | :--- | :---: | :--- |
| **G0** | **Code Traceability and Baseline** | 🟡 **PASS (CONDICIONADO)** | Commit base `fb4c5d6` identificado, HEAD consistente, 0 modificaciones en archivos rastreados y ZIP correspondiente al snapshot. *(Condicionado a verificación independiente del contenido).* La falta de sensores de kernel corresponde a G6, no a G0. |
| **G1** | **Event Contract and Provenance** | ❌ **FAIL** | Los eventos carecen de metadatos de procedencia, contexto de contenedor (`cgroup`), `exec_id`, `parent_exec_id`, timestamps de kernel y firma de integridad. |
| **G2** | **Process Identity and Causal Correlation** | ❌ **FAIL** | Identidad débil basada en PID plano entero; vulnerable a PID recycling, sin soporte para DAG de linaje parental multi-proceso. |
| **G3** | **Workload Profiler Security** | ❌ **FAIL** | Vulnerable a evasión por symlinks, rutas relativas no canónicas y binarios renombrados (`basename spoofing`). |
| **G4** | **Network Semantics and Exfiltration** | ❌ **FAIL** | Confusión entre intento de conexión (`NETWORK_CONNECT`) y exfiltración de datos confirmada. No evalúa transmisión real de bytes (`NETWORK_SEND`). |
| **G5** | **Evidence Ledger Integrity** | ❌ **FAIL** | Base de datos SQLite plana sin serialización canónica, sin hash encadenado (Hash-Chain), sin verificación al arranque ni anclaje externo. |
| **G6** | **Real Linux Sensor Integration** | ❌ **FAIL** | 0% demostrado. No existe conector para exportación JSON ni cliente gRPC de Cilium Tetragon. Telemetría 100% sintética. |
| **G7** | **Safe Runtime Enforcement** | ❌ **FAIL** | Las acciones de contención solo imprimen texto a consola. No existe integración con mecanismos seguros del kernel (Tracing Policies de Tetragon, `cgroup.freeze` o `pidfd`). |
| **G8** | **Cloud Independence and Fail-Safe** | ⚠️ **UNKNOWN** | El prototipo corre desconectado pero no implementa lógica de fallo seguro (fail-secure vs fail-open) ni sincronización asíncrona ante cortes de red. |
| **G9** | **Reproducible Performance Benchmark** | ❌ **FAIL** | No existen mediciones de throughput de eventos, asignación de memoria ni latencias monotónicas (p50, p95, p99). |
| **G10**| **Documentation Accuracy** | ❌ **FAIL** | Documentación inicial atribuía al prototipo capacidades de contención activa y supervisión que no existen en el código fuente base. |

> **Condición Transversal Obligatoria:** Todos los repositorios congelados (`sentinel-cloud`, `sentinel-cli`, `sentinel-oracle`, `sentinel-audit`) permanecen intactos, en modo de solo lectura y aislados de este desarrollo.

---

## 4. Especificación Técnica de Integración con Cilium Tetragon

Para evitar la construcción redundante de un sensor eBPF desde cero, Sentinel Runtime se integrará formalmente como un motor causal desacoplado sobre **Cilium Tetragon**.

### 4.1 Modos de Ingesta: JSON Export vs. gRPC API
1. **JSON Export (`/var/log/tetragon/tetragon.log`):**
   - Tetragon exporta eventos estructurados en JSON Lines hacia el log estándar del daemon.
   - *Ventajas:* Ingesta desacoplada, sin dependencias pesadas de compilación en el agente consumidor, ideal para pipelines de lectura secuencial con contrapresión.
   - *Consideración Operacional:* La ruta canónica documentada por Tetragon es `/var/log/tetragon/tetragon.log` (o stdout en pods de Kubernetes), **no** rutas temporales en `/var/run`.
2. **gRPC API (`/var/run/cilium/tetragon/tetragon.sock`):**
   - Servicio `FineGuidanceSensors.GetEvents` expuesto sobre Unix Domain Socket.
   - *Ventajas:* Filtrado y agregación en el espacio del sensor antes de la serialización; menor overhead de CPU en hosts de alto throughput.
   - *Límites:* Requiere generación de stubs protobuf/gRPC y manejo de reconexión de sockets de transporte.

### 4.2 Tipos de Eventos Estándar y Tracing Policies Necesarias
- **Eventos Nativos Estándar:**
  - `PROCESS_EXEC` (código 1): emitido en cada `execve` / `execveat`. Contiene comando completo, binario, namespaces e identidad.
  - `PROCESS_EXIT` (código 5): emitido en la terminación del proceso (`exit` / `exit_group`). Obligatorio para cerrar la cadena causal y evitar fugas de memoria o colisiones de PID.
- **Eventos Personalizados vía TracingPolicy (CRD / Config):**
  - Para accesos a archivos: TracingPolicy enganchada a `security_file_open` o `sys_enter_openat` (`PROCESS_KPROBE`).
  - Para inicio de conexión: TracingPolicy enganchada a la llamada de kernel `tcp_connect` (`PROCESS_KPROBE`).
  - Para transmisión de datos: TracingPolicy enganchada a `tcp_sendmsg` (`PROCESS_KPROBE`), capturando el argumento de longitud (`size`) para cuantificar bytes transmitidos.

### 4.3 Identidad de Proceso Robusta vía Tetragon
Tetragon soluciona el problema de PID Recycling asignando identificadores unívocos basados en el ciclo de vida del kernel:
- **`exec_id`:** String determinista generado por Tetragon: `base64(cgroup_id + pid + process_start_time)`.
- **`parent_exec_id`:** Referencia unívoca al `exec_id` del proceso que disparó la ejecución.
Sentinel Runtime utilizará `exec_id` y `parent_exec_id` como claves primarias de correlación, eliminando completamente el Hallazgo H-02 y permitiendo la reconstrucción del DAG causal de H-05 sin ambigüedades.

### 4.4 Semántica de Red: `tcp_connect` vs. `tcp_sendmsg` vs. Transmisión Confirmada
- `tcp_connect`: Solo evidencia el intento o handshake inicial TCP (SYN enviado). Puede resultar en fallo o timeout. **No demuestra fuga de datos.**
- `tcp_sendmsg`: Evidencia que el proceso entregó un búfer de datos a la pila TCP del kernel. Demuestra volumen y momento de transmisión.
- *Transmisión Confirmada (ACK):* Ocurre cuando el host remoto acusa recibo a nivel de transporte. Requiere eventos de cambio de estado de socket (`sock:inet_sock_set_state`).
- *Criterio de Enforcement:* Para escalar a contención destructiva (`TERMINATE_PROCESS`), el motor causal debe exigir la correlación causal entre `RESTRICTED_FILE_READ` y al menos un evento `tcp_sendmsg` con volumen de bytes transferidos superior a cero.

### 4.5 Manejo de Contrapresión y Pérdida de Eventos (Event Drops)
- Los buffers de anillo eBPF (`perf_event_array` o `BPF_RINGBUF`) descartan eventos cuando la tasa de eventos excede el consumo del daemon.
- Tetragon reporta eventos de tipo `PROCESS_TRACEPOINT` con metadatos de `lost_events`.
- *Regla de Decisión:* Si el motor causal detecta que se perdieron eventos en la ventana temporal de un proceso monitorizado, no puede asumir inocencia ni aplicar heurísticas destructivas de falso positivo; debe degradar el estado a `ELEVATED_WATCH` y emitir una alerta de degradación de observabilidad.

---

## 5. Especificación del Rediseño Criptográfico del Evidence Ledger

Para garantizar que la evidencia sea admitida en auditorías forenses y no dependa de la confianza ciega en un archivo SQLite local, se establece la siguiente arquitectura:

### 5.1 Serialización Canónica
Los registros deben serializarse usando el estándar **RFC 8785 (JSON Canonicalization Scheme - JCS)**, asegurando que el orden de las claves, espacios en blanco y representación de números flotantes sean deterministas a nivel de bytes antes de computar cualquier hash.

### 5.2 Estructura de Hash-Chain Monotónica
Cada registro en el ledger incorporará campos de integridad:
- `seq`: Entero de 64 bits monotónicamente incremental ($1, 2, 3, \dots$).
- `prev_hash`: Hash SHA-256 del registro inmediatamente anterior.
- `record_hash`: Hash SHA-256 computado según:
  $$H_n = \text{SHA256}(H_{n-1} \mathbin{\Vert} \text{Seq}_n \mathbin{\Vert} \text{CanonicalBytes}(\text{Payload}_n))$$
  Para el bloque génesis ($n=1$):
  $$H_0 = \text{SHA256}(\text{"SENTINEL\_RUNTIME\_GENESIS\_BLOCK\_2026"})$$

### 5.3 Detección de Alteración y Truncamiento
- La modificación de cualquier fila previa altera su $H_n$, invalidando la cadena hasta el último registro.
- La inserción o eliminación de filas produce discontinuidades en `seq` ($\text{Seq}_n \neq \text{Seq}_{n-1} + 1$) o inconsistencia con $H_{n-1}$.
- Para detectar truncamiento (eliminación de las últimas $k$ filas por un atacante local), el sistema generará **Checkpoints Criptográficos Periódicos** que registren el par $(\text{last\_seq}, \text{last\_hash})$.

### 5.4 Procedimiento de Verificación al Arranque (`verifyLedgerIntegrity()`)
Al inicializar el servicio de Sentinel Runtime, el ledger ejecutará:
1. Lectura secuencial de todos los registros ordenados por `seq ASC`.
2. Verificación de que `seq` inicie en 1 y no existan saltos.
3. Recálculo determinista de $H_n$ utilizando $H_{n-1}$ y los bytes canónicos del registro.
4. Si se detecta cualquier discrepancia de hash o secuencia, el motor aborta la inicialización, entra en modo **FORENSIC_LOCKDOWN** y genera un informe de manipulación física de la evidencia.

### 5.5 Modelo de Amenazas y Necesidad de Anclaje Externo (External Anchoring)
- **Atacante Local No Privilegiado:** Es contenido por los permisos de archivo del sistema operativo (`chmod 600`, propietario dedicado). No puede modificar la base de datos sin detección.
- **Atacante Privilegiado (Root Compromise / Local Kernel Access):** Un atacante con privilegios de root que tome control del host puede modificar el archivo SQLite y **recalcular toda la hash-chain localmente**. Por esta razón matemática y de sistemas, **ningún hash-chain puramente local proporciona inmutabilidad absoluta**.
- **Mitigación mediante Anclaje Externo:** Sentinel Runtime transmitirá asíncronamente los checkpoints periódicos firmados hacia un servicio append-only remoto (Sentinel Cloud Evidence Vault o bucket con Object Lock / WORM). Si un atacante local altera la base de datos y recalcula los hashes locales, la discrepancia entre el $H_{\text{local}}$ y el $H_{\text{remoto}}$ revelará la manipulación de inmediato.

---

## 6. Estado del Repositorio Git y Verificación Criptográfica de Artefactos

- **HEAD Actual:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`
- **Commit Base Auditado:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`
- **Rama:** `master`
- **Estado de Trabajo (`git status --short --branch` en `sentinel-runtime`):**
  ```text
  ## master
  ?? RUNTIME_AUDIT_CORRECTION_002.md
  ?? RUNTIME_ENGINEERING_AUDIT_001.md
  ```
- **Cambios en Archivos Rastreados:** 0 staged, 0 unstaged. Todos los archivos de código fuente (`src/`, `labs/`, `test/`, `package.json`, `README.md`) permanecen 100% idénticos al commit `fb4c5d6`.
- **Investigación de Anomalía de Comando Previa:** El fallo con código de salida 1 de `git status` en la sesión anterior se debió a la ejecución del comando desde el directorio padre `c:\Users\sleyt` (directorio del usuario que no está bajo control de versiones git), en lugar de ejecutarse dentro del repositorio `c:\Users\sleyt\sentinel-runtime`. Al ingresar a la carpeta del proyecto, el repositorio se encuentra en estado limpio y consistente.
- **Verificación Criptográfica del Artefacto ZIP:**
  - *Ruta:* `C:\Users\sleyt\sentinel-runtime.zip`
  - *SHA-256:* `1F6270CB55B1B49B0DFE2EE18CAFF46C5DFEA13E864D704CA20DA80E145A1D70`
  - *Tamaño:* 10,154 bytes
  - *Contenido Verificado:* Corresponde exclusivamente al snapshot del commit base `fb4c5d6`. **No contiene los documentos de auditoría**, ya que fue empaquetado antes de la generación de los reportes.

---

## 7. Dictamen Final y Recomendación de Ingeniería

Evaluados los criterios técnicos, de sistemas operativos y de seguridad causal:

### **RECOMENDACIÓN FINAL: NOT READY FOR ENGINEERING**

**Justificación:**  
Antes de autorizar la escritura de código en la Fase 1, es imperativo cerrar y formalizar las especificaciones normativas de:
1. **Contrato Formal de Eventos v1** (incorporando `exec_id`, `parent_exec_id`, procedencia de Tetragon y métricas de red).
2. **Arquitectura Causal Determinista v1** (DAG de linaje y tratamiento de pérdida de eventos).
3. **Especificación Criptográfica del Ledger v1** (JCS RFC 8785 y protocolo de anclaje de checkpoints).

Cualquier implementación de código que preceda a la congelación de estos contratos introducirá deuda técnica y requerirá reescrituras estructurales posteriores.
