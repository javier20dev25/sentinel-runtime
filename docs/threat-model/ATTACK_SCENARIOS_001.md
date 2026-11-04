# SENTINEL RUNTIME — ATTACK SCENARIOS 001
## Adversarial Evaluation Scenarios & Benign Control Pairs

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/ATTACK_SCENARIOS_001.md`  
**Regla Metodológica Central:**  
> *Ningún escenario de ataque se evaluará de forma aislada. Todo escenario malicioso debe contar con un escenario benigno de control equivalente que comparta ejecutables, tecnologías o llamadas al sistema similares, con el fin de medir la precisión causal de Sentinel Runtime y evitar tanto la ceguera defensiva como la destrucción de cargas de trabajo legítimas.*

---

## Taxonomía de Certeza de Atribución y Causalidad de Datos

Para evitar afirmaciones infundadas de causalidad, Sentinel Runtime clasifica la relación entre procesos y datos en cinco niveles estrictos:

1. **Linaje de Procesos (Process Lineage):** Relación genealógica verificada en kernel (`parent_tgid`, `tgid`, `start_time_ns`, `exec_id`).
2. **Relación de Recursos (Resource Relationship):** Dos procesos interactúan con el mismo recurso (mismo inodo en disco, mismo socket UNIX o pipe), sin confirmación de contenido.
3. **Propagación Potencial de Datos (Potential Data Propagation):** Un proceso heredó descriptores abiertos o memoria Copy-on-Write (COW) tras un `fork()`, pero no se ha observado una lectura explícita del recurso. No se puede afirmar que el proceso hijo utilizó el secreto únicamente por haber heredado memoria COW.
4. **Propagación Observada de Datos (Observed Data Propagation):** Se capturan eventos explícitos de `sys_read` sobre el descriptor de origen seguidos de `sys_write` hacia un canal IPC o archivo intermedio. No se puede afirmar que un archivo temporal contiene datos sensibles únicamente porque fue escrito por un proceso relacionado.
5. **Procedencia Verificada a Nivel de Bytes (Verified Byte-Level Provenance):** Se comprueba criptográficamente (hash, entropía o coincidencia exacta de secuencia) que los bytes leídos del secreto coinciden con los bytes transmitidos al exterior. (Requiere inspección profunda de payload en memoria o terminación TLS; no derivable únicamente de syscall tracing sin instrumentación adicional).

---

## Escenario 01 — Compromiso del Entorno de Desarrollo (Supply Chain)

**Técnicas MITRE ATT&CK:** T1195.001 (Compromised Software Dependencies & IDE Configurations), T1059.007 (JavaScript Execution), T1555 (Credentials from Password Stores).

### 1.1 Caso Malicioso: Infección en Hook de Instalación
- **Ground Truth:** Un paquete malicioso en `package.json` dispara `node ./scripts/postinstall.js`. Este script abre `~/.aws/credentials`, extrae las claves y las transmite vía HTTPS a un servidor remoto `198.51.100.45:443`.
- **Eventos Esperados:**
  - `PROCESS_EXEC`: `npm -> sh -> node ./scripts/postinstall.js`.
  - `FILE_OPEN_ATTEMPT` / `FILE_OPEN_RESULT`: Apertura de `~/.aws/credentials`.
  - `FILE_READ`: Lectura de bytes del archivo.
  - `NETWORK_CONNECT_ATTEMPT` / `NETWORK_CONNECT_RESULT`: Conexión a `198.51.100.45:443`.
  - `NETWORK_SEND_ATTEMPT`: Transmisión de bytes.
- **Eventos que Realmente Proporciona el Sensor (Tetragon kprobe/tracepoint):**
  - Proporciona: `execve` con argumentos completos, `sys_enter_openat` sobre la ruta del archivo sensible, `sys_enter_connect` con IP y puerto de destino.
- **Eventos Potencialmente Ausentes:**
  - `sys_read` individual (si Tetragon no tiene habilitada una TracingPolicy de lectura de I/O de alta frecuencia para evitar saturación de ring buffer).
  - Inspección del contenido de `sendto` si la conexión utiliza TLS (cifrado en espacio de usuario por Node.js/OpenSSL).
- **Evidencia Mínima Necesaria para Decisión:**
  $$\text{Linaje(postinstall)} \wedge \text{OpenAt(ruta\_secreto)} \wedge \text{Connect(IP\_no\_catalogada)}$$
- **Resultado Esperado:** **SUSPICIOUS CORRELATED EGRESS (PARTIALLY_ATTRIBUTED)**.
  - *Precisión:* Se atestigua la relación temporal y de linaje entre la apertura del secreto y la conexión externa. NO se afirma exfiltración confirmada a nivel de bytes sin payload inspection.
- **Resultado Desconocido (UNKNOWN):** Si la telemetría pierde el evento `openat` por saturación del ring buffer, la conexión de Node.js a la IP se clasifica como conexión anómala pero sin vínculo causal con secretos.
- **Par Benigno de Control 01:**
  - `npm install esbuild`: ejecuta `node install.js`, lee `package.json`, se conecta a `registry.npmjs.org` o `github.com/releases` oficiales y escribe en `./node_modules`.
- **Condiciones para NO Bloquear:** Destino dentro del repositorio oficial de paquetes, ausencia de lecturas fuera del directorio del proyecto, conformidad con el baseline del compilador.

---

## Escenario 02 — Robo de Credenciales y Abuso de Confianza (Credential Access & Exfiltration)

**Técnicas MITRE ATT&CK:** T1552.001 (Credentials In Files), T1071.001 (Web Protocols), T1078 (Valid Accounts).

### 2.1 Caso Malicioso: Búsqueda Sigilosa y Exfiltración con Retardo
- **Ground Truth:** Un worker secundario accede a `.env` y guarda variables en memoria. Tras una pausa deliberada de 15 minutos, se conecta a un webhook legítimo de Slack (`api.slack.com`) y envía los datos.
- **Eventos Esperados:**
  - `FILE_OPEN_ATTEMPT`: Acceso a `.env`.
  - Pausa temporal (inactividad en el hilo).
  - `NETWORK_CONNECT_ATTEMPT`: Conexión a Slack HTTPS.
- **Eventos que Proporciona el Sensor:** `openat` sobre `.env`, `connect` hacia IP resuelta de Slack.
- **Eventos Potencialmente Ausentes:** Trazabilidad de variables retenidas en el heap de V8/Python sin instrumentación en tiempo de ejecución.
- **Evidencia Mínima Necesaria:**
  $$\text{Entidad}(P) \text{ con marca } TAINT\_RESOURCE \wedge \text{Egress}(P, \text{Destino\_No\_Baseline})$$
- **Resultado Esperado:** **SUSPICIOUS DEFERRED EGRESS (PARTIALLY_ATTRIBUTED)**.
  - La marca de contexto persiste en el estado del proceso en el CEG. El retraso temporal no borra la procedencia.
- **Resultado Desconocido:** Si el proceso termina y otro proceso independiente realiza la conexión sin vínculo de linaje ni IPC atestado.
- **Par Benigno de Control 02:**
  - Worker de Pod de Kubernetes leyendo `/var/run/secrets/kubernetes.io/serviceaccount/token` y comunicándose con el API Server de Kubernetes en `10.96.0.1:443`.
- **Condiciones para NO Bloquear:** Destino coincide con el API Server del clúster declarado en las variables de entorno del Pod; token leído corresponde a la identidad de servicio asignada.

---

## Escenario 03 — Ataque Distribuido entre Múltiples Procesos (IPC Splitting)

**Técnicas MITRE ATT&CK:** T1559 (Inter-Process Communication), T1055 (Process Injection), T1020 (Automated Exfiltration).

### 3.1 Caso Malicioso: Fragmentación de Operaciones via Pipes / Sockets UNIX
- **Ground Truth:** Proceso A lee `~/.ssh/id_rsa`, escribe a través de un pipe a Proceso B. Proceso B escribe en `/tmp/.cache_dat`. Proceso C (`curl`) lee `/tmp/.cache_dat` y transmite a un servidor externo.
- **Eventos Esperados:**
  - Proceso A: `openat(~/.ssh/id_rsa)`, `write(pipe_fd)`.
  - Proceso B: `read(pipe_fd)`, `openat(/tmp/.cache_dat)`, `write(/tmp/.cache_dat)`.
  - Proceso C: `openat(/tmp/.cache_dat)`, `connect(C2)`.
- **Eventos que Proporciona el Sensor:**
  - Tetragon estándar captura `openat` de A, `openat` de B sobre el archivo temporal y `openat` + `connect` de C.
  - **Límite Técnico Crítico:** El paso de bytes a través de pipes anónimos (`sys_pipe`, `sys_splice`) no genera eventos de inodo de archivo estándar en políticas eBPF básicas de syscalls a menos que se configure una TracingPolicy específica sobre descriptores de archivos de IPC.
- **Evidencia Mínima Necesaria:**
  - Si hay política IPC: Grafo completo $A \to \text{Pipe} \to B \to \text{File} \to C$.
  - Si NO hay política IPC: Solo se observa que C leyó `/tmp/.cache_dat` (escrito por B).
- **Resultado Esperado según Instrumentación:**
  - Con política de IPC activa: **MULTI-PROCESS DISTRIBUTED ATTACK (PARTIALLY_ATTRIBUTED)**.
  - Sin política de IPC: **SUSPICIOUS TEMP FILE EGRESS (UNKNOWN PROVENANCE)**. Sentinel Runtime se abstiene de afirmar que A y C están vinculados sin la evidencia intermedia de pipe.
- **Par Benigno de Control 03:**
  - Pipeline de compilación: `cat schema.sql | grep -v "test" | sqlite3 local.db`.
- **Condiciones para NO Bloquear:** Operaciones ocurren sobre archivos y herramientas declaradas en el script de build, sin acceso a almacenes de claves privadas ni destinos de red no autorizados.

---

## Escenario 04 — Abuso de Herramientas Legítimas (Living off the Land)

**Técnicas MITRE ATT&CK:** T1059.006 (Python), T1059.001 (Bash), T1105 (Ingress Tool Transfer).

### 4.1 Caso Malicioso: Intérprete Python con Inyección en Memoria
- **Ground Truth:** Ejecución de `/usr/bin/python3 -c "import urllib... exec(...)"` que descarga un script secundario en memoria y abre sockets reversos.
- **Eventos Esperados:**
  - `PROCESS_EXEC`: Argumentos `-c` con llamadas a funciones de red y `exec`.
  - `NETWORK_CONNECT_ATTEMPT`: Conexión hacia servidor no catalogado.
- **Eventos que Proporciona el Sensor:** `execve` con el array completo de argumentos de la línea de comandos, `connect` del intérprete.
- **Evidencia Mínima Necesaria:**
  $$\text{Execve}(\text{binario\_LOL}, \text{args\_anómalos}) \wedge \text{Connect}(\text{IP\_Externa\_No\_Baseline})$$
- **Resultado Esperado:** **LIVING_OFF_THE_LAND_IN_MEMORY_EXEC (ATTRIBUTED)**.
  - Atribución exacta de la instancia del proceso, sus argumentos y la conexión generada.
- **Par Benigno de Control 04:**
  - Script administrativo en disco: `/usr/bin/python3 /opt/monitoring/health_check.py --report-metrics`.
- **Condiciones para NO Bloquear:** Ejecutable apunta a un archivo estático en disco en ruta inmutable de sistema, verificado por hash de archivo, y el destino de red corresponde a la infraestructura interna de métricas.

---

## Escenario 05 — Evasión y Destrucción de Evidencia (Anti-Tampering & Sensor Resilience)

**Técnicas MITRE ATT&CK:** T1562.001 (Disable Tools), T1070.004 (File Deletion).

### 5.1 Caso Malicioso: Terminación Forzada del Agente y Purga de Disco
- **Ground Truth:** Un adversario con root (A3) ejecuta `kill -9` sobre el PID del daemon de Sentinel Runtime y borra `/var/run/sentinel/ledger.sqlite`.
- **Eventos Esperados:**
  - Recepción de señal `SIGKILL` sobre el daemon.
  - Cese del stream de eventos.
  - Intento de borrado de archivos del ledger.
- **Eventos que Proporciona el Sensor:**
  - Tetragon en kernel captura `sys_kill(target_pid, SIGKILL)` emitido por el proceso atacante.
- **Límite Técnico Fundamental:**
  - El propio daemon terminado no puede procesar su propia muerte una vez ejecutado el `SIGKILL`.
  - **Dependencia de Observador Externo:** La detección del cese del agente debe ser realizada por:
    1. El watchdog/sidecar en el host que supervisa al daemon.
    2. Sentinel Cloud al detectar el vencimiento del heartbeat del nodo.
- **Resultado Esperado:**
  - Localmente (en Watchdog): **CRITICAL_AGENT_TERMINATED_BY_SIGNAL (ATTRIBUTED al emisor del kill)** si el watchdog sobrevive.
  - En Cloud: **AGENT_UNRESPONSIVE / NODE_UNREACHABLE**.
  - *Precisión Normativa:* Sentinel Cloud no puede inferir inmediatamente un compromiso malicioso confirmado frente a una caída de red o apagado de host; reporta la pérdida de contacto y eleva a sospecha si existían eventos previos con `TAINT`.
- **Par Benigno de Control 05:**
  - Reinicio ordenado de servicio: `systemctl restart sentinel-runtime`.
- **Condiciones para NO Bloquear / NO Alertar Sabotaje:** Recepción previa de señal `SIGTERM`, ejecución de la rutina de graceful shutdown, emisión formal de evento `SENSOR_HEALTH (status: STOPPING_GRACEFULLY)` y cierre limpio de la base de datos SQLite WAL.
