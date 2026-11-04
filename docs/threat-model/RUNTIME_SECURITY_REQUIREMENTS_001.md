# SENTINEL RUNTIME — SECURITY REQUIREMENTS 001
## Mandatory Behavioral & Engineering Guarantees for the Runtime Agent

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2.1)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/RUNTIME_SECURITY_REQUIREMENTS_001.md`  
**Objetivo:** Establecer los requisitos obligatorios de ingeniería que diferencian a Sentinel Runtime de un recolector pasivo de logs o de un EDR reactivo basado exclusivamente en firmas.

---

## Requisito 01 — Adversarial Process Intelligence

El agente no debe tratar a los procesos como números PID efímeros ni confiar en el nombre del ejecutable:
1. **Separación Cuádruple de Identidades:** Se formaliza la distinción estricta de identidades:
   - **Process Instance Identity:** Instancia viva del proceso en el kernel. Formada por $\langle \text{host\_id}, \text{boot\_id}, \text{exec\_id}, \text{tgid}, \text{start\_time\_ns}, \text{namespace\_ids} \rangle$.
   - **Executable Artifact Identity:** Atributos del binario en almacenamiento $\langle \text{path}, \text{inode}, \text{device}, \text{sha256} \rangle$. El hash SHA-256 es un atributo probatorio que puede resolverse de forma asíncrona y no forma parte del identificador obligatorio de instancia.
   - **Workload Identity:** Contexto del orquestador $\langle \text{workload\_type}, \text{container\_id}, \text{k8s\_pod}, \text{k8s\_namespace}, \text{service\_account} \rangle$.
   - **Host Identity:** $\langle \text{host\_id}, \text{machine\_id}, \text{boot\_id} \rangle$.
2. **Inmunidad al Reciclaje de PIDs (PID Recycling):** Un nuevo proceso que herede el mismo PID en el sistema operativo debido a agotamiento de enteros debe ser identificado inequívocamente como una entidad diferente gracias a su `start_time_ns`, su `exec_id` de Tetragon y su `boot_id`.
3. **Visibilidad Multidimensional de Namespaces:** El agente debe auditar los 8 descriptores de namespaces del proceso (`mnt`, `pid`, `net`, `ipc`, `uts`, `user`, `cgroup`, `pid_for_children`) para detectar desacoplamientos furtivos o transiciones de aislamiento.
4. **Seguimiento del Linaje Ancestral Completo:** Todo evento debe poder vincularse retrospectivamente con su proceso padre, abuelo y la raíz del árbol de procesos (`root_ancestor`), preservando la procedencia incluso si los procesos intermedios han terminado (`PROCESS_EXIT`).

---

## Requisito 02 — Behavioral & Causal Correlation

El agente no debe disparar decisiones de bloqueo basadas en eventos aislados sin contexto:
1. **Causal Evidence Graph (CEG):** El agente mantiene en memoria un grafo acíclico dirigido (DAG) donde los nodos representan entidades (procesos, sockets, archivos, credenciales) y las aristas representan interacciones causales atestadas (`spawned_by`, `opened`, `read_sensitive`, `sent_network`, `ipc_transferred`).
2. **Propagación Contextual de Taint (Procedencia):** Si un proceso accede a un recurso catalogado como sensible (archivos `.env`, claves SSH, tokens de kubeconfig), dicho proceso recibe un estado de *procedencia comprometida* (`TAINT`) que se propaga a sus descriptores y procesos hijos directos.
3. **Certeza Escalonada de Veredicto:**
   - **`ATTRIBUTED`:** Cadena causal demostrada de forma completa e ininterrumpida.
   - **`PARTIALLY_ATTRIBUTED`:** Evidencia concluyente de etapas críticas (acceso + egress), pero con eslabones intermedios no observados (ej. memoria de heap sin inspección).
   - **`UNKNOWN`:** Evidencia fragmentada o eventos perdidos. Sentinel Runtime debe abstenerse de declarar atribución sin evidencia.
4. **Diferenciación de Baselines:** El motor causal debe contrastar cada operación contra el perfil baseline del workload (`HOST_PROCESS`, `CONTAINER`, `CI_RUNNER`), suprimiendo alarmas cuando el comportamiento coincide con la especificación funcional declarada.

---

## Requisito 03 — Sensor Integrity & Multi-Layer Observability Supervision

El agente debe diferenciar con precisión matemática los cinco estados de salud del sensor, reemplazando la noción abstracta de "cobertura completa" por una cobertura declarada:

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

1. **Definición de Cobertura Declarada:** Ningún estado del sensor implica cobertura universal del host. El estado `HEALTHY_WITHIN_DECLARED_COVERAGE` certifica únicamente que los puntos de enganche (hook points) declarados en las TracingPolicies activas están emitiendo sin pérdidas detectadas en la ventana temporal auditada.
2. **Supervisión de Desenganche de Sondas (Probe Detachment):** Verificación periódica de los identificadores de programas BPF en el kernel para detectar manipulación selectiva de kprobes.
3. **Auditoría de TracingPolicies:** Comprobación del hash de las políticas activas en Tetragon frente a la configuración aprobada.
4. **Manejo de Pérdida en Ring Buffer:** Si el kernel incrementa los contadores `dropped_events_ring_buffer`, el estado transiciona a `OBSERVABILITY_DEGRADED` de forma inmediata y explícita.
5. **Dependencia de Observador Externo ante Muerte del Agente:** La muerte abrupta del daemon (`SIGKILL` por A3) no puede ser certificada por el propio proceso; requiere la detección por parte de un watchdog de nodo o del plano de control en Sentinel Cloud tras el cese de los heartbeats.

---

## Requisito 04 — Evidence Ledger Integrity & Multi-Layer Forensic Guarantees

La integridad forense no puede garantizarse únicamente mediante mecanismos de transporte o bases de datos convencionales:
1. **Límites de SQLite WAL y mTLS:**
   - `SQLite WAL` garantiza atomicidad local (ACID) y resistencia contra cortes eléctricos, pero **no proporciona protección criptográfica contra modificaciones intencionales por un usuario root (A3)**.
   - `mTLS` protege la confidencialidad y autenticidad del canal de transporte en tránsito, pero **no demuestra que los eventos almacenados en el host no hayan sido alterados o truncados antes de su transmisión**.
2. **Las 7 Capas de Integridad Probatoria del Ledger:**
   - **Capa 1: Integridad de Registros Individuales:** Cada evento contiene su propio hash SHA-256 canónico según RFC 8785 (JCS).
   - **Capa 2: Continuidad de la Cadena Hash (Tamper-Evidence):** Cada bloque calcula $H_i = \text{SHA-256}(H_{i-1} \parallel \text{BlockPayload}_i)$. Cualquier inserción, alteración o reordenamiento invalida la serie hacia adelante.
   - **Capa 3: Detección de Eliminación o Truncamiento:** Contadores monotónicos secuenciales de bloque ($i, i+1$) que revelan huecos en la serie temporal.
   - **Capa 4: Checkpoints Periódicos Locales:** Sellado periódico de cabeceras de bloque en almacenamiento append-only.
   - **Capa 5: Anclaje Externo Verificable (External Anchoring):** Replicación inmediata de cada cabecera $H_i$ hacia Sentinel Cloud o un servicio externo inmutable. Si el host es comprometido en $t_1$, los bloques anclados en $t_0 < t_1$ permanecen no repudiables fuera del alcance del atacante.
   - **Capa 6: Protocolo de Recuperación tras Interrupción:** Verificación de la integridad de la base de datos al reiniciar, detectando bloques rotos o transacciones huérfanas mediante el último bloque cerrado válido.
   - **Capa 7: Frontera ante Root (Nivel A3):** Un atacante con root en el host puede alterar la base de datos SQLite y recalcular la cadena hash local si posee acceso al archivo. La **detección de este ataque se fundamenta exclusivamente en la divergencia entre el ledger reescrito y los checkpoints previamente anclados en Sentinel Cloud**.
3. **Poda Condicionada por Checkpoints:**
   - Queda prohibida la eliminación arbitraria de registros por cuota de disco (ej. 5 GB).
   - Solo se permite purgar payloads de eventos si el bloque cuenta con `CONFIRMED_EXTERNAL_CHECKPOINT` emitido por Sentinel Cloud y se conserva la cabecera ($H_i$) en el host para verificar la continuidad.

---

## Requisito 05 — Adaptive Containment & Formal cgroup Freeze Semantics

La contención defensiva debe contar con límites operativos estrictos para evitar que Sentinel se convierta en un vector de denegación de servicio (DoS) autoinfligido contra el workload:

### 5.1 Máquina de Estados Finitos de `cgroup.freeze`
El congelamiento mediante cgroups v2 no es una operación instantánea ni se confirma con la simple escritura. Sigue la FSM formal del kernel Linux:
```text
[Operación Normal]
       │
       ▼ (Escribir cgroup.freeze = 1)
[FREEZE_REQUESTED]
       │
       ▼ (Kernel procesa tareas del cgroup y sus hijos descendientes)
[FREEZE_PENDING]
       │
       ├─► (cgroup.events informa frozen 1) ──► [FREEZE_CONFIRMED]
       │
       └─► (Timeout de espera / error de cgroup) ──► [FREEZE_FAILED] ──► [ROLLBACK]
```

- **Alcance Jerárquico y Efectos Colaterales:** `cgroup.freeze` afecta a **todos los procesos contenidos en el cgroup y en toda su descendencia jerárquica**. Si un cgroup aloja procesos compartidos (ej. sidecars de logging, agentes de monitoreo o threads auxiliares), todos ellos serán congelados.
- **Reversibilidad Técnica vs. Seguridad Operacional:** Reanudar un proceso (`cgroup.freeze = 0`) es técnicamente reversible en el kernel, pero **operacionalmente puede provocar la caída del servicio** debido a:
  - Vencimiento de timeouts en clientes TCP remotos.
  - Acumulación y desbordamiento de búferes de mensajes.
  - Caída de health-checks de Kubernetes (liveness probes fallidas) que inducen el reinicio del Pod por parte del kubelet.
- **Precisiones sobre `SIGSTOP`:** La señal `SIGSTOP` pausa el proceso a nivel POSIX, pero puede inducir **deadlocks funcionales en la aplicación** (retención de mutexes en memoria compartida, bloqueos de locks en archivos o transacciones de base de datos a medio commit). No se describe genéricamente como "deadlock del kernel".

### 5.2 Matriz de Acciones de Contención y Requisitos de Autorización

| Acción de Contención | Reversibilidad Operativa | Impacto en Disponibilidad | Riesgos y Efectos Secundarios | Requisito de Autorización |
|---|---|---|---|---|
| **RECORD_ONLY** | Total (N/A) | Cero | Consumo marginal de I/O en disco. | Nivel base (por defecto). |
| **INCREASE_OBSERVABILITY** | Total | Muy bajo | Aumento de tasa de eventos en ring buffer. | Automático por correlación. |
| **NETWORK_ISOLATION** | Alta (regla iptables/BPF) | Alto para el proceso | Posible timeout de clientes y acumulación de colas. Riesgo de aislar canales de telemetría si no hay filtro estricto. | Regla de severidad HIGH con verificación de destino. |
| **SIGSTOP** | Media (vía `SIGCONT`) | Severo (pausa) | Riesgo de deadlocks funcionales de aplicación y timeouts. | Regla de severidad CRITICAL. |
| **CGROUP_FREEZE** | Alta (vía `cgroup.freeze=0`) | Severo (pausa jerárquica) | Congela todos los subprocesos del cgroup atómicamente. Requiere cgroups v2 y confirmación via `cgroup.events`. | Regla de severidad CRITICAL con cgroup específico. |
| **TERMINATE_PROCESS** | **NULA (Irreversible)** | Crítico (muerte) | **Pérdida irreversible de estado de memoria.** Corrupción de transacciones en curso. | **Autorización explícita de política (Require Policy Approval).** |

### 5.3 Reglas de Seguridad en Acciones Reversibles (`NETWORK_ISOLATION` y `CGROUP_FREEZE`):
1. **Precondiciones Obligatorias:** Identidad del proceso y su cgroup inequívocamente resuelta (`tgid`, `cgroup_id`, `start_time_ns`). Si la identidad es `UNKNOWN`, **la acción se suspende de inmediato**.
2. **Límite Temporal Máximo (Time-to-Live / Auto-Rollback):** Toda acción de congelamiento o aislamiento de red preventiva debe contar con un temporizador de duración máxima (por defecto: 60 segundos). Si no se recibe ratificación de Sentinel Cloud o de un operador humano dentro de esa ventana, el agente ejecuta rollback automático (`UNFREEZE` / restauración de red) para evitar DoS permanente por falso positivo.
3. **Preservación de Canales de Recuperación:** Las reglas de aislamiento de red deben contar con bypass explícito para loopback local (`127.0.0.1`), sockets de health-check y la IP del plano de control de Sentinel Cloud.

---

## Requisito 06 — Resource Exhaustion Resilience & Multi-Layer Parsing Limits

El agente debe sobrevivir a tormentas de eventos sin utilizar la degradación como excusa para intervenciones destructivas:

### 6.1 Desacoplamiento de Límites de Validación y Límites de Ingestión Wire
- **Límites de Esquema en Memoria (001A - IMPLEMENTADO):** Restringe `maxLength` en puntos de código y `maxItems` en arrays para objetos JSON ya parseados.
- **Límites de Transporte Wire (001B - NOT IMPLEMENTED / PENDING):** El límite de **4 MB por mensaje wire** no es una función del esquema JSON; corresponde estrictamente al parser de streaming de red antes de ejecutar `JSON.parse`.
- **Las 6 Capas de Protección contra Saturación de Recursos:**
  1. *Límite de Longitud por Campo:* `maxLength: 4096` en rutas, `maxLength: 131072` en args (Fase 001A).
  2. *Tamaño Máximo de Frame Wire:* Descarte de tramas superiores a 4 MB antes de la deserialización (Fase 001B).
  3. *Profundidad Máxima de Anidamiento JSON:* Cota de profundidad (máximo 8 niveles) para evitar ataques de desbordamiento de pila en V8.
  4. *Rechazo de Claves Duplicadas:* Tokenizador en streaming que rechaza duplicados a nivel de texto antes de construir el objeto JS (RFC 8785).
  5. *Presupuesto de CPU y Memoria:* Heap de Node.js acotado a 512 MB y particionamiento de tareas pesadas en `worker_threads`.
  6. *Backpressure y Recuperación:* Monitoreo de descarte del ring buffer (`loss_metrics`) y transición explícita a `DEGRADED`.

### 6.2 Allowlist de Acciones por Estado de Observabilidad

| Estado de Observabilidad | Acciones Defensivas Permitidas | Acciones Expresamente Prohibidas |
|---|---|---|
| **`FULL`** | Todas las acciones configuradas en la política según evidencia causal completa (`ATTRIBUTED`). | Ninguna (sujeto a matriz de autorización). |
| **`DEGRADED`** (Pérdidas de eventos o ring buffer drops) | Registro forense reforzado, alertas contextuales, acciones **estrictamente reversibles** previamente autorizadas (`CGROUP_FREEZE`, `NETWORK_ISOLATION` con TTL). | **PROHIBIDO: `TERMINATE_PROCESS`.** Queda terminantemente prohibido matar procesos basándose en cadenas causales incompletas. |
| **`LOST`** (Cese de sensores o ceguera total) | Emisión de alarma crítica de emergencia hacia Sentinel Cloud. Aplicación de políticas locales de emergencia previamente aprobadas (Fail-Secure preventivo). | **PROHIBIDO: Veredictos de culpabilidad definitivos ni terminación de procesos.** La pérdida de visibilidad no debe interpretarse automáticamente como evidencia de ataque. |

---

## Requisito 07 — Fleet-Level Coordination & Autonomy

El agente debe ser capaz de proteger el nodo de forma autónoma sin depender de conectividad constante:
1. **Autonomía Operativa Desconectada:** El agente toma decisiones de contención local en milisegundos utilizando su motor causal local y sus baselines precargados, sin requerir una consulta en red a Sentinel Cloud para decidir si bloquea un ataque evidente.
2. **Sincronización Store-and-Forward:** Si la red se interrumpe, el Evidence Ledger local almacena las evidencias de forma persistente y las replica en cuanto se restablece la comunicación.
3. **Distribución de Indicadores de Flota:** El agente puede recibir indicadores de compromiso (IoCs) atestados y políticas actualizadas generadas a partir de incidentes ocurridos en otros nodos de la flota.

---

## Requisito 08 — Effective Policy Integrity (6-Layer Verification)

Sentinel Runtime debe auditar activamente la coherencia entre las políticas declaradas y las efectivamente cargadas en el kernel a través de seis capas independientes:

```text
┌────────────────────────────────────────────────────────┐
│ 1. CONFIGURACIÓN DESEADA (Desired Config)              │
│    Especificación YAML/JSON aprobada por el admin.     │
├────────────────────────────────────────────────────────┤
│ 2. CONFIGURACIÓN ACEPTADA (Accepted by Tetragon)       │
│    TracingPolicy validada y cargada por el daemon.     │
├────────────────────────────────────────────────────────┤
│ 3. PROGRAMAS BPF CARGADOS (Loaded BPF Programs)        │
│    Bytecode verificado y presente en memoria kernel.   │
├────────────────────────────────────────────────────────┤
│ 4. HOOKS EFECTIVAMENTE ENLAZADOS (Attached Hooks)      │
│    Enlaces bpf_link, kprobes y tracepoints activos.    │
├────────────────────────────────────────────────────────┤
│ 5. EVENTOS RECIBIDOS (Received Events Stream)          │
│    Telemetría fluyendo hacia el agente consumidor.     │
├────────────────────────────────────────────────────────┤
│ 6. PÉRDIDAS Y FILTROS APLICADOS (Loss & Drop Metrics)  │
│    Contadores de descartes en kernel y exportador.     │
└────────────────────────────────────────────────────────┘
```

1. **Límites del Hash YAML en Disco:** La coincidencia del hash SHA-256 del archivo YAML en disco es una precondición estática, pero **no demuestra que los hooks correspondientes estén efectivamente enganchados en el kernel**.
2. **Degradación por Discrepancia:** Una divergencia entre la configuración aceptada y los enlaces BPF activos transiciona el estado del sensor a `OBSERVABILITY_DEGRADED` de forma inmediata. No se infiere automáticamente sabotaje a menos que existan señales explícitas de desenganche forzado (`PROBE_DETACHED`).

---

## Requisito 09 — Process Identity Integrity & PID Reuse Protection

El agente debe mantener una separación ontológica estricta para todo proceso:
1. **Separación Cuádruple de Identidades:** Distinción formal entre Process Instance Identity, Executable Artifact Identity, Workload Identity y Host Identity.
2. **Inmunidad al Reciclaje Rápido de PIDs:** Dos procesos consecutivos que compartan el mismo número PID en Linux se tratan como entidades desconectadas en el Grafo Causal gracias a la resolución de nanosegundos en `start_time_ns` y el identificador monotónico de ejecución (`exec_id`).

---

## Requisito 10 — Decision Provenance & Explainability

Cada acción o veredicto de seguridad emitido por Sentinel Runtime debe ser completamente explicable y auditable:
1. **Registro de Procedencia de Decisión:** Todo veredicto incluye los IDs de los eventos del Evidence Ledger que sustentaron la correlación, las versiones de las reglas aplicadas, los campos que estuvieron ausentes o truncados y el estado de observabilidad en el instante del dictamen.
2. **Reproducibilidad Determinista:** Cualquier analista externo debe poder reproducir exactamente el mismo veredicto alimentando los mismos eventos en una instancia limpia del motor causal.

---

## Requisito 11 — Defensive Isolation & Anti-Self-Harm Engineering

El agente debe garantizar que sus propias defensas no sean utilizadas para destruirse a sí mismo, eliminando afirmaciones infundadas de "inmunidad absoluta":

1. **Aislamiento por Diseño (No Inmunidad Absoluta):** Ningún sistema en espacio de usuario es inmune a un root local (A3) ni a errores en su propia lógica. R-11 se define como un conjunto de **controles arquitectónicos independientes de mitigación de auto-contención**:
   - **Identidad Protegida del Agente:** Identificadores inequívocos de Sentinel Runtime (`tgid`, `cgroup_id`, `executable_inode`) registrados al inicio en una estructura inmutable en memoria.
   - **Exclusión Forzada en el Punto de Enforcement (PEP):** La verificación de exclusión se ejecuta en la capa más baja de ejecución de la contención (`src/enforcement/`), inmediatamente antes de invocar la syscall o escribir en `cgroup.freeze`, no únicamente en la lógica heurística del motor de detección.
   - **Protección Jerárquica de Cgroups:** Antes de congelar un cgroup, el enforcement debe comprobar que el cgroup objetivo **no sea un ancestro ni contenga el cgroup donde reside Sentinel Runtime o Tetragon** (`system.slice/sentinel-runtime.service`).
   - **Fallo Seguro ante Identidad Desconocida:** Si la identidad del objetivo a contener no puede resolverse con total certeza (`UNKNOWN`), **la acción de contención se aborta de forma obligatoria**. Queda prohibido aplicar acciones sobre objetivos difusos.
   - **Pruebas Negativas de Auto-Contención:** Batería obligatoria de pruebas donde se inyectan intencionalmente reglas maliciosas dirigidas a suspender a Sentinel, verificando su rechazo automático en el PEP.
2. **Límites Frente a Root (Nivel A3):** Un atacante con privilegios root puede manipular cgroups o enviar señales directas desde fuera del proceso de Sentinel; Sentinel Runtime no promete inmunidad contra acciones externas de root, sino que sus propias políticas internas jamás dispararán auto-lesión.

---

## Requisito 12 — Recovery Integrity & Trust Re-Attestation

La restauración operativa de un sensor no implica la restauración automática de la confianza probatoria:
1. **Protocolo de Re-Atestación de Confianza:** Tras una interrupción o degradación del sensor, Sentinel Runtime no puede regresar inmediatamente a `OBSERVABILITY_FULL` simplemente porque el stream se restablezca.
2. **Condiciones de Retorno a FULL:** Debe verificarse la integridad de las TracingPolicies cargadas, la salud de las sondas BPF en kernel, la ausencia de eventos descartados pendientes y la continuidad verificable de la cadena hash en el Evidence Ledger.
