# SENTINEL RUNTIME — THREAT MODEL REVIEW 001-R2
## Guarantee Classification, Sensor Assurance & Containment Safety

**Rol:** Independent Principal Security Architect  
**Baseline Git:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/THREAT_MODEL_REVIEW_001_R2.md`  
**Dictamen Global:** **APPROVED WITH RESTRICTIONS (READY FOR LAB VALIDATION / 001B BLOCKED)**

---

## 1. Resumen Ejecutivo y Mandato de Auditoría 001-R2

Esta auditoría corrige de forma definitiva la sobreestimación de capacidades identificada en la revisión 001-R1. Se establece una separación ontológica y metodológica estricta entre:
1. **Lo que está efectivamente implementado y probado en el código actual** (Fase 001A: Event Contract v1, validador de esquema y arnés de pruebas de frontera).
2. **Lo que es técnicamente demostrable en laboratorio** sujeto a instrumentación de kernel compatible (eBPF / cgroups v2 / Tetragon).
3. **Lo que son límites físicos y teóricos inalcanzables in-host** (inmutabilidad absoluta ante root o integridad ante kernel comprometido).

### Reglas Innegociables Cumplidas:
- **0 líneas de código modificadas** en `sentinel-runtime` ni en módulos de enforcement.
- **Fase 001B (Normalizador Tetragon) se mantiene estrictamente congelada**.
- **0 dependencias nuevas**, **0 commits realizados** (HEAD inalterado en `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`).
- Los 5 escenarios adversariales originales y sus pares benignos se conservan íntegros.

---

## 2. Corrección Exhaustiva de los Seis Hallazgos Críticos (TM-R1-01 a TM-R1-06)

### TM-R1-01: Desacoplamiento de Implementación, Garantía y Evidencia
- **Defecto en R1:** Se clasificó como `DEMONSTRABLE` una serie de capacidades (CEG, cgroup freeze, detección de desenganche, anclaje externo) como si fueran garantías del producto ya existentes.
- **Corrección en R2:** Se adopta la **Matriz Tridimensional de Calidad** que audita de forma independiente:
  - *Implementation Status:* ¿Existe el código en el repositorio? (`IMPLEMENTED` vs `NOT IMPLEMENTED`).
  - *Guarantee Class:* ¿Es matemáticamente alcanzable bajo precondiciones dadas? (`DEMONSTRABLE` vs `CONDITIONAL` vs `NOT DEMONSTRABLE`).
  - *Evidence Status:* ¿Ha sido probado empíricamente en el arnés de pruebas? (`TESTED` vs `PARTIALLY TESTED` vs `NOT TESTED`).

---

### TM-R1-02: `OBSERVABILITY_HEALTHY_WITHIN_DECLARED_COVERAGE`
- **Defecto en R1:** El estado `OBSERVABILITY_COMPLETE` sugería una cobertura universal imposible de demostrar (un sensor puede estar sano pero no tener TracingPolicy para una syscall específica).
- **Corrección en R2:** Reemplazado formalmente por **`OBSERVABILITY_HEALTHY_WITHIN_DECLARED_COVERAGE`**.
  - Certifica únicamente que los hook points eBPF declarados en las TracingPolicies activas están emitiendo telemetría sin eventos descartados en la ventana temporal auditada.
  - Ningún estado implica omnisciencia sobre el host.

---

### TM-R1-03: Semántica Formal de `cgroup.freeze` y Precisión sobre `SIGSTOP`
- **Defecto en R1:** Se describió el congelamiento de cgroups como una acción "instantánea" y "quirúrgica".
- **Corrección en R2:**
  - **FSM del Kernel:** Escribir `1` en `cgroup.freeze` únicamente solicita la operación (`FREEZE_REQUESTED`). El kernel procesa las tareas (`FREEZE_PENDING`) y la confirmación real exige leer `cgroup.events` y comprobar `frozen 1` (`FREEZE_CONFIRMED`).
  - **Alcance Jerárquico:** `cgroup.freeze` congela **a todas las tareas del cgroup y sus descendientes jerárquicos**. No es una intervención sobre un único hilo.
  - **Corrección sobre `SIGSTOP`:** Se eliminó la afirmación errónea de que `SIGSTOP` induce "deadlocks del kernel". Se especifica con precisión que induce **deadlocks funcionales en la aplicación** (retención de mutexes en memoria compartida, acumulación en colas y timeouts de clientes TCP remotos).

---

### TM-R1-04: Límites de Garantía ante Root (Nivel A3) y Observación Externa
- **Defecto en R1:** Se afirmaba que ante un root el agente podía "detectar sabotaje y notificar remotamente antes de morir".
- **Corrección en R2:** Un atacante con root puede cortar el socket de red y matar el proceso en la misma ráfaga de comandos.
- **Taxonomía de Supervisión Externa:** La pérdida de latidos no permite inferir automáticamente un compromiso malicioso confirmado. Se formalizan cinco estados diferenciados:
  1. `AGENT_UNRESPONSIVE`: Proceso local no responde pings del watchdog.
  2. `NODE_UNREACHABLE`: Cloud pierde contacto WAN con el host.
  3. `SENSOR_UNAVAILABLE`: Tetragon caído mientras el agente vive.
  4. `CLOUD_UNAVAILABLE`: Agente local vivo sin salida hacia el plano SaaS.
  5. `CONFIRMED_TAMPERING`: Evidencia explícita de manipulación probatoria (discrepancia en mapas BPF o reglas).

---

### TM-R1-05: Separación Cuádruple de Identidad de Procesos
- **Defecto en R1:** Se utilizaba `executable_sha256` como parte de la tupla obligatoria de identidad de instancia.
- **Corrección en R2:** Se desacopla la identidad en cuatro entidades ontológicas independientes:
  1. **Process Instance Identity:** $\langle \text{host\_id}, \text{boot\_id}, \text{exec\_id}, \text{tgid}, \text{start\_time\_ns}, \text{namespace\_ids} \rangle$.
  2. **Executable Artifact Identity:** $\langle \text{path}, \text{inode}, \text{device}, \text{sha256} \rangle$ (el hash se calcula de forma asíncrona y no condiciona la identidad de instancia).
  3. **Workload Identity:** $\langle \text{workload\_type}, \text{container\_id}, \text{k8s\_pod}, \text{k8s\_namespace}, \text{service\_account} \rangle$.
  4. **Host Identity:** $\langle \text{host\_id}, \text{machine\_id}, \text{boot\_id} \rangle$.

---

### TM-R1-06: Allowlist de Acciones en Modo Degradado
- **Defecto en R1:** Se permitía contención preventiva genérica en modo degradado sin acotar sus límites.
- **Corrección en R2:**
  - En `DEGRADED`: Permitido únicamente registro reforzado y acciones **estrictamente reversibles** previamente aprobadas (`CGROUP_FREEZE`, `NETWORK_ISOLATION`).
  - **PROHIBICIÓN TAXATIVA:** Queda prohibido emitir `TERMINATE_PROCESS` en `DEGRADED` o `LOST` basándose en cadenas causales incompletas. La pérdida de visibilidad nunca equivale a evidencia de culpabilidad.

---

## 3. Matriz Tridimensional de Requisitos (R-01 a R-12)

| Requisito | Implementation Status | Guarantee Class | Evidence Status | Residual Risk | Prerrequisitos de Activación | Método de Prueba |
|---|:---:|:---:|:---:|:---:|---|---|
| **R-01 Process Intelligence** | `PARTIALLY IMPLEMENTED` (Envelope v1) | `DEMONSTRABLE` | `PARTIALLY TESTED` (Schema tests) | MEDIUM | Kernel con export de `start_time_ns` y `cgroup_id`. | Test de reciclaje rápido de PID. |
| **R-02 Behavioral Correlation** | `NOT IMPLEMENTED` (Prototipo sintético) | `CONDITIONAL` | `NOT TESTED` | HIGH | Ventana deslizante en memoria, TracingPolicies activas. | Inyección de grafos multi-paso. |
| **R-03 Sensor Supervision** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | MEDIUM | Conexión gRPC local con daemon de Tetragon. | Watchdog ping + simulación de desconexión. |
| **R-04 Evidence Integrity** | `NOT IMPLEMENTED` (Spec v1) | `CONDITIONAL` | `NOT TESTED` | MEDIUM | SQLite WAL local + canal mTLS hacia Cloud. | Test de manipulación de bytes en DB. |
| **R-05 Adaptive Containment** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | HIGH | Host con cgroups v2 montado y permisos root. | Test de FSM de `cgroup.freeze` y rollback. |
| **R-06 Exhaustion Resilience** | `PARTIALLY IMPLEMENTED` (Esquema doS) | `DEMONSTRABLE` | `PARTIALLY TESTED` (maxLength tests) | MEDIUM | Límite wire de 4 MB en parser de Phase 001B. | Inyección de ráfaga de 50,000 ev/s. |
| **R-07 Fleet Autonomy** | `NOT IMPLEMENTED` | `DEMONSTRABLE` | `NOT TESTED` | LOW | Motor causal local desacoplado de Cloud. | Corte de interfaz de red externa. |
| **R-08 Policy Integrity** | `NOT IMPLEMENTED` | `DEMONSTRABLE` | `NOT TESTED` | MEDIUM | API de introspección BPF (`bpftool`/Tetragon API). | Modificación furtiva de mapa BPF en RAM. |
| **R-09 Identity Separation** | `IMPLEMENTED` (Contrato v1) | `DEMONSTRABLE` | `TESTED` (Suite de tipos v1) | LOW | Conformidad con esquema JSON Draft 2020-12. | Batería de validación de esquemas. |
| **R-10 Decision Provenance** | `NOT IMPLEMENTED` | `DEMONSTRABLE` | `NOT TESTED` | LOW | Registro de eventos causales en Evidence Ledger. | Reconstrucción determinista offline. |
| **R-11 Defensive Isolation** | `NOT IMPLEMENTED` | `DEMONSTRABLE` | `NOT TESTED` | CRITICAL | Lista de exclusión dura en el motor de contención. | Intento deliberado de auto-bloqueo. |
| **R-12 Recovery Integrity** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | MEDIUM | Protocolo de re-atestación previa a FULL. | Simulación de recuperación tras desenganche. |

---

## 4. Auditoría de Métricas de Benchmark (Fundamentación Estadística)

1. **Falsos Positivos ($\le 0.001 \text{ FP / workload-hour}$):**
   - Se ratifica formalmente la cota de Poisson:
     $$T \ge \frac{-\ln(0.05)}{0.001} \approx 2,996 \text{ workload-hours sin fallos}$$
   - Una suite de 50 horas de laboratorio es una **prueba exploratoria de cordura**, no una demostración contractual de la tasa $0.001$.
2. **Latencia de Detección Causal ($t_{\text{detect}} \le 200 \text{ ms}$):**
   - Medida desde el timestamp de kernel del evento desencadenante hasta la emisión del veredicto causal.
3. **Latencia de Congelamiento ($t_{\text{freeze}} \le 100 \text{ ms}$):**
   - Medida desde `write(cgroup.freeze, 1)` hasta la confirmación `read(cgroup.events, "frozen 1")`.
4. **Resiliencia ante Tormentas ($50,000 \text{ ev/s}$):**
   - Tamaño medio de evento: 1 KB. 4 vCPUs dedicadas. Límite de heap: 512 MB. Criterio: cero crash y reporte exacto de `EVENT_LOSS`.

---

## 5. Dictamen Final de Salida

- **Veredicto Técnico:** **`APPROVED WITH RESTRICTIONS`**
  - La especificación de `Threat Model 001` (R-01 a R-12) queda formalmente depurada y aprobada como base normativa para el diseño del laboratorio de pruebas.
  - Se reconocen explícitamente los componentes no implementados, eliminando falsas atribuciones de funcionalidad existente.
- **Fase 001B (Normalizador Tetragon):** Permanece **ESTRICTAMENTE BLOQUEADA**.
  - No se iniciará la implementación de código de normalización hasta completar la etapa pasiva `001B-0` (reconocimiento y obtención de telemetría real de Linux).
