# SENTINEL RUNTIME — ARCHITECTURE REVIEW 001
**Independent Systems Architecture Review & Specification Ratification**  
*Document ID:* `ARCH-REVIEW-001`  
*Date:* 2026-11-02  
*Reviewer:* Principal Systems Security Architect / Independent Technical Reviewer  
*Baseline:* `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Specifications Reviewed:* `SPEC-EVENT-V1r2`, `SPEC-CAUSAL-V1r2`, `SPEC-LEDGER-V1r2`, `SPEC-TETRAGON-V1r2`  
*Source Code Modified:* **NONE (0 bytes changed)**

---

## 1. Resumen Ejecutivo

La **Specification Phase 001** de Sentinel Runtime produjo cuatro especificaciones normativas que definen el contrato de eventos, el motor causal, el ledger forense y la integración con Cilium Tetragon. La presente revisión arquitectónica independiente identificó **seis deficiencias técnicas** (AR-01 a AR-06) en los contratos originales y resolvió tres decisiones de ingeniería pendientes.

Tras la corrección y validación cruzada:

| Área | Estado Anterior | Estado Posterior |
|---|---|---|
| Compatibilidad de Kernel | Requisitos incorrectos (5.15 para fentry) | 3 perfiles por capacidad (BASE/ADVANCED/ENFORCEMENT) con fentry ≥ 6.1 |
| Propagación de Taint | Sin semántica de fork/COW | 4 niveles formales de propagación de datos (D-00 a D-03) |
| Semántica de Exfiltración | 4 niveles, exfiltración excesivamente confiada | 5 niveles con separación explícita de alta sospecha vs. confirmación |
| Pérdida de Eventos | Binaria (loss > 0 = degradado) | FSM con RECOVERING y deltas por ventana temporal |
| Anclaje Externo | "Garantía" de 60s absoluta | Objetivo condicionado a conectividad; 3 estados de anclaje |
| Trazabilidad Evento↔FSM | "Biyectividad" incorrecta | Matriz many-to-many con 14 familias × 7 estados |

---

## 2. Hallazgos de la Revisión Arquitectónica (AR-01 a AR-06)

### AR-01 — Compatibilidad de Kernel (CORREGIDO)

**Problema:** La especificación original declaraba Linux 5.15 como estándar óptimo suficiente para fentry/fexit. La documentación oficial de Tetragon establece:
- Kernel mínimo: Linux ≥ 4.19
- BTF (`CONFIG_DEBUG_INFO_BTF`): **Obligatorio** (Tetragon falla al iniciar sin `/sys/kernel/btf/vmlinux`)
- fentry/fexit: **Linux ≥ 6.1** (no 5.15)
- BPF LSM: Requiere `CONFIG_BPF_LSM=y` y `bpf` en el parámetro de boot `lsm=`
- ARM64: Requiere kernel ≥ 5.10 (kernels 4.19/5.4 tienen bugs conocidos)

**Hallazgo adicional de la investigación:** fentry en Tetragon está actualmente limitado a **observabilidad solamente**. Las acciones de enforcement (`sigkill`, `override`) requieren políticas basadas en **kprobes**, no fentry.

**Resolución:** Se definieron 3 perfiles de compatibilidad:
- **BASE** (≥ 4.19 con BTF): Observabilidad de procesos.
- **ADVANCED** (≥ 5.10 con BTF): Instrumentación de archivos y red vía kprobes/tracepoints.
- **ENFORCEMENT** (≥ 6.1 con BTF + LSM): Prevención en kernel vía kprobes (enforcement) + fentry (observabilidad de baja latencia).

### AR-02 — Semántica de Fork/COW en Propagación de Taint (CORREGIDO)

**Problema:** La regla T-03 anterior no modelaba adecuadamente la herencia de memoria por Copy-On-Write en `fork()`.

**Ejemplo del Comité:**
```
Proceso A (lee /proc/self/environ → guarda secreto en memoria)
  └── fork()
       └── Proceso B (hereda copia COW del espacio de memoria)
            └── Utiliza los datos heredados sin IPC explícito
```

**Resolución:** Se formalizaron 4 niveles de propagación de datos:
- **D-00 (`PROCESS_LINEAGE`):** Solo parentesco. No propaga taint.
- **D-01 (`POTENTIAL_DATA_PROPAGATION`):** Fork con COW, descriptores heredados. *Posibilidad* de transferencia, no demostración. Incrementa vigilancia pero no escala a enforcement.
- **D-02 (`OBSERVED_DATA_PROPAGATION`):** Lectura en descriptor heredado, IPC con escritura/lectura observada. Propaga taint con nivel `OBSERVED`.
- **D-03 (`VERIFIED_DATA_PROVENANCE`):** Cadena causal completa: lectura sensible → propagación observada → transmisión confirmada. Único nivel que autoriza `TERMINATE_PROCESS`.

**Distinción clave:** `execve()` actúa como barrera de taint de memoria (reemplaza el espacio de direcciones) pero **no** como barrera de taint de descriptores (los `fd` sin `FD_CLOEXEC` persisten).

### AR-03 — Veredicto de Exfiltración Demasiado Ambicioso (CORREGIDO)

**Problema:** La taxonomía original de 4 niveles saltaba de `OUTBOUND_TRANSFER_CORRELATED` a `SENSITIVE_DATA_EXFILTRATION_CONFIRMED` sin un nivel intermedio que reconociera la limitación del sensor.

**Realidad Técnica:** Un sensor de kernel genérico no puede:
- Inspeccionar el contenido de flujos TLS cifrados.
- Correlacionar byte por byte qué datos leídos fueron los que se transmitieron.
- `returnCopy` de Tetragon tiene limitaciones de tamaño, solo aplica a `char_buf`/`char_iovec`, y bajo carga puede saturar el ring buffer.

**Resolución:** Se añadió un quinto nivel:
- **`SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED`** (nuevo): Alta sospecha con acceso sensible + transferencia observada, pero sin procedencia verificable del dato transmitido. Confianza máxima: `HIGH`. Permite `ISOLATE_NETWORK` / `SUSPEND_PROCESS` pero **no** `TERMINATE_PROCESS`.
- **`SENSITIVE_DATA_EXFILTRATION_CONFIRMED`** se reserva para evidencia `D-03` con correlación de volumen o captura de buffer verificable.

### AR-04 — FSM de Observabilidad sin Recuperación (CORREGIDO)

**Problema:** El tratamiento original era binario: `loss > 0` → degradado, sin mecanismo de recuperación. Los contadores de Tetragon son acumulativos (Prometheus Counters monotónicos).

**Métricas de Tetragon investigadas:**
- `tetragon_observer_ringbuf_events_lost_total` (kernel)
- `tetragon_export_ratelimit_events_dropped_total` (rate limiting)
- `tetragon_events_export_failed_total` (exportación)
- `PROCESS_THROTTLE` con subtipos `THROTTLE_START` / `THROTTLE_STOP` (cgroup-based, deshabilitado por defecto)

**Resolución:** Se definió una FSM de 3 estados de observabilidad:
```
NORMAL → OBSERVABILITY_DEGRADED → RECOVERING → NORMAL
```
- La transición a `DEGRADED` evalúa **deltas por ventana temporal**, no valores absolutos acumulados.
- La transición a `RECOVERING` requiere heartbeat saludable del sensor con contadores estabilizados.
- El retorno a `NORMAL` requiere 60 segundos sin nuevos deltas de pérdida.
- **Regla Anti-Amnesia:** Ausencia de eventos sin heartbeat ≠ ausencia de actividad. Se mantiene `DEGRADED`.

### AR-05 — Anclaje Externo sin Conectividad (CORREGIDO)

**Problema:** La fórmula $\mathcal{W} = \min(60\text{s}, 500\text{ registros})$ se presentaba como garantía absoluta, pero si la conectividad con Cloud está perdida, no existe anclaje remoto y la ventana crece indefinidamente.

**Resolución:**
- **Tres estados de anclaje:** `ANCHORED`, `UNANCHORED_ONLINE`, `UNANCHORED_OFFLINE`.
- La fórmula de 60s/500 registros se reclasifica como **objetivo operacional** condicionado a disponibilidad del servicio remoto.
- Política de spool local con capacidad reservada de 50 MB.
- Detección de fork-attack al reconectarse.
- Rotación de claves de nodo con checkpoint especial `KEY_ROTATION`.

### AR-06 — Trazabilidad Evento↔FSM (CORREGIDO)

**Problema:** Se afirmaba "mapeo biyectivo" entre familias de eventos y transiciones de la FSM.

**Resolución:** Se creó una matriz many-to-many con las 14 familias de eventos × 7 estados causales, documentando para cada intersección: evidencia requerida, confianza y enforcement máximo.

---

## 3. Decisiones Arquitectónicas Resueltas

### AR-01 — Lenguaje del Ingestor: Node.js con gRPC
- **Decisión:** Desarrollar el adaptador gRPC de Tetragon en Node.js con `@grpc/grpc-js`.
- **Principio:** La arquitectura es independiente del transporte. JSON export queda como fuente secundaria y para fixtures.
- **Criterio de Escalamiento:** Si benchmarks demuestran que Node.js no satisface >10,000 eventos/segundo con latencia p99 < 50ms, se introducirá un forwarder nativo (Go/Rust) como componente de infraestructura desacoplado.
- **Riesgo Residual:** GC pauses de V8 bajo carga extrema.

### AR-02 — Anclaje Externo: Interfaz WORM Genérica
- **Decisión:** Interfaz de anclaje compatible con almacenamiento append-only con Object Lock en modo `COMPLIANCE`.
- **Principio:** No se modifica `sentinel-cloud` durante esta fase. El adaptador de Cloud se desarrollará bajo autorización independiente.
- **Riesgo Residual:** Sin servicio dedicado de alta disponibilidad, la latencia de anclaje es variable.

### AR-03 — ENOSPC: Degradación Controlada
- **Decisión:** Ni fail-open ni fail-secure global.
- **Comportamiento:**
  1. Conmutar a buffer RAM reservado.
  2. Mantener TracingPolicies activas.
  3. Activar `EVIDENCE_PERSISTENCE_DEGRADED`.
  4. Reservar espacio de emergencia para registrar el incidente.
  5. Prohibir terminaciones nuevas que dependan de evidencia no persistida.
  6. No suspender workloads automáticamente.
  7. Exigir verificación completa antes de retornar a operación normal.

---

## 4. Arquitectura Final de Sentinel Runtime

```text
┌─────────────────────────────────────────────────────────────────┐
│                    LINUX KERNEL / TETRAGON                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ TracingPolicies (kprobes / tracepoints / fentry)         │   │
│  │ PROCESS_EXEC · PROCESS_EXIT · FILE · TCP · THROTTLE      │   │
│  │ Enforcement: sigkill / override (kprobes only)            │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ gRPC / JSON Lines
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              SENSOR INGESTION & EVENT NORMALIZATION              │
│  ┌───────────────┐ ┌──────────────┐ ┌────────────────────────┐  │
│  │ Tetragon      │ │ Event Schema │ │ Loss Accounting        │  │
│  │ Adapter       │ │ Validator    │ │ (7 counters + deltas)  │  │
│  │ (gRPC client) │ │ (JSON Schema)│ │                        │  │
│  └───────┬───────┘ └──────┬───────┘ └────────────┬───────────┘  │
│          │ exec_id opaco  │ Provenance           │ loss_metrics │
└──────────┼────────────────┼──────────────────────┼──────────────┘
           │                │                      │
           ▼                ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SENTINEL BEHAVIORAL CORE                       │
│  ┌──────────────┐ ┌───────────────┐ ┌─────────────────────────┐ │
│  │ Process      │ │ Causal        │ │ Decision FSM            │ │
│  │ Lineage      │ │ Evidence      │ │ (7 states)              │ │
│  │ Graph (PLG)  │ │ Graph (CEG)   │ │ + Observability FSM     │ │
│  │              │ │ Taint D-00    │ │ (NORMAL→DEGRADED→       │ │
│  │ parent →     │ │ → D-01 → D-02│ │  RECOVERING→NORMAL)     │ │
│  │ exec_id      │ │ → D-03       │ │                         │ │
│  └──────────────┘ └───────────────┘ └─────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Decision 4-Tuple: ⟨Confidence, Severity, Policy, Action⟩ │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
┌──────────────────┐ ┌──────────┐ ┌──────────────────────────────┐
│ ENFORCEMENT      │ │ EVIDENCE │ │ MANAGEMENT PLANE             │
│ ┌──────────────┐ │ │ LEDGER   │ │ ┌──────────────────────────┐ │
│ │ DRY_RUN      │ │ │ ┌──────┐ │ │ │ Cloud Telemetry          │ │
│ │ Reversible   │ │ │ │ JCS  │ │ │ │ Fleet Policies           │ │
│ │ Destructive  │ │ │ │ Hash │ │ │ │ Incident Coordination    │ │
│ │ (VERIFIED    │ │ │ │ Chain│ │ │ │ Checkpoint Anchoring     │ │
│ │  only)       │ │ │ └──────┘ │ │ └──────────────────────────┘ │
│ └──────────────┘ │ │ Checkpts │ │ States: ANCHORED /           │
│ Tetragon kprobe  │ │ External │ │ UNANCHORED_ONLINE /          │
│ enforcement      │ │ Anchor   │ │ UNANCHORED_OFFLINE           │
└──────────────────┘ └──────────┘ └──────────────────────────────┘
```

---

## 5. Riesgos Residuales Aceptados

| ID | Riesgo | Mitigación | Riesgo Residual |
|---|---|---|---|
| RR-01 | GC pauses de V8 en Node.js bajo carga extrema | Benchmark obligatorio; criterio de escalamiento a forwarder nativo definido | Latencia p99 podría exceder objetivo bajo >10k ev/s |
| RR-02 | Exfiltración por canal cifrado no detectable por sensor kernel | Veredicto `SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED` como escalón de alta sospecha | Certeza absoluta de contenido inalcanzable sin DPI |
| RR-03 | Evidencia no anclada durante desconexión prolongada | Spool local con firma de nodo; detección de fork-attack al reconectar | Atacante root durante desconexión puede manipular ventana no anclada |
| RR-04 | Kernels sin BTF desplegados en producción | Verificación dinámica al inicio; alerta y degradación a perfil imposible | Tetragon no arranca sin BTF; host queda sin sensor |
| RR-05 | fentry enforcement no disponible en Tetragon | Enforcement basado en kprobes; fentry solo para observabilidad | Mayor latencia en hooks de enforcement vs. fentry |
| RR-06 | Buffer RAM de emergencia (ENOSPC) puede saturarse | Contador `loss_storage_drop` + transición a `OBSERVABILITY_DEGRADED` | Pérdida de eventos si RAM se satura antes de liberar disco |

---

## 6. Verificación del Repositorio

| Verificación | Resultado |
|---|---|
| HEAD | `fb4c5d638810e6a63cd35f68c50f5740e8db8d75` |
| Commit Base Auditado | `fb4c5d638810e6a63cd35f68c50f5740e8db8d75` |
| `git diff --exit-code` | Código 0 (0 bytes modificados en archivos rastreados) |
| Archivos de código fuente | 100% idénticos al baseline |
| Archivos de especificación (untracked) | `docs/specs/` × 5, `RUNTIME_ENGINEERING_AUDIT_001.md`, `RUNTIME_AUDIT_CORRECTION_002.md`, `ARCHITECTURE_REVIEW_001.md` |
| SHA-256 del ZIP original | `1F6270CB55B1B49B0DFE2EE18CAFF46C5DFEA13E864D704CA20DA80E145A1D70` |

---

## 7. Criterios de Aceptación Consolidados para la Fase de Implementación

### Criterios Cumplidos
- [x] Especificaciones revisadas con correcciones AR-01 a AR-06.
- [x] Matriz de kernel con 3 perfiles y corrección de fentry ≥ 6.1.
- [x] Decisiones AR-01, AR-02, AR-03 resueltas.
- [x] Modelo de taint con 4 niveles (D-00 a D-03) y semántica fork/COW/exec.
- [x] Taxonomía de red con 5 niveles y veredicto intermedio de alta sospecha.
- [x] FSM de observabilidad con RECOVERING y deltas por ventana.
- [x] Anclaje condicionado a conectividad con 3 estados.
- [x] Biyectividad eliminada; matriz many-to-many documentada.

### Criterios Pendientes de Ratificación
- [ ] **CR-09:** Verificación independiente del hash SHA-256 del ZIP por parte del comité.
- [ ] **CR-10:** Ratificación de prohibición de `TERMINATE_PROCESS` no supervisado en las primeras 3 fases.

---

## 8. Dictamen Final de Arquitectura

### **DICTAMEN: APPROVED WITH RESTRICTIONS**

**Justificación:**  
Las especificaciones normativas son internamente coherentes, técnicamente rigurosas y resuelven de forma verificable los 11 hallazgos originales (H-01 a H-11) más las 6 observaciones de esta revisión (AR-01 a AR-06).

**Restricciones para la Fase de Implementación:**
1. **Implementar en estricto orden de la hoja de ruta:** Event Contract → Causal Core → Profiler → Ledger → Tetragon Adapter → Enforcement → Reliability.
2. **DRY_RUN obligatorio:** Durante las fases 1 a 3, toda acción de enforcement se ejecuta exclusivamente en modo `DRY_RUN` (registro sin intervención sobre procesos del host).
3. **Prohibición de `TERMINATE_PROCESS`:** No se ejecutará ninguna terminación destructiva de procesos hasta completar la fase 6 (Enforcement) con aprobación explícita.
4. **Benchmark previo a escalamiento:** Node.js se mantiene como lenguaje del plano de control hasta que benchmarks demuestren necesidad documentada de un componente nativo.
5. **No modificar repositorios del ecosistema:** `sentinel-cloud`, `sentinel-cli`, `sentinel-oracle` y `sentinel-audit` permanecen congelados e intactos.

**Siguiente paso autorizado:**  
Al recibir ratificación del comité sobre CR-09 y CR-10, se autoriza la apertura de **Implementation Phase 001: Event Contract v1** — el normalizador de eventos y el validador de esquema con pruebas de conformidad.

No se ha escrito código. No se han realizado commits. No se ha ejecutado enforcement.  
El quinto miembro de Sentinel está listo para nacer. 🦇
