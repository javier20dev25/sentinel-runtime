# SENTINEL RUNTIME — SPECIFICATION CROSS-VALIDATION 001 (REVISED)
**Coherence Analysis, Traceability Matrix & Readiness Assessment**  
*Document ID:* `SPEC-CROSSVAL-001r2`  
*Status:* `SUPERSEDED — HISTORICAL DESIGN REVIEW ONLY`  
*Revision:* Architecture Review 001  
*Baseline Reference:* Commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Specifications Evaluated:*
- `SPEC-EVENT-V1r2` — [`EVENT_CONTRACT_V1.md`](./EVENT_CONTRACT_V1.md)
- `SPEC-CAUSAL-V1r2` — [`CAUSAL_CORE_V1.md`](./CAUSAL_CORE_V1.md)
- `SPEC-LEDGER-V1r2` — [`EVIDENCE_LEDGER_V1.md`](./EVIDENCE_LEDGER_V1.md)
- `SPEC-TETRAGON-V1r2` — [`TETRAGON_COMPATIBILITY_V1.md`](./TETRAGON_COMPATIBILITY_V1.md)

---

> **Implementation boundary:** This document evaluates a proposed architecture against an earlier baseline. Its state-transition and enforcement tables are not evidence that those features exist in code. The repository currently runs observe-only and has no process or network enforcement provider. See [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) for implemented scope. Provider corrections for Event Contract v2 are maintained in [`EVENT_CONTRACT_PROVENANCE_MATRIX.md`](./EVENT_CONTRACT_PROVENANCE_MATRIX.md).

---

## 1. Correcciones Respecto a la Validación Anterior

### Eliminación de la Afirmación de Biyectividad (AR-06)
La versión anterior declaraba que "las 14 familias de eventos se mapean biyectivamente a las transiciones de la FSM". Esto es **incorrecto**.

La relación real es **muchos-a-muchos:**
- Un evento puede alimentar múltiples transiciones (e.g., `FILE_READ` puede contribuir a transiciones de `NORMAL→ANOMALOUS` y de `SUSPICIOUS→POLICY_VIOLATION` dependiendo del estado previo y del taint acumulado).
- Una transición puede depender de múltiples eventos (e.g., `SUSPICIOUS→POLICY_VIOLATION` requiere `FILE_READ` + `NETWORK_SEND_RESULT` + correlación causal).

---

## 2. Matriz de Trazabilidad Evento ↔ Estado ↔ Decisión (Many-to-Many)

| Familia de Evento | Estados Causales que Puede Alimentar | Requisito de Evidencia para Transición | Nivel de Confianza | Enforcement Máximo |
|---|---|---|---|---|
| `PROCESS_EXEC` | `NORMAL→ANOMALOUS` (binario no catalogado) | Binario fuera de baseline del workload | `MEDIUM` | `INCREASE_LOGGING` |
| `PROCESS_EXIT` | Sellado de cadena causal del `exec_id` | Siempre procesado (limpieza de estado) | N/A | `RECORD_ONLY` |
| `FILE_OPEN_ATTEMPT` | `ANOMALOUS→SUSPICIOUS` (acceso a ruta restringida) | Intento de apertura registrado; no demuestra lectura | `LOW` | `INCREASE_LOGGING` |
| `FILE_OPEN_RESULT` | Confirmación de apertura exitosa | `return_code >= 0` (descriptor válido) | `MEDIUM` | `INCREASE_LOGGING` |
| `FILE_READ` | `ANOMALOUS→SUSPICIOUS`, Adquisición de taint `T-01` | `bytes_read > 0` sobre recurso restringido | `HIGH` | `ISOLATE_NETWORK` |
| `NETWORK_CONNECT_ATTEMPT` | `ANOMALOUS→SUSPICIOUS` (destino no autorizado) | Destino fuera de baseline de red | `LOW` | `INCREASE_LOGGING` |
| `NETWORK_CONNECT_RESULT` | `SUSPICIOUS→POLICY_VIOLATION` (conexión establecida a C2) | `return_code == 0` hacia destino no autorizado | `MEDIUM` | `ISOLATE_NETWORK` |
| `NETWORK_SEND_ATTEMPT` | Registro de intento de transmisión | Intento de escritura en socket conectado | `LOW` | `RECORD_ONLY` |
| `NETWORK_SEND_RESULT` | `SUSPICIOUS→POLICY_VIOLATION`, `POLICY_VIOLATION→CRITICAL_COMPROMISE` | `return_code > 0` + taint `D-02`/`D-03` + destino no autorizado | `HIGH`–`VERIFIED` | `SUSPEND_PROCESS` / `TERMINATE_PROCESS` |
| `SOCKET_STATE_CHANGE` | Enriquecimiento de evidencia de red | Cambio a `TCP_ESTABLISHED`, `TCP_CLOSE` | Contextual | `RECORD_ONLY` |
| `IDENTITY_CHANGE` | `NORMAL→ANOMALOUS` (escalamiento de privilegios) | `setuid(0)` o `capset` inesperado | `HIGH` | `SUSPEND_PROCESS` |
| `CAPABILITY_CHANGE` | `NORMAL→ANOMALOUS` (adquisición de capacidad sensible) | `CAP_SYS_ADMIN`, `CAP_NET_RAW` no autorizado | `HIGH` | `SUSPEND_PROCESS` |
| `EVENT_LOSS` | `*→OBSERVABILITY_DEGRADED` (desde cualquier estado) | `delta(loss_*) > 0` en ventana actual | N/A | Prohibido escalar |
| `SENSOR_HEALTH` | `OBSERVABILITY_DEGRADED→RECOVERING` | Heartbeat recibido con contadores estabilizados | N/A | `INCREASE_LOGGING` |

---

## 3. Coherencia Cruzada entre Especificaciones

| Interfaz | Contratos | Estado | Evaluación |
|---|---|:---:|---|
| **Envelope ↔ Motor Causal** | EVENT ↔ CAUSAL | ✅ **COHERENTE** | Las 14 familias de eventos alimentan la FSM de 7 estados. Relación many-to-many documentada. |
| **Semántica de Red ↔ Veredictos** | EVENT ↔ CAUSAL | ✅ **COHERENTE** | Taxonomía de 5 niveles (AR-03) alineada. `SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED` incorporado como veredicto de alta sospecha sin autorizar terminación. |
| **Procedencia ↔ Ledger** | EVENT ↔ LEDGER | ✅ **COHERENTE** | `provenance` completo serializado en `canonical_payload` con RFC 8785 (JCS). |
| **Pérdida ↔ FSM de Observabilidad** | EVENT ↔ CAUSAL | ✅ **COHERENTE** | Deltas de contadores `loss_*` por ventana (no acumulados absolutos) activan `OBSERVABILITY_DEGRADED`. FSM incluye `RECOVERING` para retorno controlado. |
| **Taint Levels ↔ Enforcement** | CAUSAL ↔ EVENT | ✅ **COHERENTE** | `D-01` (potencial) limita confianza a `MEDIUM`. Solo `D-03` (verificado) permite `TERMINATE_PROCESS`. |
| **Tetragon ↔ Event Contract** | TETRAGON ↔ EVENT | ✅ **COHERENTE** | `exec_id` opaco en ambos. TracingPolicies mapeadas a familias de eventos. |
| **Tetragon ↔ Enforcement** | TETRAGON ↔ CAUSAL | ⚠️ **COHERENTE CON RESTRICCIÓN** | fentry en Tetragon solo soporta observabilidad; enforcement requiere kprobes. El perfil ENFORCEMENT de Tetragon se redefinió para reflejar esta limitación. |
| **Ledger ↔ Offline** | LEDGER ↔ CAUSAL | ✅ **COHERENTE** | Tres estados de anclaje definidos (`ANCHORED`, `UNANCHORED_ONLINE`, `UNANCHORED_OFFLINE`). La "garantía de 60s" es un objetivo condicionado, no una promesa absoluta. |

---

## 4. Campos Difíciles o Imposibles de Obtener

| Campo | Realidad Técnica | Resolución |
|---|---|---|
| `executable_digest` (hash SHA-256 de binario) | Calcular síncronamente en kernel durante `execve` causa bloqueos catastróficos en binarios grandes. | Opcional. Delegado a worker asíncrono o IMA del kernel. |
| Confirmación TCP ACK por paquete | Requiere programas eBPF complejos en `sockops`. | No exigido. Se mide retorno positivo de `tcp_sendmsg`. |
| Contenido semántico del payload del socket | Tetragon captura metadatos, no contenido de flujos TLS cifrados. `returnCopy` tiene limitaciones de tamaño y rendimiento. | Exfiltración confirmada se basa en correlación causal estricta, no en DPI. Se añadió veredicto intermedio `SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED`. |
| BTF en kernels < 5.10 | BTF es obligatorio para Tetragon; muchas distribuciones enterprise no lo incluyen antes de 5.10. | Perfil BASE requiere kernel con BTF. Verificación dinámica al iniciar. |
| fentry enforcement | Tetragon solo soporta fentry para observabilidad; enforcement requiere kprobes. | Perfil ENFORCEMENT usa kprobes para contención + fentry para observabilidad de baja latencia. |

---

## 5. Garantías Demostrables vs. No Demostrables

### A. Demostrables
1. **Inmunidad a PID Recycling:** 100% demostrable con `exec_id` opaco.
2. **Desacoplamiento parentesco/taint:** Demostrable con tests adversariales (AC-CC-02, AC-CC-05).
3. **Detección de manipulación del ledger:** `verifyLedgerIntegrity()` detecta alteración de un solo byte (AC-LED-02).
4. **Acotamiento de ventana anclada:** Cuando Cloud está disponible, $\le \min(60\text{s}, 500\text{ registros})$ (AC-LED-04).
5. **Determinismo causal:** Reproducible con trazas idénticas (AC-CC-04).

### B. No Demostrables
1. **Inmutabilidad bajo root compromise:** Atacante root puede recalcular hash-chain local.
2. **Garantía de anclaje sin conectividad:** Sin Cloud, la ventana no anclada crece sin límite.
3. **Causalidad con eventos perdidos:** Si eBPF descarta eventos, la cadena es incompleta.
4. **Contenido exacto de exfiltración:** El sensor no inspecciona payloads cifrados.
5. **Protección en kernels sin BTF:** Tetragon no arranca sin BTF.

---

## 6. Resolución de Decisiones Arquitectónicas AR-01, AR-02, AR-03

### AR-01 — Lenguaje del Ingestor de Tetragon
- **Decisión:** Node.js con `@grpc/grpc-js`.
- **Justificación:** Mantiene consistencia del stack tecnológico. La arquitectura desacopla el transporte del procesamiento: si se demuestra mediante benchmarks que Node.js no satisface >10,000 eventos/segundo, se introducirá un forwarder nativo como componente de infraestructura separado.
- **Riesgo Residual:** GC pauses de V8 pueden introducir latencia p99 elevada bajo carga extrema. Medición obligatoria en la fase de Reliability & Performance.

### AR-02 — Anclaje Externo
- **Decisión:** Interfaz genérica de anclaje compatible con almacenamiento append-only y Object Lock en modo `COMPLIANCE` (S3, GCS, R2).
- **Justificación:** No se modifica `sentinel-cloud` durante esta fase. El adaptador de Cloud se desarrollará bajo autorización independiente con contrato de API estable.
- **Riesgo Residual:** Sin un servicio dedicado de alta disponibilidad, la latencia de anclaje puede variar significativamente entre proveedores de Object Storage.

### AR-03 — Política ante ENOSPC
- **Decisión:** Degradación controlada sin fail-open ni fail-secure global.
- **Justificación:** Suspender workloads por disco lleno causa disrupciones de disponibilidad potencialmente más dañinas que la amenaza detectada. Descartar telemetría silenciosamente oculta evidencia.
- **Comportamiento:** Conmutar a buffer RAM, mantener TracingPolicies activas, reservar espacio de emergencia para registrar el incidente, prohibir terminaciones nuevas que dependan de evidencia no persistida.
- **Riesgo Residual:** Si el buffer RAM se satura antes de liberar disco, se perderán eventos. El contador `loss_storage_drop` se incrementará y el motor causal transitará a `OBSERVABILITY_DEGRADED`.

---

## 7. Criterios de Aceptación para Architecture Review 001

- [x] **CR-01:** Especificaciones revisadas y actualizadas con correcciones AR-01 a AR-06.
- [x] **CR-02:** Matriz de compatibilidad de kernel corregida con 3 perfiles (BASE/ADVANCED/ENFORCEMENT).
- [x] **CR-03:** Decisiones AR-01, AR-02, AR-03 resueltas y documentadas.
- [x] **CR-04:** Modelo de taint revisado con 4 niveles de propagación de datos (D-00 a D-03).
- [x] **CR-05:** Taxonomía de red ampliada a 5 niveles con `SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED`.
- [x] **CR-06:** FSM de observabilidad con estado `RECOVERING` y deltas por ventana.
- [x] **CR-07:** Anclaje externo condicionado a conectividad con 3 estados de anclaje.
- [x] **CR-08:** Afirmación de biyectividad eliminada; matriz many-to-many con 14 familias × 7 estados.
- [ ] **CR-09 (Pendiente):** Verificación independiente del hash SHA-256 del ZIP por parte del comité.
- [ ] **CR-10 (Pendiente):** Ratificación de prohibición de `TERMINATE_PROCESS` no supervisado en las primeras 3 fases de implementación.
