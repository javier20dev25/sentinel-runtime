# Informe técnico — Corrección y validación independiente F5-R1-R1

**Fecha:** 2026-11-08  
**Repositorio:** `C:\Users\sleyt\sentinel-runtime`  
**Ámbito:** Separación semántica de `OPERATOR_ACK` frente a `SENSOR_REPLAY_VERIFIED`, auditoría de la fuente de replay de Tetragon v1.8.0, ejecución de la suite de validación `L3-05d-R1` y sincronización con el motor de decisiones.  
**Estado:** `autoContain = false`, `dryRun = true`. Sin commit, sin push, sin enforcement.

---

## 1. Veredicto por criterio

| Criterio | Veredicto | Descripción |
|---|---|---|
| **Semántica `OPERATOR_ACK`** | **PASS** | `OPERATOR_ACK` transiciona exclusivamente a `GAP_ACKNOWLEDGED`. Mantiene `observabilityDegraded = true`. No repara ni afirma haber recuperado eventos. |
| **Gating de contención en `GAP_ACKNOWLEDGED`** | **PASS** | `DecisionEngine` permanece en estado degradado tras `OPERATOR_ACK`. Toda decisión posterior se fuerza estrictamente a `R1_OBSERVE_ONLY`. |
| **Persistencia y supervivencia a reinicio** | **PASS** | Un colector que reinicia sobre un checkpoint `GAP_ACKNOWLEDGED` restaura dicho estado y mantiene el gate de seguridad activo. |
| **Rechazo de `OPERATOR_ACK` para recuperación** | **PASS** | Cualquier intento de invocar `RECOVERY_PENDING` o `RECOVERED` con `kind: 'OPERATOR_ACK'` es rechazado con error `TypeError`. |
| **Validación estricta de evidencia de replay** | **PASS** | Esquemas de replay con ventanas temporales invertidas, secuencias invertidas, recuentos negativos, `verified !== true` o hashes corruptos son rechazados de forma determinista. |
| **Fuente de replay sobre Tetragon v1.8.0 gRPC** | **BLOCKED / NO DEMOSTRADA** | El RPC `GetEvents` de Tetragon v1.8.0 no expone cursor, offset, timestamp de inicio ni número de secuencia de origen. La recuperación por sensor gRPC directo es inviable sin una fuente durable externa out-of-band. |
| **Transición live a `RECOVERED`** | **NOT TESTED / UNAVAILABLE VIA DIRECT GRPC** | Debido a la ausencia de soporte de replay en el sensor gRPC nativo, ningún escenario live debe proclamar recuperación del stream gRPC. El sistema permanece degradado. |

---

## 2. Fase 1 — Auditoría de código

Se inspeccionaron:
- `src/collectors/tetragon-grpc.js`
- `src/intelligence/decision-engine.js`
- `test/collectors/tetragon-grpc.test.js`
- `README.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/specs/L3_EVIDENCE_REPORT_2026-11-07.md`

### Hallazgos de auditoría:
1. **`OPERATOR_ACK` aislado:** `markObservabilityGapAcknowledged(evidence)` solo acepta `kind === 'OPERATOR_ACK'`.
2. **Invariante de degradación:** En `applyObservabilityState()`, `degraded = state !== HEALTHY && state !== RECOVERED`. Por definición, `GAP_ACKNOWLEDGED !== HEALTHY` y `!== RECOVERED`, resultando en `observabilityDegraded = true`.
3. **Propagación sincronizada:** Se invoca `decisionEngine.setObservabilityState(state, degraded, reason)`. `DecisionEngine` almacena `this.observabilityState = 'GAP_ACKNOWLEDGED'` y `this.observabilityDegraded = true`.
4. **Supervivencia a segundo reinicio:** `restoreObservabilityState()` restaura explícitamente `OBSERVABILITY_STATES.GAP_ACKNOWLEDGED` si el checkpoint previo lo poseía, conservando la referencia de auditoría y manteniendo el flag de degradación.
5. **No existen bypasses:** No existe ninguna ruta en el colector ni en el CLI que mutee `observabilityDegraded` a `false` sin pasar por `markObservabilityRecovered()` con evidencia matching de `SENSOR_REPLAY_VERIFIED`.

---

## 3. Fase 2 — Auditoría de la fuente de replay (Tetragon v1.8.0 API)

Se inspeccionó la definición protobuf canónica fijada en `vendor/tetragon/v1.8.0/api/v1/tetragon/events.proto` (líneas 144–164):

```protobuf
message GetEventsRequest {
  repeated Filter allow_list = 1;
  repeated Filter deny_list = 2;
  AggregationOptions aggregation_options = 3;
  repeated FieldFilter field_filters = 4;
}
```

### Conclusiones normativas:
- `GetEventsRequest` no posee campos para reanudar stream (`offset`, `cursor`, `sequence_number`, `resume_token`).
- Los campos `source_sequence_start` y `source_sequence_end` en la evidencia de Sentinel Runtime corresponden a secuencias internas del `EvidenceLedger` local, **no a secuencias emitidas por el sensor del kernel**.
- Tetragon no garantiza la persistencia en memoria de eventos no entregados si la conexión gRPC se interrumpe.
- **Veredicto:** `SENSOR_REPLAY_VERIFIED` no puede satisfacerse a través de la interfaz gRPC estándar de Tetragon v1.8.0. Una eventual recuperación requeriría una fuente secundaria durable (ej. ingesta forense del JSON log local de Tetragon en disco o un bus intermedio). Hasta que esa fuente exista, Sentinel Runtime debe considerar que cualquier gap en el sensor gRPC es **irrecuperable en vivo**, manteniendo el estado `GAP_ACKNOWLEDGED` de forma indefinida para ese epoch.

---

## 4. Fase 3 — Resultados de la suite L3-05d-R1

Ejecutada en `test/collectors/tetragon-grpc.test.js`:

| Paso | Escenario probado | Resultado obtenido |
|---|---|---|
| **A** | Reinicio de collector con checkpoint previo `HEALTHY`. | Arranca en `DEGRADED`, razón `COLLECTOR_RESTART_PRIOR_OBSERVABILITY_HEALTHY`. |
| **B** | Detección posterior con nuevo proceso `exec-after-restart`. | `DecisionEngine` aplica gate: acción forzada a `OBSERVE_ONLY`, `observabilityStatus: 'DEGRADED'`. |
| **C** | Ejecución de `markObservabilityGapAcknowledged({ kind: 'OPERATOR_ACK', reference: 'incident-1' })`. | Colector pasa a `GAP_ACKNOWLEDGED`. `observabilityDegraded` permanece en `true`. |
| **D** | Nueva detección tras ACK. | Permanece estrictamente en `OBSERVE_ONLY`. |
| **E** | Segundo reinicio del collector sobre checkpoint `GAP_ACKNOWLEDGED`. | Colector restaura `GAP_ACKNOWLEDGED`, `observabilityDegraded` continúa en `true`, y las decisiones siguen acotadas a `OBSERVE_ONLY`. |
| **F** | Intento de recuperación usando `OPERATOR_ACK`. | `markObservabilityRecoveryPending` rechaza la llamada: `TypeError: Observability recovery evidence kind must be SENSOR_REPLAY_VERIFIED`. |
| **G** | Replay inválido (fechas invertidas, secuencias invertidas, recuento negativo, `verified: false`, hash malformado, hash no coincidente). | Todas las variaciones son rechazadas con `TypeError` o `Error` de matching. |
| **H** | Recuperación mock controlada (validación sintética de contrato en test suite con matching criptográfico completo; NO constituye replay live del sensor). | Comprueba que el validador y despachador aceptan un replay matemáticamente consistente. Solo tras validar estructura y match de hash SHA-256 pasa a `RECOVERED` y apaga `observabilityDegraded`. |

---

## 5. Fase 4 — Suite de regresión y verificación de integridad

- **Pruebas del colector:** `node --test test/collectors/tetragon-grpc.test.js` → **11 pass, 1 skip (Linux-only), 0 fail**.
- **Suite completa:** `npm test` → **260 tests, 258 pass, 2 skip (Linux-only), 0 fail**.
- **Integridad de ledger:** `ledger.verifyIntegrity().valid === true`. Las cadenas hash SHA-256 de los checkpoints y eventos se mantienen intactas a través de los múltiples reinicios.

---

## 6. Historial de evidencia y preservación

- El informe previo `docs/specs/L3_EVIDENCE_REPORT_2026-11-07.md` se conserva íntegro como registro histórico de la primera iteración exploratoria en WSL2.
- Se aclara que la transición a `RECOVERED` descrita en la corrida original de L3-05d correspondía a la versión anterior de la librería y queda formalmente superada por la arquitectura auditada en el presente documento `L3_F5_R1_CORRECTION_REPORT.md`.
