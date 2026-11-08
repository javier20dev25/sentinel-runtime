# Informe técnico L3 — evidencia WSL2 (L3-W)

**Fecha:** 2026-11-07  
**Ámbito:** L3-03-W (reutilización de PID / correlación entre procesos), L3-05b/L3-05c (continuidad de identidad tras reinicio), L3-05d (validación live de F5-R1), auditoría F5 de reinicio, L3-04/L3-06 (integridad y latencia), y estado de L3-07.  
**Repositorio:** `/mnt/c/Users/sleyt/sentinel-runtime` (Windows: `C:\Users\sleyt\sentinel-runtime`)  
**Commit base:** `76111a966f64589f14d923fd1e02406e0129a67b` (`76111a9`)  
**Entorno:** WSL2 Ubuntu, Tetragon `v1.8.0`, kernel `6.18.54.1-microsoft-standard-WSL2`  
**Modo:** acciones destructivas deshabilitadas (`autoContain=false`); R2 se solicitó en L3-05d pero no se ejecutó; sin enforcement; sin commit.

---

> [!IMPORTANT]
> **Nota histórica de corrección (2026-11-08):** La interpretación de `OPERATOR_ACK → RECOVERED` descrita en las secciones de F5-R1 y L3-05d de este reporte representa la iteración de desarrollo previa y está **superada normativamente por [L3_F5_R1_CORRECTION_REPORT.md](L3_F5_R1_CORRECTION_REPORT.md)**. En la arquitectura corregida, `OPERATOR_ACK` transiciona exclusivamente a `GAP_ACKNOWLEDGED`, preservando `observabilityDegraded = true` y acotando toda acción a `OBSERVE_ONLY`. La transición a `RECOVERED` exige estrictamente `SENSOR_REPLAY_VERIFIED`, la cual permanece no demostrada en vivo sobre el stream gRPC directo de Tetragon v1.8.0.

---

## 1. Veredicto ejecutivo

| Caso | Veredicto | Resultado |
|---|---|---|
| L3-03-W | **PASS (L3-W)** | Tres procesos con el mismo PID de namespace; 3 `exec_id` distintos; solo el proceso C generó detecciones; 0 acciones destructivas. |
| L3-05b | **PARTIAL / UNKNOWN (L3-W)** | Post-reinicio: `host_id`, `boot_id` y PID presentes, pero `exec_id`/path nulos y `process_start_time` no coincide; continuidad no demostrada; F6 reproducido. |
| L3-05c | **PARTIAL** | F5 (propagación de degradación) verificado en vivo; F6 (identidad de proceso pre-reinicio) reproducido y ampliado; 0 detecciones post-reinicio. |
| L3-05d | **PASS (L3-W)** | Reinicio de collector con checkpoint previo `HEALTHY` restaura `DEGRADED`; detección live queda `OBSERVE_ONLY`; recuperación explícita con `OPERATOR_ACK`; nueva detección pide `PROCESS_SUSPEND` sin acción destructiva. |
| L3-04 | **PASS (L3-W, reverificado)** | 610 eventos / 357 con decisión / 253 sin decisión; ledger 640 válido; 192 detecciones históricas; 0 destructivas. |
| L3-06 | **PASS (L3-W, derivado de L3-04)** | Live n=335: p50 5.5 ms, p95 123.0 ms, p99 163.4 ms; backlog n=22 infla la vista all-ingested a ~30 s. |
| L3-07 | **PASS (L3-W)** | Matriz 3 benignos / 3 adversarios (a nivel escenario: TP=3, FN=0, FP=0, TN=3; 6 alertas de detección individuales emitidas en los 3 escenarios positivos); todas las detecciones `OBSERVE_ONLY`. |
| F5 reinicio | **PASS live (collector restart) / F6 abierto** | F5-R1 validado en L3-05d: checkpoint `HEALTHY` → collector nuevo `DEGRADED`; detección live `OBSERVE_ONLY`; recuperación solo con `OPERATOR_ACK`; después de recuperar, `PROCESS_SUSPEND` solicitado pero no ejecutado (`autoContain=false`). |
| L3-03-N | **NO EJECUTADO** | No hay host Linux nativo disponible; la reutilización de PID del host no se reprodujo en WSL2. |
| L3-05 completo | **BLOQUEADO** | F6 impide la detección de un proceso que ya existía antes del reinicio de Tetragon. F5-R1 ya está validado en vivo para reinicio de collector (L3-05d), pero L3-05 no puede cerrarse con F6 abierto. |

**Conclusión corta:** L3-03-W valida la ruta policy → identidad `exec_id` → FSM en WSL2. L3-05 sigue **PARTIAL**: L3-05b no demuestra continuidad y F6 produce un falso negativo post-reinicio. F5-R1 ya está implementado, cubierto por tests y **validado en vivo en L3-05d**: un collector nuevo sobre un checkpoint `HEALTHY` arranca `DEGRADED`, su detección live queda `OBSERVE_ONLY`, y solo una recuperación explícita con `OPERATOR_ACK` permite que la siguiente detección solicite `PROCESS_SUSPEND`; no se ejecutó ninguna acción destructiva. F6 sigue bloqueando el cierre de L3-05 para procesos preexistentes. L3-04 está íntegro y L3-06 se midió por separado: procesamiento ~1–5 ms; el retraso de ~30 s es backlog, no análisis live. No se declara cierre nativo.

---

## 2. Entorno y restricciones

- WSL2 usa un **PID namespace anidado**. El PID que ve el escenario (`process.pid`) no coincide con el PID host que ve Tetragon/collector. Por eso las policies usan `isNamespacePID: true`.
- La evidencia es **L3-W**, no cierre nativo. Los criterios de L3 exigen al menos una distribución Linux nativa y kernel nativo.
- Tetragon socket: `/var/run/cilium/tetragon/tetragon.sock`.
- Repo sin commit de los cambios de F5. `git status --short`:
  - `M src/collectors/tetragon-grpc.js`
  - `M src/intelligence/decision-engine.js`
  - `M test/collectors/tetragon-grpc.test.js`
- Suite completa tras F5-R1: **258 pass / 2 skip / 260 tests**.
- Test focalizado de PID reuse: `node --test --test-name-pattern 'PID reuse' test/intelligence/intelligence-engine.test.js` → **1/1 pass**.
- No se habilitó `autoContain`; no se ejecutaron acciones R2/R3. En L3-05d la fase degradada solicitó `OBSERVE_ONLY` y, tras recuperar, la siguiente detección **solicitó** `PROCESS_SUSPEND`; sin dispatcher y con `autoContain=false`, no se ejecutó ninguna acción destructiva.

---

## 3. L3-03-W — reutilización de PID y correlación entre procesos

### 3.1 Objetivo

Comprobar que el FSM no mezcla cadenas de procesos distintos cuando el PID visible se reutiliza, y que la identidad de kernel (`exec_id`) es la que gobierna la correlación.

### 3.2 Diseño

- Tres procesos secuenciales A, B y C, lanzados por el mismo binario de escenario.
- Se forzó el mismo PID visible de namespace (**5876**) para los tres mediante `ns_last_pid`.
- Policy PID-scoped a 5876 con `isNamespacePID: true`; probes `vfs_read` + `tcp_sendmsg`; acción `Post`.
- El escenario espera a `READY` y a un archivo `GO`; el harness espera el `PROCESS_EXEC` con `exec_id` no nulo antes de liberar la acción.
- A: lectura de `/etc/shadow`, sin envío.
- B: lectura de `/etc/hosts` + envío loopback.
- C: lectura de `/etc/shadow` + envío loopback.

### 3.3 Resultados

| Modo | PID namespace | PID host | `exec_id` | Lectura | Reads | Sends | Detecciones |
|---|---|---|---

---:|---

---:|---|---|---|---

---:|---

---:|---

---:|
| A | 5876 | 1111 | `REVTS1RPUC1LSTVBUFA0OjUwNzI2MzU5MTc5OjExMTE=` | `/etc/shadow` | 1 | 0 | 0 |
| B | 5876 | 1168 | `REVTS1RPUC1LSTVBUFA0OjU2NjQwMzcyMDI1OjExNjg=` | `/etc/hosts` | 1 | 2 | 0 |
| C | 5876 | 1201 | `REVTS1RPUC1LSTVBUFA0OjYyNDU4NDA5Nzc0OjEyMDE=` | `/etc/shadow` | 1 | 2 | 2 |

- `PROCESS_EXEC` persistidos: **3**; `exec_id` distintos: **3**; `identity_quality=PROBED_KERNEL` en los tres.
- `namespace_pid_reused_across_three_processes=true`; `host_pid_reused=false` (los PIDs host fueron distintos).
- Detecciones: **2**, ambas del `exec_id` de C (secuencias 256 y 260), regla `SUSPICIOUS_EXFILTRATION_SEQUENCE`, `HIGH`, `OBSERVE_ONLY`, `observabilityStatus=NORMAL`, 2 `evidenceReferences` cada una.
- A y B: **0 detecciones**. No hubo fusión de la lectura de A con el envío de B ni con el de C.
- Acciones destructivas: **0**.
- Ledger: `verify-ledger` válido, **283** registros, head `c4826ac94dd5c730a9492b64fb990080667bd873ae5a5c48c816cac775b47e93`.
- Test unitario de PID reuse: **PASS** (mismo `pid` host 999, `exec_id` distintos; no se mezclan cadenas).
- Evidencia: `/root/l3-evidence/l3-03/` (`results.json`, `evidence.sqlite`, `policy.json`, logs A/B/C, `unit-test.log`, `verify.json`, `sha256.txt`).

### 3.4 Interpretación y límite

La corrida demuestra que:

1. La policy PID-scoped captura eventos de los tres procesos aunque el PID visible sea el mismo.
2. El collector conserva `exec_id` distintos para cada ejecución.
3. El FSM atribuye la cadena sensible + envío únicamente a C; no hay colapso entre A, B y C.
4. El gate de acción se mantiene en `OBSERVE_ONLY`.

**Límite importante:** en WSL2 los PIDs host fueron 1111, 1168 y 1201, no el mismo PID host. Por tanto, la corrida live no ejerce el caso “mismo PID host reutilizado”; ese caso lo cubre el test unitario determinista. La variante **L3-03-N** en un host Linux nativo, con reutilización real de PID host, sigue pendiente. El veredicto correcto es **L3-03-W PASS**, no cierre nativo de L3-03.

---

## 4. L3-05c — reinicio de Tetragon con proceso longevo

### 4.1 Objetivo

Medir si, tras detener y reiniciar Tetragon, el collector:

- conserva el estado de degradación de observabilidad (F5);
- evita fabricar eventos durante el corte;
- puede correlacionar un proceso que ya existía antes del reinicio y que realiza una lectura sensible + envío después del reinicio (F6).

### 4.2 Secuencia

1. Se inicia un proceso Node longevo (`scenario_pid=989`) **antes** del reinicio.
2. Se detiene Tetragon; el collector registra los `STREAM_DISCONNECTED`.
3. Se reinicia Tetragon; el collector reconecta.
4. Se re-arma la policy **después** de la reconexión con nombre nuevo: `sentinel-l3-05c-989-post-1794018593353` (`TP_STATE_ENABLED`).
5. Se esperan **35 s** de replay.
6. El proceso lee `/etc/shadow` y hace un envío HTTP a `127.0.0.1`.
7. El escenario termina con código 0.

El primer intento reutilizó el nombre de policy previo y chocó con un pin BPF obsoleto (`/sys/fs/bpf/tetragon/grpc:<name>/... file exists`). La corrida final usa un nombre nuevo y evita esa colisión.

### 4.3 Estado del stream

| Métrica | Valor |
|---|---|---|
| `STREAM_CONNECTED` | 2 |
| `STREAM_DISCONNECTED` | 4 (reintentos) |
| `disconnect_gap_state` | `UNKNOWN` |
| `reconnect_gap_state` | `UNKNOWN` |
| `prior_checkpoint` no nulo en reconexión | `true` |
| `replay_supported` | `false` |
| `observability_degraded` en disconnect/reconnect | `true` |
| Eventos con timestamp dentro del corte explícito | 0 sourced / 0 ingested |
| `reconnect_sequence` | 148 |

No se fabricaron eventos durante el sensor-down. El gap se declara honestamente como `UNKNOWN`; no se afirma continuidad.

### 4.4 Captura post-reconexión

| Evento | `exec_id` | `executable_path` | PID | Identidad | Decisión |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `FILE_READ` `/etc/shadow` | `null` | `null` | 4585 | `PARTIAL_RECONSTRUCTED` | `DEGRADED` / `OBSERVE_ONLY` |
| `NETWORK_SEND_RESULT` (x2) | `null` | `null` | 4585 | `PARTIAL_RECONSTRUCTED` | `DEGRADED` / `OBSERVE_ONLY` |

- `PROCESS_EXEC` conocido del proceso pre-reinicio: `REVTS1RPUC1LSTVBUFA0OjUxODk0NjQzNTc1MDo0NTg1`, guardado antes del corte.
- Aun así, los kprobes posteriores no recuperaron ese `exec_id` ni el path del ejecutable.
- Detecciones: **0**. Acciones destructivas: **0**.
- Eventos post-reconexión registrados: 9 `PROCESS_EXEC`, 8 `PROCESS_EXIT`, 11 sin tipo resuelto, 1 `FILE_READ`, 2 `NETWORK_SEND_RESULT`.
- Ledger: `verify-ledger` válido, **188** registros, head `722561ee1032f9bc737fb9bab915867dcb5bfa0868b8eff86bf7221b77fd457f`.
- Evidencia: `/root/l3-evidence/l3-05c/` (`results.json`, `evidence.sqlite`, `collector.out/err`, `scenario.out/err`, `timing.txt`, `sha256.txt`).

### 4.5 F6: identidad de proceso después del reinicio

**Estado:** abierto; bloqueante para L3-05.

La corrida L3-05c demuestra que el problema no es solo el retraso de replay de ~28 s observado antes:

- El proceso ya existía antes del reinicio; su `PROCESS_EXEC` estaba persistido.
- Se esperaron 35 s después de la reconexión.
- La policy estaba armada y los kprobes se capturaron.
- Aun así, los 3 eventos relevantes llegaron `PARTIAL_RECONSTRUCTED` con `exec_id=null` y `executable_path=null`.

Consecuencia: el FSM no puede unir `FILE_READ(/etc/shadow)` + `NETWORK_SEND_RESULT`; no se produce `SUSPICIOUS_EXFILTRATION_SEQUENCE`. Es un **falso negativo post-reinicio** para procesos preexistentes, no un fallo de policy ni de captura.

Hipótesis operativa: el cache de procesos de Tetragon tras el reinicio se reconstruye con nuevas ejecuciones y no re-emite el `PROCESS_EXEC` del proceso que sigue vivo; los kprobes de ese proceso quedan sin contexto. Esperar al replay del target no es suficiente porque el target no vuelve a ejecutar.

**Opciones de mitigación (no implementadas; freeze vigente):**

1. Cache de identidad en el collector, poblado antes del gap, con `host_pid`, `boot_id`, `exec_id`, `process_start_time`; enriquecer kprobes parciales y marcarlos con procedencia (`CACHE_RECONSTRUCTED`). Debe invalidarse en `PROCESS_EXIT` y protegerse contra reutilización de PID.
2. Correlación por `pid` + `process_start_time` verificado contra `/proc/<pid>/stat` o `pidfd`; no usar solo PID.
3. Reiniciar Tetragon antes que el collector y re-calentar el cache; útil como mitigación operativa, no como solución general al reinicio del sensor.
4. Rescoping de L3-05: separar “proceso nuevo post-reinicio” (debería detectar y validar F5) de “proceso preexistente post-reinicio” (F6). No cerrar L3-05 mientras el segundo caso sea un FN.

### 4.6 F5: propagación de degradación y residual de reinicio

**Estado:** F5 en sesión corregido; **F5-R1 implementado, testeado y validado en vivo (L3-05d)**.

- `DecisionEngine.setObservabilityDegraded()` y `TetragonGrpcCollector.markObservabilityDegraded()`.
- Se activa en `STREAM_DISCONNECTED` no fatal y `COLLECTOR_QUEUE_OVERFLOW`.
- Persiste tras la reconexión dentro de la misma sesión; `STREAM_CONNECTED`/`STREAM_DISCONNECTED` reportan `observability_degraded`.
- L3-05c: las decisiones post-gap fueron `DEGRADED` / `OBSERVE_ONLY`.
- **F5-R1 implementado:** el collector mantiene un FSM `HEALTHY → GAP_DETECTED → DEGRADED → RECOVERY_PENDING → RECOVERED`; `observability_state`, motivo, timestamp y evidencia de recuperación se guardan en cada `source_checkpoint`.
- Al arrancar, cualquier checkpoint previo se restaura como `DEGRADED` (incluido un checkpoint `HEALTHY`), porque sin replay el hueco entre procesos es `UNKNOWN`. Un `GAP_DETECTED` pasa a `DEGRADED` antes de declarar `STREAM_CONNECTED`.
- La recuperación no es automática: `markObservabilityRecoveryPending(evidence)` y `markObservabilityRecovered(evidence)` exigen `kind ∈ {OPERATOR_ACK, SENSOR_REPLAY_VERIFIED}` y una referencia acotada. Hasta completar ambos pasos, `DecisionEngine` sigue bloqueando R2+.
- Tests: `Tetragon stream gap keeps subsequent detections observe-only` y `Tetragon collector restart preserves degraded observability and requires evidence to recover`; collector focalizado **11 pass / 1 skip**; suite completa **258 pass / 2 skip / 260 tests**.
- **Validación live (L3-05d):** se repitió con un proceso nuevo lanzado después de la reconexión para separar F5-R1 de F6. El collector nuevo restauró `DEGRADED`, la detección fue `OBSERVE_ONLY`, y tras `OPERATOR_ACK` la siguiente detección pidió `PROCESS_SUSPEND` sin acción destructiva. Detalle en §4.7.
- **Auditoría de reinicio original:** con un collector nuevo y `prior_checkpoint` no nulo, `STREAM_CONNECTED` reportaba `stream_gap_state=UNKNOWN` pero `observability_degraded=false`; una detección sintética podía devolver `PROCESS_SUSPEND` con `observabilityStatus=NORMAL`. Ese camino queda cubierto y bloqueado por el nuevo test de reinicio. No se ejecutó contención real (`autoContain` por defecto `false`).
- Evidencia sintética: `/root/l3-evidence/f5-audit/restart-reset.json`, sha256 `853ae9bad91f4dc488c3e5cefab5dd987c0378163100ed8949c45467d346f443`.
- **Veredicto F5:** PASS en misma sesión; **F5-R1 PASS live para reinicio de collector (L3-05d)**. No habilitar R2 automático hasta cerrar F6 y revisar el orden de durabilidad P0.

### 4.7 L3-05d — validación live de F5-R1 (reinicio de collector)

**Objetivo:** demostrar en vivo que F5-R1 no depende de tests sintéticos: un collector nuevo debe restaurar `DEGRADED` desde un checkpoint previo, bloquear la solicitud R2 mientras está degradado, y permitirla solo después de una recuperación explícita con evidencia. Para separar F5-R1 de F6, el proceso que lee `/etc/shadow` y envía por loopback se lanza **después** de la reconexión; no se reutiliza un proceso preexistente.

**Diseño:**

1. Collector #1 escribe un checkpoint inicial y se detiene con señal; el checkpoint queda `HEALTHY` (`sequence=1`, `sequence_number=0`).
2. Collector #2 abre el mismo ledger, restaura el checkpoint y arranca con `observability_state=DEGRADED`, motivo `COLLECTOR_RESTART_PRIOR_OBSERVABILITY_HEALTHY`. `STREAM_CONNECTED` reporta `prior_observability_state=HEALTHY` y `observability_state=DEGRADED`.
3. Se lanza un hijo Node nuevo (`pid=753` de namespace; PID host/Tetragon `2804`) después de la reconexión. Policy PID-scoped `sentinel-f5r1-753-1794116678887` con `vfs_read` + `tcp_sendmsg` (`isNamespacePID: true`, acción `Post`), estado `TP_STATE_ENABLED`.
4. Gate R2 autorizado en el `DecisionEngine` (`allowAutomatedSuspension=true`, `requireHumanApprovalForR2=false`) pero `autoContain=false` y sin dispatcher. Así se prueba la decisión, no la contención.
5. Primer trigger: lectura de `/etc/shadow` (678 bytes) + POST loopback (HTTP 200, 2 bytes) mientras el collector está `DEGRADED`.
6. Recuperación explícita: `markObservabilityRecoveryPending({kind:'OPERATOR_ACK', reference:'f5r1-live-1794116689189'})` y luego `markObservabilityRecovered(...)`; checkpoint `RECOVERY_PENDING` (seq 92) → `RECOVERED` (seq 94).
7. Segundo trigger con el mismo hijo y una policy vigente: lectura de `/etc/shadow` (678 bytes) + POST loopback (HTTP 200, 2 bytes) con el collector `RECOVERED`.

**Resultados:**

| Fase | Detección | `exec_id` | Identidad | Acción solicitada | `observabilityStatus` | Gate |
|---|---|---|---|---|---|---

---:|---|---|---|---|---|---|
| Degradada | seq 88, `NETWORK_SEND_RESULT` | `REVTS1RPUC1LSTVBUFA0OjE5NTIyOTIwNDkyOToyODA0` | `PROBED_KERNEL` | `OBSERVE_ONLY` | `DEGRADED` | “Observability degraded / telemetry loss active; destructive containment blocked” |
| Recuperada | seq 98, `NETWORK_SEND_RESULT` | mismo `exec_id` | `PROBED_KERNEL` | `PROCESS_SUSPEND` | `NORMAL` | sin gate de observabilidad |

- La cadena detectada en ambas fases es `SUSPICIOUS_EXFILTRATION_SEQUENCE`, `HIGH`, confianza 0.7, con referencias al `FILE_READ` y al `NETWORK_SEND_RESULT`.
- El primer trigger **no** solicitó R2: `OBSERVE_ONLY` con el gate de observabilidad. El segundo trigger **sí** solicitó `PROCESS_SUSPEND` después de la recuperación explícita.
- `autoContain=false` y sin dispatcher: **0 acciones destructivas**; la petición R2 no se ejecutó.
- Policy eliminada al final; no quedaron procesos del harness. Tetragon quedó activo y sin policies al terminar.
- Ledger final: **102 registros**, `verifyIntegrity` válido (`checked=102`), head `0414060d3ae488a54f6e7f25ef45e7f419f72c8d84dd3284bafb4d7049c3a57f`.
- Entorno de esta corrida: `host_id=sentinel-wsl2-lab`, `boot_id=fb6adb37-00e8-4018-9fcc-7b711ef95a8d`, `source_id=tetragon:d0a189c9a5d60eea5ecf5f37cf76ae002ac00ece16b43055e0fc93cbc3aa8bc0`; ventana UTC `2026-11-08T05:44:36.733Z` → `05:44:50.077Z`.
- Evidencia: `/root/l3-evidence/f5r1-live/` (`results.json`, `statuses.json`, `evidence.sqlite`, `tracing-policy.yaml`, `harness.js`, `child.js`, `run.out`, `run.err`, `sha256.txt`).
- sha256: `results.json` `84490e4ad36f4e4c928e827a240455d599d5904a58b4fc441e14a101e346af75`; DB `b2289c81d865809e1da15520300c1f52470c5fd39db65342c312a31093c78053`; `statuses.json` `0721f1207eab4413a1e46ecccde1f70ae7c49c0beb3d2ab57383a8c04da2d3ec`; policy `83aee7fa1a7563c0a940ed588805427887f375b14f201914d4a67843930f321c`.
- Nota de harness: dos intentos previos se descartaron por fallos del propio harness (timeout de carga del hijo y comparación contra el nombre de enum `R1_OBSERVE_ONLY`); no fueron fallos del motor. La corrida final es la preservada.

**Veredicto:** **PASS (L3-W)** para F5-R1 en reinicio de collector. El checkpoint degradado sobrevive, el gate de acción se ejerce en vivo y la recuperación requiere evidencia explícita. F6 sigue abierto para procesos que ya existían antes del reinicio; L3-05 no se cierra.

### 4.8 Veredicto L3-05c

**PARTIAL.** F5 está corregido y su estado se propaga correctamente dentro de la sesión, pero F6 impide la detección post-reinicio de un proceso preexistente. L3-05 no puede cerrarse con 0 detecciones en el escenario adversarial: eso es un falso negativo, no un “no ataque”.

---

## 5. L3-05b y latencia L3-04/L3-06

### 5.1 L3-05b — continuidad de identidad tras el reinicio

**Método:** análisis de la corrida live L3-05c, no una nueva corrida de sensor. Se comparó la identidad del `PROCESS_EXEC` original con los eventos post-reinicio del mismo PID. Evidencia: `/root/l3-evidence/l3-05b-identity/` (`identity-continuity.json`, hash `e990a9889572f060a195decb86fa61d9ff45c3fbbbb120defeda0bf68a5b3f78`).

| Campo | Original (pre-reinicio) | Post-reinicio (`FILE_READ` seq 175 / send seq 177) |
|---|---|---|---|---|---|
| `host_id` | `sentinel-wsl2-lab` | `sentinel-wsl2-lab` |
| `boot_id` | `00a639f4-20d6-4f06-bee3-8b2858b13851` | `00a639f4-20d6-4f06-bee3-8b2858b13851` |
| `pid` / `tid` | 4585 / 4585 | 4585 / 4585 |
| `exec_id` | `REVTS1RPUC1LSTVBUFA0OjUxODk0NjQzNTc1MDo0NTg1` | `null` |
| `executable_path` | `/root/sentinel-l3-05c-node` | `null` |
| `process_start_time` | `1794018573200961131` | `1794018658356661140` / `1794018658397471201` |
| `identity_quality` | `PROBED_KERNEL` | `PARTIAL_RECONSTRUCTED` |
| Decisión | — | `DEGRADED` / `OBSERVE_ONLY` |

- `attribution=PARTIALLY_ATTRIBUTED`: solo `host_id`, `boot_id` y PID permiten una atribución parcial.
- `continuity=UNKNOWN`, `continuity_verified=false`: PID por sí solo no demuestra continuidad con el `exec_id` original; el `process_start_time` post-reinicio es el tiempo del evento, no el start time real.
- `fabricated_process_exec=false` y `stale_exec_id_reused=false`: no se inventó un `PROCESS_EXEC` ni se reutilizó el `exec_id` viejo.
- `post_restart_scenario_process_exec_count=0`: no hubo un nuevo `PROCESS_EXEC` del escenario después del reinicio.
- **Veredicto:** L3-05b **PARTIAL / UNKNOWN**; F6 reproducido. L3-05 sigue PARTIAL.
- No se mezcló con `/root/l3-evidence/l3-05b/`, que es la evidencia anterior de L3-05.

### 5.2 L3-04 / L3-06 — integridad y latencia separada

**Integridad L3-04:** `verify-ledger` sobre `/root/l3-evidence/l3-04/evidence.sqlite` → `valid=true`, **640 registros**, head `a2ecd50a825e43ac0f8b414203321501fa8b91b2cc1637323d4b630e5542fa4b`. Conteos: 610 eventos, 3 `sensor_health`, 27 `source_checkpoint`; 357 eventos con decisión y 253 sin decisión (`event_type` no resuelto). Los 253 no soportados se excluyen de la latencia. La captura histórica fue 610/610 persistidos, 357 soportados, 253 no soportados, 0 rechazados; 192 detecciones históricas en L3-04.

**L3-06 (derivado):** se midió sobre los eventos soportados de L3-04. `source_to_ingest` usa `timestamps.source_timestamp` → `timestamps.ingest_timestamp`; `ingest_to_decision` usa `ingest_timestamp` → `decision.timestamp`; `source_to_decision` es la suma. No existe una corrida independiente `/root/l3-evidence/l3-06`.

| Vista | n | source→ingest p50 / p95 / p99 | ingest→decision p50 / p95 / p99 | source→decision p50 / p95 / p99 | max |
|---|---|---|---

---:|---|---|---|---|---|---|---

---:|
| Live post-`STREAM_CONNECTED` | 335 | 4.373 / 119.934 / 162.369 ms | 1 / 2.000 / 5 ms | **5.5 / 123.041 / 163.369 ms** | 172.146 ms |
| Backlog pre-conexión | 22 | 30040.504 / 30052.378 / 30057.566 ms | 1 / 3 / 6 ms | 30041.596 / 30055.378 / 30058.566 ms | 30058.566 ms |
| Todos los soportados | 357 | — | — | 5.696 / 30031.781 / 30050.261 ms | 30058.566 ms |

- Live `source_to_decision`: 0 negativos. Live `ingest_to_decision`: 3 negativos de ~0.00024 ms por granularidad de timestamp; el peor caso es 76 ms.
- Desglose live `source_to_decision`: `FILE_READ` n=100 p50 3.564 / p99 158.652 ms; `NETWORK_SEND_RESULT` n=200 p50 6.456 / p99 163.369 ms; `PROCESS_EXEC` n=13 p50 5.935 / p99 132.334 ms; `PROCESS_EXIT` n=22 p50 4.163 / p99 123.041 ms.
- El p99 live de **163.4 ms** cumple el objetivo de ≤500 ms en L3-W. La vista all-ingested (~30 s) está dominada por 22 `PROCESS_EXEC` backlog drenados al conectar, no por análisis en tiempo real.
- Evidencia derivada: `/root/l3-evidence/l3-04/latency-separation.json`, sha256 `54de04dfbb9e484784c5df2ca8a2714ae7c37258c2379ec8211b388b3736cbcf`.

**Veredicto:** L3-04 **PASS L3-W**; L3-06 **PASS L3-W derivado/provisional**; la latencia live cumple, pero la tasa real y el cierre nativo siguen abiertos.

---

## 6. Estado L3-W (contexto)

| Caso | Estado | Nota |
|---|---|---|---|---|---|
| L3-01 | Sin entrada independiente | La captura live está cubierta por L3-02/04/07/08; no se declara PASS propio. |
| L3-02 | PASS (L3-W) | 161/161 persistidos; detección `OBSERVE_ONLY`; ledger 174. |
| L3-03 | **PASS (L3-W)** | Esta corrida; reutilización de PID de namespace; nativo pendiente. |
| L3-04 | PASS (L3-W, reverificado) | 610 eventos; 357 con decisión; 253 sin decisión; 192 detecciones; 0 destructivas; ledger 640. |
| L3-05b | **PARTIAL / UNKNOWN (L3-W)** | Identidad post-reinicio parcialmente atribuida; `exec_id=null`; continuidad no demostrada; F6 reproducido. |
| L3-05 | **PARTIAL** | F5 corregido en sesión; F5-R1 PASS live en L3-05d (collector restart); F6 abierto; L3-05c 0 detecciones para proceso preexistente. |
| L3-06 | PASS (L3-W, derivado/provisional) | Live p99 163.4 ms; backlog n=22 con ~30 s; desglose source→ingest e ingest→decision. |
| L3-07 | PASS (L3-W) | TP=3, FN=0, FP=0, TN=3; 6 detecciones; ledger 596. |
| L3-08 | PASS (L3-W) | Checkpoint 428; dedup 62/62; 4 detecciones; ledger 534. |

Ninguno de estos resultados constituye cierre nativo del milestone. Falta la corrida en host Linux nativo y falta resolver F6.

---

## 7. Hallazgos

| ID | Estado | Resumen |
|---|---|---|---|---|---|
| L3-F1 | Abierto | El FSM no consume `NETWORK_CONNECT_RESULT`; solo `tcp_sendmsg` (`NETWORK_SEND_RESULT`) dispara la cadena. |
| L3-F2 | Abierto | Tetragon v1.8.0 no emite `label` en `sockaddr_arg` para `tcp_v4_connect`; el adapter necesita `labeled('sentinel_sockaddr')`. |
| L3-F3 | Mitigado en harness | En cold start de WSL2 se puede perder el `PROCESS_EXEC` inicial; warm-up gate + binario único + espera de `exec_id`. |
| L3-F4 | Abierto | `STREAM_CONNECTED.coverage` dice `LIVE_EVENTS_AFTER_CONNECTION_ONLY`, pero se drenan eventos backlog con timestamps previos; afecta latencia y stale FSM. |
| L3-F5 | **Corregido y validado en vivo** | Degradación de observabilidad se propaga y fuerza `OBSERVE_ONLY`; tests focalizados en verde. L3-05d ejerció el gate en vivo: detección degradada `OBSERVE_ONLY` con `observabilityStatus=DEGRADED`. |
| L3-F5-R1 | **PASS live (collector restart)** | El estado FSM se persiste en checkpoint; todo reinicio con checkpoint previo restaura `DEGRADED`; recuperación solo mediante evidencia explícita. L3-05d: `HEALTHY` → `DEGRADED` → detección `OBSERVE_ONLY` → `OPERATOR_ACK` → `RECOVERED` → `PROCESS_SUSPEND` no ejecutado. Evidencia `/root/l3-evidence/f5r1-live/`. |
| L3-F6 | **Abierto, bloqueante** | Post-reinicio, kprobes de procesos preexistentes quedan `PARTIAL_RECONSTRUCTED` sin `exec_id`; el FSM no detecta. 35 s de espera no lo resuelven. L3-05b confirma continuidad `UNKNOWN`. |

---

## 8. Riesgos y limitaciones

- **F6 produce falsos negativos** en la ventana posterior al reinicio de Tetragon para procesos que ya existían. Es el riesgo principal de detección.
- **WSL2 no reproduce reutilización de PID host**. L3-03-W valida la ruta de identidad y el FSM, pero no sustituye L3-03-N.
- **El escenario L3-05c/F6 no ejerce el gate de acción en vivo** por la ausencia de detección post-reinicio del proceso preexistente. El gate sí se ejerció en L3-05d con un proceso nuevo (degradado → `OBSERVE_ONLY`; recuperado → `PROCESS_SUSPEND` no ejecutado).
- **F5-R1 validado en vivo solo para reinicio de collector (L3-05d)**: el estado degradado se restaura desde checkpoint y la recuperación exige evidencia, pero la recuperación sigue siendo una API interna sin comando operativo ni integración CLI. F6 sigue abierto para procesos preexistentes al reinicio del sensor, por lo que L3-05 no se cierra.
- **L3-05b no demuestra continuidad**: `exec_id=null` y `process_start_time` sintético; el PID no es suficiente para atribuir los eventos al proceso original.
- **L3-06 live vs backlog**: el p99 live de 163.4 ms es válido para eventos post-conexión; la vista all-ingested (~30 s) no debe usarse como latencia del motor. La tasa real y el p99 nativo siguen abiertos.
- **F4** puede introducir latencias artificiales y eventos stale en cadenas live; no se corrigió en este bloque.
- **n pequeño** en L3-07 (6 casos) y una sola regla de secuencia; la matriz no cubre todas las rutas de detección.
- **Sin enforcement**: no se probó R2/R3 real; el freeze P0 sigue vigente. No se debe habilitar contención hasta cerrar P0 y F6.

---

## 9. Evidencia y reproducibilidad

### L3-03

- Directorio: `/root/l3-evidence/l3-03/`
- `results.json`: `pass: true`; 3 execs; 3 `exec_id`; 2 detecciones solo en C; 0 destructivas.
- `sha256.txt`: incluye DB, logs A/B/C, policy, unit-test, verify y results.
- Ledger: 283 registros; head `c4826ac94dd5c730a9492b64fb990080667bd873ae5a5c48c816cac775b47e93`.

### L3-05c

- Directorio: `/root/l3-evidence/l3-05c/`
- `results.json`: `f5_state_pass: true`; `f5_action_gate: not_exercised_due_to_no_detection`; `f6_reproduced: true`; `l3_05_pass: false`.
- `sha256.txt`: incluye DB, logs, timing y results.
- Ledger: 188 registros; head `722561ee1032f9bc737fb9bab915867dcb5bfa0868b8eff86bf7221b77fd457f`.

### L3-05d / F5-R1 (live)

- Directorio: `/root/l3-evidence/f5r1-live/`; `results.json` con `pass: true` en los 17 checks.
- Checkpoint previo `HEALTHY` (seq 1) → collector nuevo `DEGRADED` (seq 5) con motivo `COLLECTOR_RESTART_PRIOR_OBSERVABILITY_HEALTHY`.
- Detección degradada seq 88 (`OBSERVE_ONLY`, `observabilityStatus=DEGRADED`, gate de observabilidad); recuperación `RECOVERY_PENDING` seq 92 → `RECOVERED` seq 94 (`OPERATOR_ACK`, ref `f5r1-live-1794116689189`); detección recuperada seq 98 (`PROCESS_SUSPEND`, `observabilityStatus=NORMAL`, sin gate), no ejecutada (`autoContain=false`).
- Ledger: `verifyIntegrity` válido, **102** registros, head `0414060d3ae488a54f6e7f25ef45e7f419f72c8d84dd3284bafb4d7049c3a57f`.
- `sha256.txt` incluye DB, results, statuses, policy, harness, child y logs. Hashes principales: DB `b2289c81d865809e1da15520300c1f52470c5fd39db65342c312a31093c78053`; results `84490e4ad36f4e4c928e827a240455d599d5904a58b4fc441e14a101e346af75`.
- Intentos previos: `/root/l3-evidence/f5r1-live.failed-harness-1/` y `...-2/`; fallos del harness, no del motor, descartados.

### L3-05b

- Directorio: `/root/l3-evidence/l3-05b-identity/`
- `identity-continuity.json`: `attribution=PARTIALLY_ATTRIBUTED`; `continuity=UNKNOWN`; `fabricated_process_exec=false`; `stale_exec_id_reused=false`; `f6_reproduced=true`.
- sha256 del JSON: `e990a9889572f060a195decb86fa61d9ff45c3fbbbb120defeda0bf68a5b3f78`.
- La evidencia antigua `/root/l3-evidence/l3-05b/` no se modificó ni se mezcló.

### F5 — auditoría de reinicio

- Directorio: `/root/l3-evidence/f5-audit/`
- `restart-reset.json`: segunda conexión con `prior_checkpoint` no nulo, `stream_gap_state=UNKNOWN`, `observability_degraded=false`; decisión `PROCESS_SUSPEND` con `observabilityStatus=NORMAL`.
- sha256 del JSON: `853ae9bad91f4dc488c3e5cefab5dd987c0378163100ed8949c45467d346f443`.
- Es una prueba sintética con `allowAutomatedSuspension=true` y `requireHumanApprovalForR2=false`; `autoContain` no se habilitó.

### L3-04 / L3-06

- Directorio: `/root/l3-evidence/l3-04/`; `latency-separation.json` es derivado.
- Integridad: `verify-ledger` válido, 640 registros; head `a2ecd50a825e43ac0f8b414203321501fa8b91b2cc1637323d4b630e5542fa4b`.
- Latencia live n=335: source→decision p50 5.5 ms / p95 123.041 ms / p99 163.369 ms; backlog n=22: p50 30041.596 ms.
- sha256 de `latency-separation.json`: `54de04dfbb9e484784c5df2ca8a2714ae7c37258c2379ec8211b388b3736cbcf`.

### L3-07 (referencia)

- Directorio: `/root/l3-evidence/l3-07/`
- `results.json`: Escenarios clasificados TP=3, FN=0, FP=0, TN=3; 6 alertas de detección individuales emitidas en los 3 positivos (2 por escenario: secuencia sospechosa + desviación); 0 `exec_missing`; 0 `identity_missing`.
- Ledger: 596 registros; head `9b612d980451322eeb72e56109d282a87b119cd695ff4a45cda95f3014c374ba`.

### Comandos

```bash
# L3-03-W
wsl.exe -d Ubuntu -- bash /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/run_l3_03.sh

# L3-05c
wsl.exe -d Ubuntu -- bash /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/run_l3_05c.sh

# L3-05b: análisis de continuidad sobre L3-05c
wsl.exe -d Ubuntu -- node /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/analyze_l3_05b.js

# L3-05d / F5-R1: reinicio de collector y gate de observabilidad en vivo
wsl.exe -d Ubuntu -- node /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/f5r1-live.js

# F5: auditoría de reinicio
wsl.exe -d Ubuntu -- node /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/f5_restart_audit.js

# L3-04/L3-06: latencia separada
wsl.exe -d Ubuntu -- node /mnt/c/Users/sleyt/AppData/Local/Temp/opencode/analyze_l3_04_06.js

# Test focalizado
node --test --test-name-pattern 'PID reuse' test/intelligence/intelligence-engine.test.js

# Suite completa
npm test
```

---

## 10. Próximos pasos recomendados

1. **Prioridad 1 — F6:** diseñar y validar una cache de identidad de proceso en el collector para procesos preexistentes; probar con L3-05e (proceso longevo pre-reinicio + lectura/envío post-reinicio). F5-R1 ya está validado en vivo en L3-05d; no se debe atribuir el falso negativo de L3-05c a F5.
2. **Prioridad 2 — L3-03-N:** ejecutar en host Linux nativo con reutilización real de PID host; validar `isNamespacePID: false` y el FSM con `exec_id` distintos.
3. **Prioridad 3 — F4:** filtrar/marcar eventos backlog por timestamp de conexión; ajustar la afirmación de coverage y no incluir backlog en la latencia live.
4. **No cerrar L3-05** mientras el caso pre-reinicio siga siendo un falso negativo por F6.
5. **No habilitar enforcement** hasta cerrar P0 y F6; mantener `OBSERVE_ONLY` y `autoContain=false`.
6. **No commit** de los cambios F5/F5-R1 hasta que el usuario lo pida; el working tree tiene 3 archivos modificados y el informe sin commitear.

---

## 11. Conclusión

L3-03-W es una validación sólida de que la policy PID-scoped, la identidad `exec_id` y el FSM no colapsan procesos distintos con el mismo PID visible: solo C, el proceso con lectura sensible + envío, generó detecciones, y no hubo acciones destructivas.

L3-05c confirma que F5 funciona dentro de una sesión: el estado `DEGRADED` se propaga y las decisiones post-gap quedan en `OBSERVE_ONLY`. La auditoría de reinicio encontró que un collector nuevo con checkpoint previo arrancaba `NORMAL`; F5-R1 corrige ese camino y ya está validado en vivo en L3-05d: el collector nuevo restaura `DEGRADED` desde un checkpoint `HEALTHY`, la detección live queda `OBSERVE_ONLY`, y solo después de `OPERATOR_ACK` la siguiente detección solicita `PROCESS_SUSPEND`; `autoContain=false` impide la acción destructiva. L3-05b sigue mostrando que un proceso que existía antes del reinicio pierde su identidad en los kprobes posteriores (`exec_id=null`, continuidad `UNKNOWN`), y el FSM no puede detectar; la espera de 35 s no lo mitiga. Por eso L3-05 permanece abierto por F6, no por F5-R1.

L3-04 está íntegro (640 registros, ledger válido). L3-06 separado muestra que el motor decide en ~1–5 ms tras la ingesta; el p99 live source→decision es 163.4 ms, mientras que los ~30 s corresponden a 22 eventos backlog. L3-04/06 no justifican un cambio de algoritmo.

Por tanto: **L3-03-W PASS; L3-04 PASS; L3-06 PASS L3-W derivado; L3-05b PARTIAL/UNKNOWN; L3-05d/F5-R1 PASS live (collector restart); L3-05 PARTIAL por F6; sin cierre nativo; sin enforcement.**
