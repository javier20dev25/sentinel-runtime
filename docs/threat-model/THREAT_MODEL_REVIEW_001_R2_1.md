# SENTINEL RUNTIME — THREAT MODEL REVIEW 001-R2.1
## Final Consistency Audit Before Passive Sensor Reconnaissance

**Rol:** Independent Principal Security Architect  
**Baseline Git:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
**Rama:** `feature/runtime-event-contract-v1`  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/THREAT_MODEL_REVIEW_001_R2_1.md`  
**Dictamen de Salida:** **CONSISTENCY RATIFIED — APPROVED FOR PASSIVE RECONNAISSANCE 001B-0 (CODE IMPLEMENTATION REMAINS BLOCKED)**

---

## 1. Resumen Ejecutivo y Mandato de Auditoría R2.1

Esta auditoría quirúrgica resuelve de forma definitiva las inconsistencias residuales identificadas en la revisión R2 antes de dar paso a cualquier interacción con un entorno Linux real. 

### Principios Rectores Innegociables:
1. **Separación Estricta de Cuatro Dimensiones:** Ninguna capacidad se clasifica como `IMPLEMENTED` o `TESTED` a menos que exista código ejecutable y pruebas automatizadas en el repositorio actual (`fb4c5d638810e6a63cd35f68c50f5740e8db8d75`).
2. **Erradicación de Falsas Inmunidades:** Se elimina cualquier afirmación de "inmunidad absoluta" o "cobertura universal".
3. **No Inferencia Automática de Culpabilidad:** La pérdida de observabilidad (`DEGRADED` o `LOST`) nunca se interpreta como evidencia confirmada de ataque.
4. **Fase 001B de Código Bloqueada:** Esta auditoría únicamente evalúa si la especificación es coherente para avanzar a la etapa **`001B-0: Reconocimiento Pasivo de Sensor`** (solo lectura, sin enforcement, sin carga de programas eBPF).

---

## 2. Resolución Quirúrgica de los Seis Hallazgos Obligatorios

### R2.1-01 — Defensive Isolation (Requisito R-11)
- **Corrección Fundamental:** Se eliminó la afirmación de "inmunidad defensiva absoluta".
- **Definición de Aislamiento Defensivo:**
  - **Identidad Protegida del Agente:** Identificadores inequívocos de Sentinel Runtime (`tgid`, `cgroup_id`, `executable_inode`) registrados al inicio en una estructura inmutable en memoria.
  - **Exclusión en el Policy Enforcement Point (PEP):** La comprobación de auto-exclusión se aplica en la capa más baja de ejecución (`src/enforcement/`), inmediatamente antes de invocar cualquier syscall de señal (`kill`) o escribir en el pseudo-archivo de cgroups, no únicamente en la lógica heurística de detección.
  - **Protección Jerárquica de Cgroups:** Antes de solicitar un congelamiento, el PEP verifica que el cgroup objetivo **no sea un ancestro ni contenga el cgroup donde reside Sentinel Runtime o Tetragon** (`system.slice/sentinel-runtime.service`).
  - **Fallo Seguro ante Identidad Desconocida:** Si la identidad del objetivo a contener no puede resolverse con total certeza (`UNKNOWN`), **la acción de contención se aborta obligatoriamente**.
  - **Límites ante Root (A3):** Un atacante root puede manipular cgroups o enviar señales desde fuera del proceso de Sentinel; Sentinel Runtime no promete inmunidad contra acciones externas de root, sino que sus propias políticas internas jamás dispararán auto-lesión.
- **Estado de R-11:** `NOT IMPLEMENTED` — `CONDITIONAL` — `NOT TESTED` — Riesgo Residual: `CRITICAL`.

---

### R2.1-02 — Effective Policy Integrity (Requisito R-08)
- **Corrección Fundamental:** Se descartó que la coincidencia de un hash SHA-256 de un archivo YAML en disco demuestre que el sensor esté efectivamente enganchado en el kernel.
- **Arquitectura de Verificación en 6 Capas:**
  1. *Configuración Deseada:* Especificación YAML/JSON aprobada por el administrador.
  2. *Configuración Aceptada:* TracingPolicy validada y cargada por el daemon de Tetragon.
  3. *Programas BPF Cargados:* Bytecode verificado y presente en memoria del kernel.
  4. *Hooks Efectivamente Enlazados:* Enlaces `bpf_link`, kprobes y tracepoints activos en el kernel.
  5. *Eventos Recibidos:* Flujo de telemetría llegando al consumidor en espacio de usuario.
  6. *Pérdidas y Filtros Aplicados:* Contadores de descartes en kernel y exportador.
- **Criterio de Degradación:** Una discrepancia entre la configuración aceptada y los enlaces BPF activos transiciona el estado del sensor a `OBSERVABILITY_DEGRADED`. No se declara automáticamente un sabotaje intencional a menos que existan señales explícitas de desenganche forzado (`PROBE_DETACHED`).
- **Estado de R-08:** `NOT IMPLEMENTED` — `CONDITIONAL` — `NOT TESTED` — Riesgo Residual: `HIGH`.

---

### R2.1-03 — Wire-Level Resource Limits (Requisito R-06)
- **Corrección Fundamental:** Se eliminó la clasificación prematura de R-06 como parcialmente probado en lo relativo al límite de mensaje.
- **Desacoplamiento de Fronteras:**
  - *Límites de Esquema (Fase 001A - IMPLEMENTED / TESTED):* Restricciones de `maxLength` en puntos de código y `maxItems` en arrays sobre objetos JavaScript ya deserializados.
  - *Límite de Trama Wire (Fase 001B - NOT IMPLEMENTED / PENDING):* El descarte de tramas superiores a **4 MB** debe ejecutarse a nivel de búfer de red en streaming **antes de llamar a `JSON.parse`**.
  - *Límites Adicionales Requeridos en 001B:* Cota de profundidad JSON (máximo 8 niveles), rechazo de claves duplicadas a nivel de texto (RFC 8785) y presupuesto estricto de tiempo de parsing.
- **Estado de R-06:** `PARTIALLY IMPLEMENTED` (Límites de campos v1) — `DEMONSTRABLE` — `PARTIALLY TESTED` (maxLength/maxItems probados; límite de 4 MB pendiente de 001B) — Riesgo Residual: `MEDIUM`.

---

### R2.1-04 — Degraded and Lost Enforcement Safety
- **Corrección Fundamental:** Se diferenció taxativamente la seguridad operacional de la reversibilidad técnica en `DEGRADED` y `LOST`.
- **Condiciones de Acciones Reversibles (`NETWORK_ISOLATION` y `CGROUP_FREEZE`):**
  - *Precondición:* Identidad de proceso y cgroup unívocamente comprobada. Si es `UNKNOWN`, se suspende la acción.
  - *Alcance Jerárquico:* Evaluación explícita de subprocesos compartidos en el cgroup.
  - *Duración Máxima (TTL / Auto-Rollback):* Temporizador máximo (ej. 60 segundos) tras el cual, sin ratificación externa, el agente revierte el congelamiento o aislamiento de red.
  - *Preservación de Canales Críticos:* Las reglas de aislamiento de red deben contar con bypass innegociable para loopback (`127.0.0.1`), sockets de health-check locales y la IP de Sentinel Cloud.
  - *Prohibición Taxativa:* En `DEGRADED` o `LOST`, queda **estrictamente prohibido emitir `TERMINATE_PROCESS`**. El estado `LOST` no hereda acciones activas de `DEGRADED`; su función primordial es alertar al plano externo.
- **Estado de R-05:** `NOT IMPLEMENTED` — `CONDITIONAL` — `NOT TESTED` — Riesgo Residual: `HIGH`.

---

### R2.1-05 — Evidence Ledger Integrity (Requisito R-04)
- **Corrección Fundamental:** Se eliminó la presentación de SQLite WAL y mTLS como garantías suficientes de integridad probatoria.
- **Límites Forenses Formalizados:**
  - `SQLite WAL` proporciona atomicidad local (ACID), pero no protege contra modificaciones de archivos por un root local (A3).
  - `mTLS` protege el transporte, pero no acredita que los datos almacenados localmente antes del envío no hayan sido manipulados.
  - La integridad probatoria depende de la confluencia de las **7 capas**: hash individual JCS, cadena hash local, contadores monotónicos, checkpoints periódicos, **anclaje externo en Sentinel Cloud**, protocolo de recuperación atómica y detección de divergencia ante manipulación root.
- **Estado de R-04:** `NOT IMPLEMENTED` (Especificación de diseño v1) — `CONDITIONAL` — `NOT TESTED` — Riesgo Residual: `HIGH`.

---

### R2.1-06 — Metodología de Benchmarks y Métricas
- **Definición de Métricas como Hipótesis de Benchmark (No Promesas Comerciales):**
  1. *Falsos Positivos ($\le 0.001 \text{ FP / workload-hour}$):* Se ratifica que bajo el modelo de Poisson homogéneo con $k = 0$ y confianza del 95%, se requieren **$T \ge 2,996 \text{ workload-hours}$**. La prueba de 50 horas es una **prueba exploratoria de cordura**, no una demostración estadística de la cota $0.001$.
  2. *Latencia de Detección Causal ($t_{\text{detect}} \le 200 \text{ ms}$):* Medida desde el timestamp de kernel del evento desencadenante hasta la emisión del veredicto. Se reportarán percentiles $p_{50}, p_{95}, p_{99}$ y máximo observado.
  3. *Latencia de Congelamiento ($t_{\text{freeze}} \le 100 \text{ ms}$):* Medida desde `write(cgroup.freeze, 1)` hasta la confirmación `read(cgroup.events, "frozen 1")`.
  4. *Rendimiento ante Tormentas ($50,000 \text{ ev/s}$):* Eventos con tamaño medio de 1 KB, 4 vCPUs dedicadas, límite de heap 512 MB. Criterio: cero crash y reporte de pérdidas.
  5. *Contadores Independientes de Pérdida:* La pérdida de eventos no puede depender únicamente de los eventos `EVENT_LOSS` generados por el mismo flujo. Se exige consultar contadores independientes a nivel de kernel vía `sysfs` o `bpftool` (`bpf_map_lookup` sobre contadores de drop).

---

## 3. Matriz Maestra Tridimensional Reconciliada (R-01 a R-12)

| Requisito | Implementation Status | Guarantee Class | Evidence Status | Residual Risk | Prerrequisitos de Activación | Método de Prueba |
|---|:---:|:---:|:---:|:---:|---|---|
| **R-01 Process Intelligence** | `PARTIALLY IMPLEMENTED` (Envelope v1) | `DEMONSTRABLE` | `PARTIALLY TESTED` (Esquema v1) | MEDIUM | Kernel exportando `start_time_ns` y `cgroup_id`. | Test de reciclaje rápido de PID. |
| **R-02 Behavioral Correlation** | `NOT IMPLEMENTED` (Prototipo sintético) | `CONDITIONAL` | `NOT TESTED` | HIGH | Ventana deslizante en memoria, TracingPolicies activas. | Inyección de grafos causales multi-paso. |
| **R-03 Sensor Supervision** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | MEDIUM | Conexión gRPC local con daemon de Tetragon. | Watchdog ping + simulación de desconexión. |
| **R-04 Evidence Integrity** | `NOT IMPLEMENTED` (Spec v1) | `CONDITIONAL` | `NOT TESTED` | HIGH | SQLite WAL local + anclaje mTLS a Cloud. | Inyección de bytes alterados en DB local. |
| **R-05 Adaptive Containment** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | HIGH | Host con cgroups v2 montado y permisos root. | Test de FSM de `cgroup.freeze` y rollback. |
| **R-06 Exhaustion Resilience** | `PARTIALLY IMPLEMENTED` (Esquema doS) | `DEMONSTRABLE` | `PARTIALLY TESTED` (Campos schema) | MEDIUM | Límite wire de 4 MB en parser de Phase 001B. | Inyección de ráfaga de 50,000 ev/s. |
| **R-07 Fleet Autonomy** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | HIGH | Motor causal local desacoplado de Cloud. | Corte total de interfaz de red externa. |
| **R-08 Policy Integrity** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | HIGH | API de introspección BPF (`bpftool`/Tetragon). | Modificación furtiva de mapa BPF en kernel. |
| **R-09 Identity Separation** | `PARTIALLY IMPLEMENTED` (Esquema v1) | `DEMONSTRABLE` | `PARTIALLY TESTED` (Tipos v1) | LOW | Esquema Draft 2020-12 con campos de identidad. | Validación de campos de identidad 4-way. |
| **R-10 Decision Provenance** | `NOT IMPLEMENTED` | `DEMONSTRABLE` | `NOT TESTED` | LOW | Registro de eventos causales en Evidence Ledger. | Reconstrucción determinista offline. |
| **R-11 Defensive Isolation** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | CRITICAL | Lista de exclusión en PEP y chequeo jerárquico. | Intento deliberado de auto-congelamiento. |
| **R-12 Recovery Integrity** | `NOT IMPLEMENTED` | `CONDITIONAL` | `NOT TESTED` | MEDIUM | Protocolo de re-atestación previa a FULL. | Simulación de reconexión tras fallo de sensor. |

---

## 4. Matriz de Hallazgos de la Auditoría R2.1

| Identificador | Descripción del Hallazgo | Estado de Resolución | Evidencia en Documentación |
|---|---|:---:|---|
| **R2.1-01** | Eliminación de "inmunidad absoluta" y definición de PEP en R-11 | ✅ **PASS** | R-11 actualizado en `RUNTIME_SECURITY_REQUIREMENTS_001.md`. |
| **R2.1-02** | Verificación de política efectiva en 6 capas en R-08 | ✅ **PASS** | R-08 detallado con capas y criterios de degradación. |
| **R2.1-03** | Separación de límites wire (4 MB) de límites de esquema en R-06 | ✅ **PASS** | Matriz y R-06 actualizados con diferimiento a 001B. |
| **R2.1-04** | Allowlist de contención y seguridad operacional en DEGRADED/LOST | ✅ **PASS** | Matriz de allowlist y prohibición de terminación en R-06/R-05. |
| **R2.1-05** | Las 7 capas de integridad de ledger y límites ante root en R-04 | ✅ **PASS** | Desacoplamiento de SQLite/mTLS de la prueba forense. |
| **R2.1-06** | Metodología de benchmarks con percentiles y Poisson en Test Plan | ✅ **PASS** | `ADVERSARIAL_TEST_PLAN_001.md` actualizado con muestras y cotas. |

---

## 5. Lista Explícita de Afirmaciones No Verificadas (Pending Lab Validation)

Con total transparencia epistemológica, se declara que las siguientes afirmaciones **NO han sido verificadas en código ni en laboratorio**:
1. *Latencia de detección $\le 200 \text{ ms}$:* No verificada (Causal Core definitivo no está implementado).
2. *Rendimiento de $50,000 \text{ ev/s}$:* No verificado (no existe stream gRPC activo en este host).
3. *Latencia de congelamiento $\le 100 \text{ ms}$:* No verificada (requiere kernel Linux con cgroups v2 activo).
4. *Tasa de falsos positivos $\le 0.001 \text{ FP/hr}$:* No demostrada (requiere ~3,000 horas de ejecución continua).
5. *Detección de desenganche de kprobes:* No verificada (Tetragon no está conectado al agente).
6. *Límite de trama wire de 4 MB:* No verificado (el parser de red de la Fase 001B no ha sido programado).

---

## 6. Estado de Integridad Git

```text
Rama actual: feature/runtime-event-contract-v1
Commit HEAD: fb4c5d638810e6a63cd35f68c50f5740e8db8d75
Commits nuevos realizados en R2.1: 0 (Cero commits)
Modificaciones de código: 0 líneas de código modificadas
Dependencias: Cero paquetes nuevos instalados
```

---

## 7. Dictamen Final de Salida

- **Veredicto:** **`CONSISTENCY RATIFIED — APPROVED FOR PASSIVE RECONNAISSANCE 001B-0`**
- **Alcance Autorizado:** Se autoriza exclusivamente la preparación del entorno de laboratorio para la etapa pasiva de reconocimiento (`001B-0: Tetragon Environment Discovery`), consistente en inspeccionar el kernel Linux, BTF y la disponibilidad de eBPF en modo de **solo lectura**.
- **Restricción Innegociable:** La implementación de código del normalizador de eventos 001B, la carga de programas eBPF y la activación de mecanismos de enforcement **permanecen estrictamente bloqueadas**.
