# SENTINEL RUNTIME — AUDIT CORRECTION 002
**Audit Integrity, Evidence Validation & Remediation Readiness**  
*Referencia de Commit Base:* `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Fecha:* 2026-11-02  
*Auditor:* Principal Runtime Security Engineer / Systems Security Auditor  
*Dictamen de Ingeniería:* **NOT READY FOR ENGINEERING**

---

## 1. Propósito del Documento

Este documento constituye el registro formal de la auditoría de integridad practicada sobre el informe preliminar `RUNTIME_ENGINEERING_AUDIT_001.md`. 

En la ingeniería de sistemas críticos de defensa y runtime security, ningún informe técnico puede admitir ambigüedades en criterios de aceptación, sobrestimación de capacidades destructivas, ni falta de rigor empírico en la reproducción de vulnerabilidades. Este informe documenta el historial completo de discrepancias identificadas, su análisis técnico de causa raíz y su resolución definitiva en el repositorio `sentinel-runtime`.

---

## 2. Historial de Discrepancias y Resoluciones Técnicas

### Discrepancia 1: Inconsistencia y Desalineación en la Numeración de Gates (G0 a G10)
- **Problema Detectado:** Existía una divergencia en la definición de los Gates entre el resumen emitido en el canal de chat y la matriz detallada del informe Markdown. En el chat, G0 se definió como "Separación entre simulación sintética y telemetría de kernel" y G2 como "Distinción entre CONNECT y DATA_TRANSFER", mientras que en el documento Markdown G0 correspondía a "Trazabilidad completa de capacidades" y G4 a "Diferenciación real entre conexión y exfiltración".
- **Causa Raíz:** Falta de un esquema normativo único congelado previo a la emisión del reporte preliminar.
- **Resolución Técnica:** Se adopta con carácter vinculante y único la matriz canónica definitiva:
  - **G0:** Code Traceability and Baseline.
  - **G1:** Event Contract and Provenance.
  - **G2:** Process Identity and Causal Correlation.
  - **G3:** Workload Profiler Security.
  - **G4:** Network Semantics and Exfiltration.
  - **G5:** Evidence Ledger Integrity.
  - **G6:** Real Linux Sensor Integration.
  - **G7:** Safe Runtime Enforcement.
  - **G8:** Cloud Independence and Fail-Safe.
  - **G9:** Reproducible Performance Benchmark.
  - **G10:** Documentation Accuracy.
- **Condición Transversal Independiente:** La preservación e inviolabilidad de los repositorios externos del ecosistema Sentinel (`sentinel-cloud`, `sentinel-cli`, `sentinel-oracle`, `sentinel-audit`) se extrae de la matriz de numeración y se establece como una **condición transversal de solo lectura incondicional**, aplicable en todas las fases del ciclo de vida del proyecto.

---

### Discrepancia 2: Atribución Errónea de Capacidades Destructivas Actuales en H-01 y H-02
- **Problema Detectado:** El informe preliminar afirmaba que el código actual "dispara la terminación del proceso (`SIGKILL`)" (H-01) y que "matará un proceso inocente" (H-02), describiendo el comportamiento como si el prototipo ya tuviera capacidades operativas de intervención en el sistema operativo.
- **Causa Raíz:** Confusión entre la lógica de decisión teórica de una máquina de estados y las capacidades de enforcement materializadas en el código.
- **Resolución Técnica:** Se desglosó rigurosamente la realidad del código fuente en `fb4c5d6`:
  1. *Capacidad Real Actual:* El motor `BehavioralSequenceEngine` es un componente de software que únicamente evalúa objetos JavaScript en memoria, calcula un valor en la enumeración `EnforcementAction` y llama a una función callback `this.onEnforce(decision)`. En el código existente (`labs/01-proc-injection/run-lab.js` y `test/engine.test.js`), este callback solo ejecuta `console.log()` y realiza una inserción en SQLite.
  2. *Limitación Comprobada:* El prototipo actual no contiene llamadas a `process.kill()`, ni bindings de kernel (`syscall`), ni manipula señales POSIX ni tablas de red. No puede matar ni suspender ningún proceso en el host.
  3. *Riesgo Operacional Futuro (Latente):* Se clasifica formalmente como un **defecto de diseño causal** que generaría disrupción de disponibilidad catastrófica (H-01) o terminación de procesos legítimos inocentes por reciclaje de PID (H-02) **únicamente si en el futuro se acopla un ejecutor real de sistema operativo sin corregir estos contratos**.

---

### Discrepancia 3: Ambigüedad en la Reproducción de Evasiones del Profiler (H-03)
- **Problema Detectado:** El informe original afirmaba que `/app/../../proc/self/environ` evadiría la validación de `src/profiler.js`. Sin embargo, un análisis estricto de strings revela que `'/app/../../proc/self/environ'.includes('/proc/self/environ')` evalúa a `true` por coincidencia de subcadena fortuita, lo que invalidaba la solidez del ejemplo.
- **Causa Raíz:** Ausencia de una batería de pruebas de laboratorio ejecutada de forma empírica contra las funciones del profiler.
- **Resolución Técnica:** Se ejecutaron pruebas reales en el runtime de Node.js, documentando con precisión matemática qué evade la política y qué no:
  - *Symlinks:* `ln -s /proc/self/environ /app/config.json`. Al abrir `/app/config.json`, la comprobación por subcadena falla (`false`). **Evasión Confirmada.**
  - *Rutas Relativas sin `/`:* La apertura de `etc/passwd` o `etc/shadow` desde el directorio raíz o de trabajo evalúa a `false`, porque la regla busca `'/etc/passwd'`. **Evasión Confirmada.**
  - *Directory Traversal Relativo:* `app/../etc/passwd` evalúa a `false`. **Evasión Confirmada.**
  - *Basename Spoofing:* Copiar cualquier binario malicioso a `/tmp/node` o `/dev/shm/node` evalúa a `true` en `isBinaryAllowed()`, porque `split(/[/\\]/).pop()` extrae `'node'` sin validar ruta canónica ni hash. **Evasión Confirmada.**
  - *Contexto de Contenedores:* Se añadió formalmente la advertencia técnica de que `fs.realpath()` en el host es inválido para contenedores, requiriendo resolución canónica dentro del `mount_ns` (`mnt`) del proceso inspeccionado.

---

### Discrepancia 4: Concepción Ingenua de la Inmutabilidad del Evidence Ledger (H-04)
- **Problema Detectado:** La propuesta inicial sugería que añadir una columna de hash encadenado ($H_n = \text{SHA256}(\text{Record}_n \mathbin{\Vert} H_{n-1})$) en SQLite confería inmutabilidad al ledger.
- **Causa Raíz:** Omitir el modelo de amenazas de un atacante con acceso al sistema de archivos local.
- **Resolución Técnica:** Se reformuló la arquitectura de integridad bajo un modelo formal de amenazas:
  1. *Falsa Inmutabilidad Local:* Si un atacante compromete privilegios locales o root en el host, puede modificar registros en SQLite y **recalcular toda la hash-chain localmente**. Una clave HMAC local tampoco lo mitiga si reside en la misma máquina.
  2. *Requisitos Formales Incorporados:*
     - Serialización canónica determinista según RFC 8785 (JSON Canonicalization Scheme).
     - Secuencia monotónica de 64 bits para detección de saltos.
     - Detección de truncamiento mediante checkpoints criptográficos.
     - Procedimiento obligatorio de verificación al arranque (`verifyLedgerIntegrity()`).
     - **Anclaje Externo (External Anchoring):** Publicación periódica y asíncrona de checkpoints hacia un almacenamiento inmutable externo (Sentinel Cloud Evidence Vault o bucket con Object Lock / WORM).

---

### Discrepancia 5: Imprecisiones en la Especificación de Integración con Cilium Tetragon
- **Problema Detectado:** El reporte preliminar propuso consumir logs en `/var/run/cilium/tetragon/tetragon.log` (una ruta errónea para logs persistentes) y no especificó la correlación causal nativa que Tetragon ofrece ni los tipos de eventos y tracing policies requeridas.
- **Causa Raíz:** Falta de contraste directo con la especificación y documentación técnica oficial de Cilium Tetragon.
- **Resolución Técnica:**
  - *Rutas Canónicas:* Se estableció que `/var/log/tetragon/tetragon.log` es la ruta estándar para el exportador JSON, mientras que `/var/run/cilium/tetragon/tetragon.sock` corresponde al Unix Domain Socket de la API gRPC (`FineGuidanceSensors`).
  - *Identidad Nativa de Procesos:* Se identificó que Tetragon resuelve el problema de PID Recycling en el kernel mediante `exec_id` y `parent_exec_id` (hashes base64 deterministas basados en `cgroup_id`, `pid` y `process_start_time`). Esto proporciona la solución arquitectónica limpia para G2 y H-05 sin necesidad de que Sentinel Runtime invente identificadores heurísticos frágiles.
  - *Tracing Policies Formales:* Se detallaron las políticas necesarias para enganchar kprobes en `sys_enter_openat`, `tcp_connect` y `tcp_sendmsg` para distinguir formalmente la apertura de sockets de la transmisión efectiva de datos.
  - *Pérdida de Eventos:* Se integró el tratamiento normativo de eventos descartados por saturación de buffers de anillo eBPF (`lost_events`), prohibiendo la emisión de veredictos absolutos si se compromete la fidelidad de la ventana temporal.

---

### Discrepancia 6: Diagnóstico Erróneo de Git Status y Trazabilidad del ZIP
- **Problema Detectado:** En la sesión anterior, el comando `git status` falló con código de salida 1 (`fatal: not a git repository`), lo que generó dudas sobre la estabilidad del entorno de control de versiones. Además, se desconocía con exactitud si el archivo `sentinel-runtime.zip` incluía o no los documentos de auditoría.
- **Causa Raíz:** El comando se ejecutó en el directorio de trabajo del usuario `c:\Users\sleyt` en lugar del subdirectorio `c:\Users\sleyt\sentinel-runtime`.
- **Resolución Técnica:**
  - Se confirmó que dentro de `c:\Users\sleyt\sentinel-runtime` el repositorio está en la rama `master`, con commit base `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`, con 0 cambios staged y 0 cambios unstaged en archivos rastreados.
  - Se verificó criptográficamente el hash SHA-256 de `sentinel-runtime.zip`:
    `1F6270CB55B1B49B0DFE2EE18CAFF46C5DFEA13E864D704CA20DA80E145A1D70` (10,154 bytes).
  - Se inspeccionó el catálogo interno del archivo ZIP, demostrando empíricamente que **solo contiene el snapshot limpio del commit base `fb4c5d6`**. Los informes de auditoría (`RUNTIME_ENGINEERING_AUDIT_001.md` y `RUNTIME_AUDIT_CORRECTION_002.md`) no están incluidos en el ZIP, preservando la separación estricta entre el código auditado y los artefactos de la auditoría.

---

## 3. Estado Consolidado de la Evaluación (Gates G0 a G10)

| Gate | Criterio Canónico | Veredicto | Resumen de Justificación Técnica |
| :--- | :--- | :---: | :--- |
| **G0** | **Code Traceability and Baseline** | 🟡 **PASS (CONDICIONADO)** | Commit base `fb4c5d6` identificado, HEAD consistente, 0 modificaciones en archivos rastreados y ZIP correspondiente al snapshot. *(Condicionado a verificación independiente).* La ausencia de sensores de kernel corresponde a G6, no a G0. |
| **G1** | **Event Contract and Provenance** | ❌ **FAIL** | Contrato de eventos incompleto; carece de `exec_id`, `parent_exec_id`, `cgroup_id` y firma de origen. |
| **G2** | **Process Identity and Causal Correlation** | ❌ **FAIL** | Identidad vulnerable a reciclaje de PID en Linux; sin soporte para grafos de linaje multi-proceso. |
| **G3** | **Workload Profiler Security** | ❌ **FAIL** | Comprobación ingenua susceptible a bypass por symlinks, rutas relativas y basename spoofing. |
| **G4** | **Network Semantics and Exfiltration** | ❌ **FAIL** | Decisión de terminación tomada ante simple `CONNECT`, sin verificar transferencia de datos (`SEND`). |
| **G5** | **Evidence Ledger Integrity** | ❌ **FAIL** | SQLite plano sin hash-chain, sin serialización canónica RFC 8785 y sin anclaje externo. |
| **G6** | **Real Linux Sensor Integration** | ❌ **FAIL** | 0% demostrado en código. Telemetría 100% sintética generada en memoria de JavaScript. |
| **G7** | **Safe Runtime Enforcement** | ❌ **FAIL** | 0% ejecutado en el sistema operativo. Las acciones son solo mensajes a consola y registros en DB. |
| **G8** | **Cloud Independence and Fail-Safe** | ⚠️ **UNKNOWN** | No existe integración de red para evaluar comportamiento ante fallos de conectividad. |
| **G9** | **Reproducible Performance Benchmark** | ❌ **FAIL** | Sin métricas de contrapresión, consumo de CPU/memoria ni latencias percentiles (p50/p95/p99). |
| **G10**| **Documentation Accuracy** | ❌ **FAIL** | El README original describía el componente como un motor de contención activo cuando es un prototipo pasivo. |

---

## 4. Dictamen Final y Recomendación de Ingeniería

Habiendo auditado el repositorio, corregido las contradicciones documentales, verificado empíricamente cada vulnerabilidad y cerrado la especificación de los componentes:

### **VEREDICTO DEFINITIVO: NOT READY FOR ENGINEERING**

**Condiciones Obligatorias para Autorizar la Fase 1:**  
No debe escribirse una sola línea de código en los módulos de producción hasta que se completen las siguientes tres especificaciones de ingeniería:

1. **Especificación del Contrato de Eventos v1:** Definición formal del esquema de datos que unifique la ingesta de Tetragon (`exec_id`, `parent_exec_id`, `cgroup`, namespaces, `bytes_sent`, timestamps de kernel) con procedencia garantizada.
2. **Especificación del Núcleo Causal v1:** Formalización matemática del grafo acíclico dirigido (DAG) de procesos para propagación de contaminación (*taint tracking*) y reglas de contención graduada.
3. **Especificación Criptográfica del Ledger v1:** Documento normativo de serialización canónica (RFC 8785), Hash-Chain y protocolo de emisión de checkpoints para anclaje externo.

La disciplina de ingeniería de Sentinel Runtime exige que los contratos se definan antes que el código. Solo cuando estos contratos estén formalizados se podrá levantar la restricción de implementación.
