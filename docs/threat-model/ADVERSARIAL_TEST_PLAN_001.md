# SENTINEL RUNTIME — ADVERSARIAL TEST PLAN 001
## Multi-Dimensional Evaluation Framework & Statistical Acceptance Criteria

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/ADVERSARIAL_TEST_PLAN_001.md`  
**Filosofía de Evaluación:**  
> *Contar pruebas unitarias que pasan en un entorno estático solo demuestra que el software procesa datos felices. Los números de rendimiento y precisión no deben ser metas arbitrarias impuestas sin sustento experimental; deben formularse como hipótesis de benchmark estadísticamente rigurosas, con tamaños de muestra calculados, intervalos de confianza explícitos y condiciones de laboratorio reproducibles.*

---

## 1. Requisitos de Infraestructura del Laboratorio

Para evitar cualquier riesgo operacional y garantizar resultados estrictamente científicos:
1. **Aislamiento Total del Host de Producción:**
   - Todas las pruebas de ejecución dinámica deben correr en entornos aislados: contenedores Linux con cgroups v2, máquinas virtuales locales (KVM / QEMU) o instancias aisladas dedicadas.
   - Prohibido realizar pruebas de contención o ejecución de muestras activas directamente sobre el host Windows de desarrollo o en infraestructura de terceros no controlada.
2. **Cero Conectividad C2 Externa:**
   - Los endpoints de red externos simulados deben apuntar a receptores locales controlados (loopback / redes virtuales privadas `10.0.0.0/24` o `198.51.100.0/24` en bridge cerrado). Ningún payload debe enviar tráfico a Internet abierta.
3. **Sensores Reales en Linux:**
   - La telemetría debe generarse desde un kernel Linux con soporte eBPF (BTF activo, kernel $\ge 5.15$ o $\ge 6.1$ para Tetragon completo) con el fin de obtener flujos auténticos de syscalls y kprobes.

---

## 2. Auditoría y Fundamentación Estadística de Métricas como Hipótesis de Benchmark

A continuación se auditan las 8 métricas propuestas, separando **aspiraciones de diseño** de **hipótesis de benchmark experimentalmente verificables**:

### Métrica 1: Tasa de Detección Causal (Hipótesis: $\ge 95\%$)
- **Definición de Latencia:** Intervalo desde el timestamp del evento desencadenante en kernel (`trigger_timestamp_ns`) hasta la emisión del veredicto causal (`verdict_timestamp_ns`).
- **Metodología:** Ejecución de 100 variantes sintéticas de los 5 escenarios adversariales con variaciones de temporización, argumentos y nombres de binarios.
- **Hardware Requerido:** VM Linux Ubuntu 22.04 LTS (4 vCPU, 8 GB RAM, kernel 6.1+).
- **Muestra y Confianza:** $n = 100$ ejecuciones. Para $\ge 95\%$ de acierto con intervalo de confianza binomial de Wilson al 95%: $\hat{p} = 0.95 \implies \text{IC}_{95\%} = [0.887, 0.979]$.
- **Evaluación por Tipo de Arista:** Medición de precisión y recall diferenciados para aristas `spawned_by`, `opened_file`, `ipc_transferred` y `connected_socket`.
- **Criterio PASS/FAIL:** PASS si $\ge 95$ de 100 variantes son detectadas como `ATTRIBUTED` o `PARTIALLY_ATTRIBUTED`.

### Métrica 2: Latencia de Detección Causal (Hipótesis: $t_{\text{detect}} \le 200 \text{ ms}$)
- **Justificación:** Ventana de tiempo necesaria para intervenir antes de que un payload complete su conexión de red saliente.
- **Metodología:** Medición del delta $t_{\text{alert}} - t_{\text{trigger\_event}}$ utilizando timestamps del kernel en nanosegundos (`timestamp_ns`).
- **Muestra:** 1,000 eventos correlacionados en ejecución continua.
- **Criterio PASS/FAIL:** PASS si el percentil 95 ($P_{95}$) es $\le 200 \text{ ms}$ en hardware estándar de prueba.

### Métrica 3: Precisión y Recall de Atribución Causal
- **Aspiración Original Descartada:** "Attribution 100% universal".
- **Garantía Redefinida:**
  - En linaje de procesos directo (PPID/TGID/exec_id): **$100\%$ determinista** en corpus sin descarte de eventos.
  - En relaciones causales multi-proceso: clasificación obligatoria en tres estados: `ATTRIBUTED`, `PARTIALLY_ATTRIBUTED`, `UNKNOWN`.
- **Criterio PASS/FAIL:** Cero falsas atribuciones (`Precision = 1.0` sobre aristas declaradas como `ATTRIBUTED`).

### Métrica 4: Resiliencia ante Tormentas de Eventos (Hipótesis: $50,000 \text{ eventos/s}$)
- **Parámetros del Experimento:** Eventos con tamaño medio de 1 KB, inyectados con distribución en ráfaga (burst de 100,000 ev/s por 5 s) y sostenida (50,000 ev/s por 60 s).
- **Hardware Requerido:** 4 vCPUs dedicadas, límite de heap Node.js fijado en 512 MB (`--max-old-space-size=512`).
- **Comportamiento Esperado:** Activación controlada de backpressure, emisión de `EVENT_LOSS` y heap de memoria estable $\le 450 \text{ MB}$.
- **Criterio PASS/FAIL:** PASS si el proceso del agente no sufre un crash/OOM y las pérdidas se contabilizan formalmente con `loss_metrics`.

### Métrica 5: Tiempo de Recuperación tras Caída de Sensor (Hipótesis: $t_{\text{recov}} \le 5 \text{ s}$)
- **Justificación:** Rapidez para transicionar a `DEGRADED_SENSOR` y reanudar al reiniciar Tetragon.
- **Metodología:** Envío de `kill -9` al daemon de Tetragon y posterior reinicio via `systemctl`.
- **Criterio PASS/FAIL:** Detección de caída en $\le 5 \text{ s}$; restablecimiento del stream gRPC y verificación de políticas en $\le 5 \text{ s}$ tras el reinicio del daemon.

### Métrica 6: Tasa de Falsos Positivos (Hipótesis Longitudinal: $\le 0.001 \text{ FP / workload-hour}$)
- **Auditoría Estadística Rigurosa:**
  - Demostrar una cota superior de falsos positivos inferior a $0.001$ por workload-hour bajo una distribución de Poisson al 95% de nivel de confianza ($1 - \alpha = 0.95$) con cero falsos positivos observados ($k = 0$) requiere:
    $$T \ge \frac{-\ln(0.05)}{\lambda} = \frac{-\ln(0.05)}{0.001} \approx 2,995.73 \text{ workload-hours}$$
  - **Prueba Exploratoria en Laboratorio:** Una suite inicial de **50 horas de ejecución continua** de pipelines benignos (Node.js builds, Go compilations, Python unit tests) es una **prueba exploratoria de cordura**, pero NO constituye una demostración matemática de la cota $0.001 \text{ FP/hr}$.
  - Se formaliza como meta longitudinal para validación en flotas reales.

### Métrica 7: Latencia de Congelamiento de cgroup ($t_{\text{freeze}} \le 100 \text{ ms}$)
- **Medición Real:** Intervalo medido desde la escritura de `cgroup.freeze = 1` hasta que la lectura de `cgroup.events` confirma `frozen 1`.
- **Criterio PASS/FAIL:** $P_{99} \le 100 \text{ ms}$ en 500 pruebas de congelamiento sobre cgroups con hasta 50 procesos hijos. Reanudación limpia comprobada (`cgroup.freeze = 0`) confirmando `frozen 0`.

### Métrica 8: Integridad Forense del Ledger
- **Garantía Real:** Verificabilidad al 100% de la cadena de bloques SHA-256 local y detección inmediata de inconsistencias ante cualquier alteración de bytes en SQLite (`TAMPER_DETECTED`).
- **Límite Reconocido:** La inmutabilidad no es in-host; depende de la replicación confirmada por Sentinel Cloud.

---

## 3. Matriz de Criterios de Aceptación por Escenario

| Escenario Adversarial | Ground Truth | Evidencia Mínima Exigida | Resultado Nominal | Par Benigno de Control | Criterio de No Disrupción |
|---|---|---|---|---|---|
| **01. npm postinstall** | Script lee claves AWS y conecta a C2 | `execve(node)` + `openat(~/.aws)` + `connect(externa)` | PARTIALLY_ATTRIBUTED | `npm install esbuild` | Tráfico a registry oficial + archivos locales |
| **02. Credential Theft** | Worker accede a `.env` y exfiltra tras 15 min | `openat(.env)` + retardo + `connect(SaaS)` | PARTIALLY_ATTRIBUTED | Worker leyendo K8s service token | Destino = API Server K8s del clúster |
| **03. IPC Splitting** | Proceso A (clave) $\to$ Pipe $\to$ B $\to$ C (`curl`) | Tracing de pipe + inodo compartido + egress | ATTRIBUTED (con IPC) / UNKNOWN (sin IPC) | Pipeline `cat \| grep \| sqlite` | Comandos estándar en build recipe |
| **04. Living off the Land** | Python `-c` dinámico descarga en RAM | `execve(python, args_anómalos)` + `connect` | ATTRIBUTED | Python ejecutando `/opt/agent.py` | Script en disco verificado por hash |
| **05. Evasión / Sabotaje** | Atacante con root ejecuta `kill -9` al agente | Captura de `sys_kill` en sensor / timeout en Cloud | NODE_UNREACHABLE / AGENT_UNRESPONSIVE | `systemctl restart` ordenado | Recepción de `SIGTERM` + graceful shutdown |
