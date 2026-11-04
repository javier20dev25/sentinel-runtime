# SENTINEL RUNTIME — THREAT MODEL REVIEW 001-R1
## Adversarial Claims Audit & Security Requirements Validation

**Rol:** Independent Principal Security Architect  
**Fase:** Threat Model Review 001-R1  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/THREAT_MODEL_REVIEW_001_R1.md`  
**Dictamen Global:** **REVIEWED WITH CONSTRAINTS (DRAFT UPDATED / 001B BLOCKED)**

---

## 1. Resumen Ejecutivo y Mandato de Auditoría

Esta auditoría somete a revisión crítica los seis documentos de `Threat Model 001` de Sentinel Runtime para separar las **aspiraciones arquitectónicas** de las **garantías demostrables en laboratorio**, eliminando falsas promesas de seguridad y formalizando los límites del agente frente a adversarios avanzados (APTs, redes de trabajadores de TI de la RPDC, campañas como WaterPlum/Contagious Interview y ataques de cadena de suministro en código abierto documentados por AWS y MITRE).

### Resoluciones Innegociables del Review 001-R1:
1. **Cambio de Estado Normativo:** Todos los documentos de `Threat Model 001` se reclasifican formalmente a **`DRAFT / UNDER INDEPENDENT REVIEW`**. No se elevarán a definitivos sin ratificación explícita fundamentada en evidencia de laboratorio.
2. **Fase 001B Bloqueada:** La implementación del normalizador Tetragon permanece estrictamente congelada hasta contar con el entorno de telemetría real y las garantías acotadas.
3. **Cero Supuesto de Ignorancia:** El diseño asume que el adversario conoce plenamente el código, los heurísticos y los umbrales de Sentinel Runtime.

---

## 2. Auditoría Detallada de los Seis Hallazgos Críticos (TM-01 a TM-06)

### TM-01 — Auditoría Estadística de Métricas Cuantitativas
- **Defecto Detectado:** El documento inicial fijaba metas numéricas rígidas ($\ge 95\%$ detección, $\le 200 \text{ ms}$ latencia, $100\%$ atribución, $50,000 \text{ ev/s}$, $\le 0.001 \text{ FP/hora}$) sin justificación matemática ni metodología de muestreo.
- **Resolución Metodológica:**
  - Se convierten de "gates de producción" a **hipótesis de benchmark**.
  - **Prueba del Límite de Falsos Positivos ($\le 0.001 \text{ FP / workload-hour}$):**  
    Bajo una distribución de Poisson para eventos raros con $k = 0$ falsos positivos observados y un nivel de confianza unilateral del 95% ($1 - \alpha = 0.95$):
    $$T \ge \frac{-\ln(0.05)}{\lambda} = \frac{-\ln(0.05)}{0.001} \approx 2,995.73 \text{ workload-hours}$$
    *Dictamen:* Demostrar contractualmente $\le 0.001 \text{ FP/hr}$ requiere **~3,000 horas de ejecución continua de workloads benignos sin un solo fallo**. Declararlo en pruebas de laboratorio de 10 minutos es metodológicamente inválido. Se define como una meta longitudinal de flota.

---

### TM-02 — Atribución Causal Tripartita vs. Promesa de Atribución 100%
- **Defecto Detectado:** Afirmar "100% de atribución" prometía reconstruir todas las relaciones causales de un ataque real, ignorando pérdidas de eventos o canales opacos.
- **Resolución Metodológica:** Se define formalmente una clasificación tripartita obligatoria para todo veredicto:
  - **`ATTRIBUTED`:** Relación causal y linaje demostrados completamente mediante evidencia ininterrumpida de kernel.
  - **`PARTIALLY_ATTRIBUTED`:** Se comprueba el acceso al recurso sensible y la conexión anómala, pero existen eslabones intermedios no observados (ej. memoria de heap sin inspeccionar).
  - **`UNKNOWN`:** Evidencia fragmentada o eventos perdidos. Sentinel Runtime tiene la **obligación de abstenerse** en lugar de inventar aristas causales en el grafo.

---

### TM-03 — Causalidad de Datos vs. Asociación de Recursos en IPC
- **Defecto Detectado:** El escenario de IPC afirmaba que si Proceso A lee claves SSH, Proceso B escribe en un archivo temporal y Proceso C ejecuta `curl`, se "demuestra" la exfiltración.
- **Resolución Metodológica:** Se formaliza la matriz de capacidad por fuente de telemetría:
  - *Syscall Tracing (Tetragon estándar):* Demuestra **relación de procesos** y **relación de recursos** (apertura de inodos).
  - *Pipes anónimos / memoria compartida:* Requieren TracingPolicies específicas de IPC; sin ellas, el paso de datos entre procesos es **propagación potencial**, no observada.
  - *Exfiltración confirmada:* Requiere **procedencia a nivel de bytes** (inspección de payload o terminación TLS). Sin esto, el veredicto es estrictamente **correlación sospechosa (PARTIALLY_ATTRIBUTED)**.

---

### TM-04 — Supervisión de Salud en 5 Capas vs. Heartbeat Ingenuo
- **Defecto Detectado:** Un heartbeat de 5 segundos solo demuestra que el daemon emisor está vivo, no que las sondas de kernel estén capturando eventos.
- **Resolución Metodológica:** Se descompone la salud en 5 estados independientes y jerárquicos:
  1. `AGENT_ALIVE`: Proceso de espacio de usuario activo.
  2. `SENSOR_OPERATIONAL`: Daemon Tetragon activo con eBPF cargado.
  3. `POLICY_OPERATIONAL`: TracingPolicies activas y sin alteración de hash SHA-256.
  4. `EVENT_STREAM_HEALTHY`: Canal gRPC sin saturación ni descarte.
  5. `OBSERVABILITY_COMPLETE`: Cobertura de eventos verificada al 100%.
- **Observador Externo:** Si un atacante con root envía `kill -9` al daemon, el propio agente no puede auto-reportar su caída; se exige un watchdog local y la detección de vencimiento de latidos en Sentinel Cloud (`NODE_LOST`).

---

### TM-05 — Niveles A1-A4 como Capacidades Acumulativas
- **Defecto Detectado:** Tratar A1-A4 como categorías estáticas y asumir que un agente local puede resistir indefinidamente a un root (A3).
- **Resolución Metodológica:**
  - Los niveles son acumulables (el atacante inicia en A0 con credenciales robadas y escala a A1, A2, A3).
  - En **A3 (Root en host)**, el agente **pierde la inmutabilidad local** y solo puede garantizar detección de sabotaje y notificación remota previa.
  - En **A4 (Kernel comprometido)**, se reconoce el límite teórico absoluto in-host: el kernel puede mentirle a eBPF. Se depende exclusivamente de Secure Boot, TPM 2.0 y monitorización fuera de banda.
  - Se reafirma: Sentinel atribuye **TTPs y linajes técnicos**, jamás nacionalidades ni identidades civiles.

---

### TM-06 — Límites de Seguridad en Contención (Anti-Self-DoS)
- **Defecto Detectado:** Promover `SIGSTOP` y congelamiento de cgroups sin evaluar efectos secundarios destructivos en workloads de producción.
- **Resolución Metodológica:**
  - `SIGSTOP` es reversible a nivel de señales (`SIGCONT`), pero puede inducir **deadlocks de kernel, timeouts de clientes TCP y acumulación descontrolada de memoria**.
  - `CGROUP_FREEZE` es atómico y preferido sobre señales POSIX individuales.
  - `TERMINATE_PROCESS` es **completamente irreversible** y exige autorización explícita de política.
  - **Inmunidad Defensiva:** Ninguna regla de contención puede aislar ni congelar los sockets, archivos ni procesos de Sentinel Runtime o Tetragon.

---

## 3. Matriz de Requisitos y Nivel de Garantía (Master Verification Matrix)

Estados de Garantía:
- **`DEMONSTRABLE`:** Verificable de forma determinista en laboratorio con la instrumentación actual.
- **`CONDITIONAL`:** Verificable solo si se cumplen precondiciones estrictas (ej. sin pérdida de eventos, cgroups v2 activo).
- **`PENDING INSTRUMENTATION`:** Requiere sondas eBPF adicionales o parsers no implementados aún.
- **`NOT DEMONSTRABLE`:** Matemáticamente inalcanzable in-host bajo el modelo de amenazas (ej. inmutabilidad total ante root o kernel comprometido).

| Requisito | Nivel de Garantía | Fuente de Evidencia | Método de Prueba | Limitación Reconocida |
|---|:---:|---|---|---|
| **R-01.1 Identidad Compuesta** | `DEMONSTRABLE` | `PROCESS_EXEC` de Tetragon | Batería con reciclaje rápido de PID | Requiere acceso a `start_time_ns` y `cgroup_id` del kernel. |
| **R-01.2 Namespaces Tracking** | `DEMONSTRABLE` | Descriptores de inodo de namespaces | Llamada a `unshare()` / `clone3()` | Detecta creación, no previene el salto sin BPF LSM. |
| **R-02.1 Grafo Causal (CEG)** | `DEMONSTRABLE` | Eventos de syscalls en memoria | Reconstrucción de grafo en DAG | Acotado por ventana deslizante en memoria RAM. |
| **R-02.2 Taint Propagation** | `CONDITIONAL` | Aristas del CEG | Apertura de secretos + subprocesos | No demuestra uso real de memoria sin byte-level taint. |
| **R-02.3 Veredicto Tripartito** | `DEMONSTRABLE` | Motor de decisión causal | Pruebas con eventos suprimidos | Obligación de emitir `UNKNOWN` ante datos incompletos. |
| **R-03.1 Detección Desenganche** | `DEMONSTRABLE` | API BPF de kernel (`bpftool`) | Descarga forzada de kprobe | Requiere sondeo periódico (latencia de detección $\approx 2 \text{ s}$). |
| **R-03.2 TracingPolicy Hash** | `DEMONSTRABLE` | Hash SHA-256 en memoria vs disco | Modificación furtiva de regla YAML | Protege configuración estática, no memoria de Tetragon. |
| **R-03.3 Muerte del Agente** | `CONDITIONAL` | Watchdog de nodo y Sentinel Cloud | `kill -9` al daemon | **Requiere observador externo.** El agente no puede reportar su fin. |
| **R-04.1 Tamper-Evident Ledger** | `DEMONSTRABLE` | Hash-chain SHA-256 en SQLite | Modificación manual de bytes en DB | Ofrece **tamper-evidence**, NO inmutabilidad absoluta in-host. |
| **R-04.2 Anclaje Externo** | `CONDITIONAL` | Replicación mTLS a Cloud | Corte de red antes del anclaje | Si el nodo se desconecta antes de replicar, root puede borrarlo. |
| **R-04.3 Poda Condicionada** | `DEMONSTRABLE` | Tabla de cabeceras + checkpoints | Llenado de disco con podas | Prohibida la poda si el bloque no tiene acuse de recibo de Cloud. |
| **R-05.1 Contención Cgroup** | `DEMONSTRABLE` | Interfaz `cgroup.freeze` en v2 | Congelamiento de proceso sospechoso | Requiere cgroups v2 en el host Linux. |
| **R-05.2 Inmunidad del Plano** | `DEMONSTRABLE` | Reglas de exclusión en motor | Intento de contención contra Sentinel | Bloqueo absoluto de autoreglas lesivas. |
| **R-05.3 Terminación Irreversible** | `CONDITIONAL` | Envío de `SIGKILL` | Prueba con política permisiva | Requiere flag explícito de política; prohibido por defecto. |
| **R-06.1 Límite Wire (4 MB)** | `PENDING INSTRUMENTATION` | Parser de streaming en red (001B) | Envío de trama JSON de 10 MB | Pertenece a la frontera de ingestión de Phase 001B. |
| **R-06.2 Modos Observabilidad** | `DEMONSTRABLE` | Métricas de ring buffer del kernel | Inyección de tormenta de syscalls | Transición explícita a `DEGRADED` ante pérdidas. |
| **R-07.1 Autonomía Desconectada** | `DEMONSTRABLE` | Motor causal local | Ejecución sin interfaz de red externa | La contención local opera en $\le 5 \text{ ms}$ sin llamar a Cloud. |

---

## 4. Modos Operativos Explícitos de Observabilidad

Sentinel Runtime formaliza tres modos operativos obligatorios:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ 1. OBSERVABILITY_FULL                                                  │
│    Sensores, políticas, streams y ledger al 100%. Pérdida = 0.         │
│    Veredictos emitidos con confianza nominal plena.                    │
├────────────────────────────────────────────────────────────────────────┤
│ 2. OBSERVABILITY_DEGRADED                                              │
│    Pérdida en ring buffer (>0), probes retrasadas o disco al 90%.      │
│    Veredictos etiquetados con advertencia; contención preventiva.      │
├────────────────────────────────────────────────────────────────────────┤
│ 3. OBSERVABILITY_LOST                                                  │
│    Cese de stream >5 s, probes desenganchadas o agente terminado.      │
│    Señal de emergencia a Cloud; fail-secure o fail-safe configurable.  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Dictamen Final y Hoja de Ruta

- **Threat Model 001:** Actualizado a estándar de ingeniería riguroso, formalizando límites, hipótesis estadísticas y supervisión multicapa.
- **Estado de Documentos:** `DRAFT / UNDER INDEPENDENT REVIEW`.
- **Fase 001B:** Se mantiene **ESTRICTAMENTE BLOQUEADA** hasta recibir autorización formal del usuario para iniciar la etapa pasiva `001B-0` (reconocimiento de entorno real en Linux).
