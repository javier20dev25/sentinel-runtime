# Sentinel Runtime

**Deterministic Behavioral Security & Active Containment Engine for Cloud Workloads**

Sentinel Runtime observa lo que una aplicación hace en caliente (procesos, llamadas al sistema, accesos a archivos y destinos de red), lo contrasta contra su perfil de comportamiento esperado (*workload profile*) y ejecuta **contención graduada determinista** antes de que culmine el ataque.

---

## 1. Principios de Ingeniería

* **Zero-AI Authority en Contención**: Ningún modelo probabilístico decide si se frena o interrumpe un proceso en producción. Las decisiones de enforcement son 100% deterministas basadas en autómatas de estados finitos (FSM) y grafos causales (DAG).
* **Contención Graduada & Reversibilidad**:
  * **Nivel 1 (Normal)**: Operación en baseline.
  * **Nivel 2 (Desviación)**: Spawning no habitual -> `INCREASE_LOGGING`.
  * **Nivel 3 (Sospechoso)**: Acceso a archivos restringidos -> `SUSPEND_PROCESS` (Reversible: `SIGSTOP`).
  * **Nivel 4 (Violación)**: Conexión externa no autorizada tras recolección de credenciales -> `TERMINATE_PROCESS` (`SIGKILL`).
  * **Nivel 5 (Crítico)**: Compromiso total -> Congelamiento de contenedor y revocación de credenciales.
* **Autonomía Operativa (Fail-Safe)**: Si se desconecta la red o el servicio de Sentinel Cloud, el agente local mantiene las políticas y la capacidad de contención activa.
* **Trazabilidad Forense Local**: Toda la cadena de eventos se sella con timestamp y SHA-256 en SQLite local (`runtime.sqlite`).

---

## 2. Estructura del Repositorio

```
sentinel-runtime/
├── bin/
│   └── sentinel-runtime.js     # CLI ejecutable
├── src/
│   ├── types.js                # Definición de eventos, niveles y acciones
│   ├── profiler.js             # WorkloadProfile y límites de baseline
│   ├── engine.js               # BehavioralSequenceEngine determinista
│   └── evidence.js             # EvidenceLedger en SQLite
├── labs/
│   └── 01-proc-injection/      # Laboratorio de inyección y exfiltración causal
└── test/
    └── engine.test.js          # Pruebas unitarias de 0 FP y contención
```

---

## 3. Uso y Laboratorio

```bash
# Ejecutar los tests unitarios
npm test

# Ejecutar el laboratorio de demostración de secuencia de ataque vs. baseline
node bin/sentinel-runtime.js demo
```
