# SENTINEL RUNTIME — THREAT MODEL 001
## Adversarial Engineering, Threat Actors & Trust Boundaries

**Estado:** DRAFT / UNDER INDEPENDENT REVIEW (001-R2)  
**Fecha:** 2026-11-02  
**Repositorio:** `sentinel-runtime`  
**Ubicación:** `docs/threat-model/THREAT_MODEL_001.md`  
**Premisa Operativa Central:**  
> *Sentinel Runtime se diseña asumiendo que el adversario conoce plenamente su arquitectura interna, sus contratos de eventos, sus heurísticas de correlación, sus firmas, sus rutas de persistencia y sus umbrales de contención. La seguridad del sistema no se fundamenta en la ofuscación de su lógica ni en el desconocimiento del defensor por parte del atacante.*

---

## 1. Contexto Estratégico y Realidad Adversaria

Sentinel Runtime protege cargas de trabajo de desarrollo, CI/CD y producción frente a actores de alta persistencia y capacidad técnica avanzada (Advanced Persistent Threats - APT, operadores de ciberdelincuencia coordinada y redes de intrusión a la cadena de suministro).

### 1.1 Evidencia y Precedentes Empíricos
El diseño integra las lecciones aprendidas de investigaciones recientes y avisos formales de seguridad:
1. **FBI Public Service Announcement & DOJ Actions (13 de octubre de 2026 — DPRK IT Worker Operations)**:
   - Operaciones masivas de actores vinculados a Corea del Norte utilizando identidades robadas o ficticias, perfiles falsos en plataformas laborales, acceso remoto mediante VPN/RDP sobre equipos incautados y abuso de herramientas de administración legítimas en más de 70 organizaciones.
   - *Lección de Diseño:* Ningún indicador aislado (dirección IP, identidad de usuario, reputación de software) es suficiente para determinar confiabilidad. El runtime no confía en un proceso porque "parezca legítimo" ni en un desarrollador porque posea credenciales activas.
2. **Aviso Conjunto CISA/DoD/GovDelivery (22 de septiembre de 2026 — Operación WaterPlum / Contagious Interview)**:
   - Campañas dirigidas de ingeniería social con falsas pruebas técnicas de contratación que distribuían paquetes npm maliciosos, afectando a más de 30,000 equipos en más de 100 países y comprometiendo más de 7,000 wallets de criptoactivos.
   - *Lección de Diseño:* La ejecución de scripts de ciclo de vida (`preinstall`, `install`, `postinstall`) en entornos de desarrollo desprotegidos es el vector principal de compromiso inicial sin necesidad de privilegios de root.
3. **AWS Threat Intelligence (29 de julio de 2026 — Ataques a Bibliotecas Open Source)**:
   - Compromiso de cuentas de mantenedores legítimos en el ecosistema npm, fragmentación del comportamiento malicioso entre múltiples paquetes y bibliotecas auxiliares aparentemente inofensivas, y técnicas de activación diferida condicionadas por variables de entorno del workload.
   - *Lección de Diseño:* Los ataques modernos no se manifiestan mediante un binario monolítico detectable por antivirus; se fragmentan en micro-acciones distribuidas a través de múltiples procesos e IPCs.
4. **MITRE ATT&CK (Actualización 6 de octubre de 2026 — T1195.001)**:
   - Incorporación explícita del vector de compromiso mediante archivos de configuración e instrucciones consumidas por IDEs y agentes de programación (ej. `.vscode/tasks.json`, `.cursorrules`, configs de extensiones).
   - *Lección de Diseño:* Es imperativo auditar no solo lo que ejecuta el usuario humano, sino qué herramientas, configuraciones y extensiones automatizadas dispararon dicha ejecución.

---

## 2. Taxonomía de Niveles Adversarios Acumulativos (A0 a A4)

Los niveles A0 a A4 representan **vectores de capacidades acumulables** en los que un adversario puede iniciar en un nivel bajo e ir escalando privilegios:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ Nivel A4: Compromiso de Kernel / Hipervisor                            │
│ ── Límite de confianza in-host ──> Dependencia de Atestación Externa    │
├─────────────────────────────────────────────────────────────────────────┤
│ Nivel A3: Control de Root en Host                                       │
│ ── Capacidad ──> Detectar manipulación local, observar silenciamiento   │
├─────────────────────────────────────────────────────────────────────────┤
│ Nivel A2: Control de Contenedor / Proceso Privilegiado                 │
│ ── Capacidad ──> Detectar evasión, escape de namespaces y escalamiento │
├─────────────────────────────────────────────────────────────────────────┤
│ Nivel A1: Código Malicioso No Privilegiado en Workload                 │
│ ── Capacidad ──> Observar, correlacionar causalmente y contener        │
├─────────────────────────────────────────────────────────────────────────┤
│ Nivel A0: Compromiso de Identidad / Credenciales Legítimas             │
│ ── Capacidad ──> Actuar bajo la identidad de un operador autorizado    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Matriz de Pérdida Progresiva de Garantías de Sentinel Runtime

| Nivel de Capacidad | Privilegios del Adversario | Garantías Mantenidas por Sentinel | Garantías Perdidas / Inalcanzables |
|---|---|---|---|
| **A0: Identidad Comprometida** | Credenciales de usuario, tokens de repo válidos, sesión SSO activa. | Correlación de anomalías de comportamiento contra baseline histórico; detección de accesos no autorizados a almacenes de secretos locales. | No puede determinar si la identidad civil detrás de la sesión es legítima o un operador suplantador. |
| **A1: Código No Privilegiado** | Ejecución de scripts (`node`, `python`, `bash`) en espacio de usuario sin root. | **Plena observación y contención dentro de cobertura declarada:** captura de syscalls, construcción del Grafo Causal, suspensión de procesos (`SIGSTOP`) y aislamiento de red. | No puede inspeccionar memoria interna de procesos sin instrumentación o permisos de ptrace/eBPF. |
| **A2: Contenedor / Privilegiado** | `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, acceso a `/proc`, docker socket. | Detección de creación de namespaces huérfanos, salto de aislamiento de contenedor y desvinculación de cgroups v2. | Si el contenedor interactúa con el socket del daemon en host, puede intentar saturar el transporte. |
| **A3: Root en el Host** | Control total de espacio de usuario, `kill -9` a procesos, montaje de discos. | **Detección de ausencia por observador externo:** supervisión de cese de latidos; preservación de checkpoints ya replicados en Sentinel Cloud antes del cese. | **Se pierde la inmutabilidad local:** un root puede reescribir SQLite si controla las claves en disco. El agente no puede auto-certificar su supervivencia si es terminado (requiere observador externo). La pérdida de heartbeat solo indica `AGENT_UNRESPONSIVE` o `NODE_UNREACHABLE`, no demuestra automáticamente manipulación maliciosa confirmada. |
| **A4: Kernel / Hipervisor** | Módulos LKM maliciosos, corrupción de mapas eBPF, parcheo de syscall tables. | Ninguna garantía dentro del host comprometido. Dependencia estricta de Secure Boot, TPM 2.0 y monitorización remota fuera de banda. | El kernel puede mentirle a eBPF, a Tetragon y a Sentinel Runtime. Prometer integridad in-host ante A4 es técnicamente falso. |

---

## 3. Filosofía de "Asunción de Adversario Informado"

Sentinel Runtime descarta cualquier mecanismo basado en "Security through Obscurity". El modelo de amenazas asume que:
1. El atacante ha descargado el código fuente de Sentinel Runtime y conoce la especificación completa del contrato de eventos v1.
2. El atacante conoce los nombres de los procesos, rutas de ejecutables y sockets locales que utiliza el agente.
3. El atacante conoce los umbrales de detección y los heurísticos causales de `sentinel-cloud` y `sentinel-runtime`.
4. El atacante intentará ejecutar operaciones que permanezcan deliberadamente por debajo de los límites estáticos o distribuirá las acciones a lo largo de lapsos de tiempo prolongados.

Por tanto, las defensas se basan en:
- **Correlación Semántica Causal Ineludible:** Si un atacante necesita robar credenciales y usarlas externamente, debe interactuar con el sistema de archivos y la red. La unión de esos dos hechos en el grafo es inevitable, sin importar qué binarios use.
- **Tamper-Evidence Criptográfica de la Telemetría:** Registros encadenados mediante funciones hash (hash-chaining) que proporcionan detección de alteración retrospectiva. La propiedad de tamper-evidence requiere que los checkpoints sean anclados externamente (replicados a Sentinel Cloud o a almacenamiento append-only fuera del host) antes de que un atacante con root (A3) pueda recalcular la cadena localmente.
- **Atestación de Estado del Sensor:** Monitorización activa de la salud y tasa de muestreo de eBPF; si el sensor deja de emitir o pierde eventos, el sistema entra en modo degradado explícito.

---

## 4. Fronteras de Confianza y Límites Reconocidos

Sentinel Runtime establece explícitamente lo que **PUEDE** y lo que **NO PUEDE** resolver por sí solo:

| Capacidad Reclamada | Límite Real y Frontera Reconocida |
|---|---|
| **Atribución de Actores** | Sentinel Runtime atribuye **Tácticas, Técnicas y Procedimientos (TTPs) y linajes de procesos**. NO realiza atribución geopolítica, de nacionalidad ni de identidad civil de un operador humano. La atribución de campañas corresponde a inteligencia externa. |
| **Identidades Laborales Falsas** | Sentinel Runtime no puede determinar si un empleado remoto es un contratista genuino o un trabajador vinculado a una entidad sancionada. Su función es auditar el comportamiento del software en ejecución, independientemente de quién posea la cuenta. |
| **Inspección de Cifrado (TLS/E2EE)** | Sentinel Runtime no inspecciona arbitrariamente el contenido cifrado dentro de túneles TLS salientes de aplicaciones de terceros a menos que se configure terminación explícita autorizada. Su fortaleza reside en correlacionar *qué proceso accedió a qué recurso sensible local inmediatamente antes de establecer la conexión*. |
| **Garantía ante Kernel Corrupto** | Sentinel Runtime depende de la fidelidad del kernel Linux y del subsistema eBPF/LSM. Si el kernel está vulnerado (A4), la atestación debe residir en hardware externo (TPM) y monitorización fuera de banda. |
| **Exfiltración vs. Tráfico Benigno** | Contar bytes salientes no demuestra exfiltración de secretos. Se requiere causalidad contextual estricta entre la apertura de un almacén sensible de credenciales y la transmisión de red posterior. |
