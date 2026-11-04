# SENTINEL RUNTIME — EVIDENCE LEDGER V1
**Normative Specification: Tamper-Evident Forensic Ledger & External Anchoring**  
*Document ID:* `SPEC-LEDGER-V1`  
*Status:* `FROZEN_FOR_REVIEW`  
*Baseline Reference:* Commit `fb4c5d638810e6a63cd35f68c50f5740e8db8d75`  
*Classification:* Technical Normative Contract

---

## 1. Principios Fundamentales del Evidence Ledger

El **Evidence Ledger v1** es el subsistema de persistencia probatoria de Sentinel Runtime. Su objetivo es transformar la telemetría efímera y las decisiones de contención en un registro forense verificable, resistente a la alteración y admisible en auditorías de seguridad e investigaciones judiciales.

### Axioma de Realidad Operacional (H-04 & H-11):
> **Ningún archivo local en disco ni ninguna tabla SQLite es "inmutable" por sí misma frente a un atacante con privilegios de root en el host.**  
> Un atacante que comprometa el sistema operativo puede modificar bytes en disco, alterar registros en SQLite y recalcular cualquier cadena de hashes o firmas locales.  
> Por tanto, la garantía técnica de Sentinel Runtime es **Tamper-Evident (Evidencia Demostrable de Manipulación)** respaldada por **Anclaje Criptográfico Externo Asíncrono (External Anchoring)**.

---

## 2. Serialización Canónica (RFC 8785)

Para que el hashing criptográfico sea determinista a través de diferentes plataformas, compiladores y lenguajes, el payload de cada incidente o evento a registrar debe serializarse utilizando el estándar **RFC 8785 (JSON Canonicalization Scheme - JCS)** antes de computar cualquier resumen criptográfico.

### Reglas Normativas de Serialización JCS:
1. **Ordenación de Claves:** Las claves de todos los objetos JSON deben ordenarse lexicográficamente según sus secuencias de unidades de código UTF-16.
2. **Espaciado en Blanco:** No deben existir espacios en blanco redundantes, saltos de línea ni tabuladores entre elementos sintácticos (delimitadores `:` y `,` sin espacios).
3. **Representación de Números:** Los números enteros y de coma flotante deben serializarse según las reglas de ECMAScript / IEEE 754 (ej. sin ceros no significativos a la derecha en fracciones, sin prefijos `+`).
4. **Codificación de Caracteres:** La salida debe ser estrictamente UTF-8 sin Byte Order Mark (BOM).

---

## 3. Arquitectura Criptográfica: Hash-Chain Monotónica

Cada registro persistido en el Evidence Ledger se encadena matemáticamente con el registro inmediatamente anterior formando una cadena de hashes lineal e ininterrumpida.

```text
Bloque Génesis (Seq 0)
H_0 = SHA256("SENTINEL_RUNTIME_LEDGER_GENESIS_V1")
       │
       ▼
Registro 1 (Seq 1)
H_1 = SHA256( H_0  ||  Seq: 1  ||  JCS(Payload_1) )
       │
       ▼
Registro 2 (Seq 2)
H_2 = SHA256( H_1  ||  Seq: 2  ||  JCS(Payload_2) )
       │
       ▼
Registro n (Seq n)
H_n = SHA256( H_{n-1}  ||  Seq: n  ||  JCS(Payload_n) )
```

### 3.1 Fórmulas Matemáticas de Integridad
- **Bloque Génesis ($n = 0$):**
  $$H_0 = \text{SHA256}(\text{"SENTINEL\_RUNTIME\_LEDGER\_GENESIS\_V1"})$$
- **Registro $n$ ($n \ge 1$):**
  $$H_n = \text{SHA256}\Big( H_{n-1} \mathbin{\Vert} \text{Uint64BE}(\text{Seq}_n) \mathbin{\Vert} \text{JCS}(\text{RecordPayload}_n) \Big)$$
  Donde:
  - $\text{Seq}_n$: Entero monotónicamente creciente sin saltos ($1, 2, 3, \dots, 2^{64}-1$).
  - $\text{Uint64BE}$: Representación binaria de 8 bytes en formato Big-Endian.
  - $\mathbin{\Vert}$: Concatenación binaria de bytes.

---

## 4. Esquema de Base de Datos SQLite y Configuración de Almacenamiento

El ledger se almacena localmente en SQLite bajo directivas estrictas de integridad ACID y tolerancia a fallos:

### 4.1 Pragmas Obligatorios de SQLite
```sql
PRAGMA journal_mode = WAL;          -- Write-Ahead Logging para lecturas y escrituras concurrentes
PRAGMA synchronous = FULL;          -- fsync() forzado en cada commit para evitar corrupción por corte eléctrico
PRAGMA foreign_keys = ON;           -- Integridad referencial habilitada
PRAGMA auto_vacuum = NONE;          -- Prevenir reordenamientos automáticos que alteren la inspección física
```

### 4.2 Esquema DDL Relacional

```sql
-- Tabla principal de incidentes y evidencia encadenada
CREATE TABLE IF NOT EXISTS evidence_records (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,      -- Secuencia monotónica estricta
  record_id TEXT NOT NULL UNIQUE,             -- UUIDv7 del registro
  timestamp INTEGER NOT NULL,                 -- Nanosegundos UTC de inserción
  workload_id TEXT NOT NULL,                  -- Identificador del workload
  exec_id TEXT NOT NULL,                      -- exec_id opaco del proceso actor
  threat_level INTEGER NOT NULL,              -- 1 a 5 según types.js
  action TEXT NOT NULL,                       -- RECORD_ONLY, TERMINATE_PROCESS, etc.
  reason TEXT NOT NULL,                       -- Justificación causal
  canonical_payload TEXT NOT NULL,            -- String JCS exacto auditado
  prev_hash TEXT NOT NULL,                    -- Hash hex SHA-256 del registro (seq - 1)
  record_hash TEXT NOT NULL UNIQUE            -- Hash hex SHA-256 de este registro (H_n)
);

-- Tabla de checkpoints locales y anclajes externos
CREATE TABLE IF NOT EXISTS evidence_checkpoints (
  checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,                -- Nanosegundos UTC
  start_seq INTEGER NOT NULL,                 -- Primera secuencia cubierta
  end_seq INTEGER NOT NULL,                   -- Última secuencia cubierta
  start_hash TEXT NOT NULL,                   -- H_{start_seq - 1}
  end_hash TEXT NOT NULL,                     -- H_{end_seq}
  record_count INTEGER NOT NULL,              -- end_seq - start_seq + 1
  agent_signature TEXT NOT NULL,              -- Firma ECDSA / Ed25519 del checkpoint
  anchor_status TEXT NOT NULL,                -- PENDING, ANCHORED, FAILED
  cloud_tx_id TEXT,                           -- Recibo o ID de transacción en Sentinel Cloud
  cloud_anchored_at INTEGER                   -- Timestamp de confirmación del anclaje remoto
);

CREATE INDEX IF NOT EXISTS idx_records_workload ON evidence_records(workload_id);
CREATE INDEX IF NOT EXISTS idx_records_exec_id ON evidence_records(exec_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON evidence_checkpoints(anchor_status);
```

---

## 5. Protocolo de Verificación al Arranque (`verifyLedgerIntegrity()`)

Cada vez que el daemon de Sentinel Runtime inicializa el servicio, debe ejecutar la rutina de verificación antes de aceptar cualquier nuevo evento:

```mermaid
flowchart TD
    A[Inicio de Sentinel Runtime] --> B[Leer evidence_records ordenado por seq ASC]
    B --> C{¿Base de datos vacía?}
    C -- Sí --> D[Verificar coherencia de checkpoint inicial y continuar]
    C -- No --> E[Inicializar CurrentHash = H_0 Genesis]
    E --> F[Leer siguiente fila seq_i]
    F --> G{¿seq_i == seq_{i-1} + 1?}
    G -- No --> H[ERROR: Salto en secuencia / Truncamiento detectado]
    G -- Sí --> I{¿prev_hash == CurrentHash?}
    I -- No --> J[ERROR: Ruptura de encadenamiento de hash]
    I -- Sí --> K[Recalcular Hash_i con JCS y Seq_i]
    K --> L{¿Hash_i == record_hash en DB?}
    L -- No --> M[ERROR: Payload alterado en reposo]
    L -- Sí --> N[CurrentHash = Hash_i]
    N --> O{¿Existen más filas?}
    O -- Sí --> F
    O -- No --> P[Validar contra último Checkpoint anclado externamente]
    P --> Q{¿Coincide con Sentinel Cloud?}
    Q -- No --> R[ERROR CRÍTICO: Detección de Rollback o Fork Attack]
    Q -- Sí --> S[LEDGER ÍNTEGRO: Habilitar operación normal]
    H --> T[ACTIVAR MODO FORENSIC_LOCKDOWN]
    J --> T
    M --> T
    R --> T
```

### Comportamiento ante Fallo de Verificación (`FORENSIC_LOCKDOWN`):
Si cualquiera de las verificaciones falla:
1. El motor causal **rechaza iniciar** el procesamiento de eventos.
2. Se emite una alerta crítica fuera de banda hacia Sentinel Cloud y el syslog local (`EMERGENCY: EVIDENCE_LEDGER_CORRUPTION`).
3. La base de datos entra en modo estricto de solo lectura (`PRAGMA query_only = ON`).
4. Se prohíbe sobreescribir los archivos WAL o DB para preservar la evidencia forense del intento de manipulación.

---

## 6. Checkpoints Periódicos y Anclaje Externo (External Anchoring)

Para neutralizar el riesgo de un atacante con privilegios de root en el host local, los registros se agrupan en **Checkpoints Criptográficos** que son exportados fuera del host:

### 6.1 Estructura del Checkpoint Normativo
```json
{
  "checkpoint_version": "1.0.0",
  "checkpoint_id": "chk-az1-node09-00042",
  "host_id": "worker-prod-az1-node09",
  "boot_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "epoch_timestamp": 1793628600000000000,
  "start_seq": 1001,
  "end_seq": 1500,
  "start_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "end_hash": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "record_count": 500,
  "agent_signature": "ecdsa-p256:MEQCID7x..."
}
```

### 6.2 Disparadores de Emisión de Checkpoints
Un nuevo checkpoint se sella y despacha automáticamente cuando se cumple la **primera** de las dos siguientes condiciones:
1. **Disparador Temporal:** Han transcurrido $\Delta T_{\text{checkpoint}} = 60\text{ segundos}$ desde el último checkpoint sellado.
2. **Disparador de Volumen:** Se han insertado $N_{\text{records}} = 500\text{ registros}$ desde el último checkpoint.

### 6.3 Destinos del Anclaje Externo
1. **Sentinel Cloud Evidence Vault:** Endpoint gRPC seguro que inserta el checkpoint en una base de datos relacional append-only distribuida.
2. **Object Storage con WORM (Write Once, Read Many):** Opcionalmente, respaldo directo en buckets S3 con Object Lock en modo `COMPLIANCE` o Google Cloud Storage Bucket Lock.

---

## 7. Ventana de Exposición, Anclaje Offline y Detección de Rollback (H-11 & AR-05)

### 7.1 Definición de la Ventana No Anclada
La **Ventana Objetivo de Anclaje** es:
$$\mathcal{W}_{\text{target}} = \min(60\text{s}, 500\text{ registros})$$

> **Corrección AR-05:** Este valor es un **objetivo condicionado a la disponibilidad del anclaje remoto**, no una garantía absoluta. Si la conectividad con el servicio de anclaje está perdida, la ventana real no anclada crece indefinidamente. Sentinel Runtime no puede declarar una garantía temporal de anclaje que dependa de una conexión que no existe.

### 7.2 Estados del Anclaje de Evidencia

| Estado del Anclaje | Definición | Garantía de Integridad |
|---|---|---|
| **`ANCHORED`** | Checkpoint confirmado y recibido por el destino externo. `cloud_tx_id` y `cloud_anchored_at` presentes. | Tamper-evidence completa: cualquier alteración local será detectada al comparar con el registro remoto. |
| **`UNANCHORED_ONLINE`** | Checkpoint sellado localmente, transmisión en curso o pendiente. Conectividad disponible. | Integridad local (hash-chain) pero sin confirmación externa. Ventana sujeta a $\mathcal{W}_{\text{target}}$. |
| **`UNANCHORED_OFFLINE`** | Sin conectividad con el servicio de anclaje externo. | Solo integridad local. La ventana no anclada crece sin límite predeterminado. **El modelo de amenazas de atacante root aplica sin mitigación remota durante este período.** |

### 7.3 Política de Almacenamiento Offline (Spool Local)
Cuando la conectividad con el servicio de anclaje está perdida:
1. Los checkpoints continúan sellándose y firmándose localmente con la clave del nodo.
2. Se almacenan en la tabla `evidence_checkpoints` con `anchor_status = 'PENDING'`.
3. **Capacidad de Spool Reservada:** Se reserva un espacio mínimo de 50 MB en disco para evidencia offline. Si el spool local excede este límite, se activa `EVIDENCE_PERSISTENCE_DEGRADED`.
4. Al restablecerse la conectividad, se ejecuta sincronización secuencial (*catch-up*) de todos los checkpoints pendientes en orden estricto.
5. **Detección de Reconexión:** El servicio remoto compara el `end_hash` del último checkpoint anclado con el `start_hash` del primer checkpoint pendiente. Si no coinciden, se declara `LEDGER_FORK_ATTACK`.

### 7.4 Ataque de Truncamiento y Rollback
- **Truncamiento Post-Checkpoint:** Un atacante con root que elimine registros posteriores al último checkpoint anclado (`seq > last_anchored_seq`) elimina evidencia dentro de la ventana no anclada. Sentinel Cloud detectará la discrepancia cuando se intente sincronizar o cuando se solicite una auditoría.
- **Rollback a Estado Anterior:** Si se restaura un backup antiguo de la base de datos, la verificación al arranque confrontará el estado local con el high-water mark remoto y declarará `LEDGER_ROLLBACK_ATTACK`.
- **Garantía Formal:** La evidencia anclada remotamente es resistente a manipulación por atacante root local. La evidencia no anclada está protegida solo por la hash-chain local, que un atacante root puede recalcular.

### 7.5 Rotación de Claves de Nodo
- Las claves de firma del agente (ECDSA P-256 o Ed25519) tienen una vida útil máxima configurable (por defecto: 90 días).
- La rotación emite un checkpoint especial `KEY_ROTATION` que contiene la clave pública nueva firmada por la clave saliente.
- El servicio de anclaje verifica la cadena de rotación y rechaza claves no autorizadas.

---

## 8. Modelo de Amenazas Formal

| Actor de Amenaza | Capacidades en el Host | Mitigación del Evidence Ledger | Garantía Resultante |
|---|---|---|---|
| **Atacante No Privilegiado** | Usuario local o servicio comprometido sin privilegios de administración. | Permisos de archivo del SO (`chmod 600`, propietario `sentinel:sentinel`). Inaccesible para otros usuarios. | **Inmutabilidad Efectiva Local** |
| **Atacante de Red / Man-in-the-Middle** | Interceptación de tráfico entre el host y Sentinel Cloud. | Canal cifrado TLS 1.3 con autenticación mutua (mTLS) y firmas digitales en cada checkpoint. | **Confidencialidad e Integridad de Tránsito** |
| **Atacante Privilegiado (Root Compromise)** | Control total de root / kernel en el host. Capacidad de editar SQLite y memoria. | No se asume inmutabilidad local. Se detecta alteración o rollback al contrastar la hash-chain local con los checkpoints anclados externamente. | **Tamper-Evidence Probatoria (Delimitada a $\mathcal{W}_{\text{unanchored}}$)** |

---

## 9. Comportamiento ante Fallos Operacionales de Sistemas (AR-03)

1. **Disco Lleno (`ENOSPC`) — Política de Degradación Controlada:**
   - El ledger conmuta a un **búfer circular en memoria RAM** reservado previamente (16 MB).
   - Se activa el estado **`EVIDENCE_PERSISTENCE_DEGRADED`** en el motor causal.
   - Las políticas preventivas previamente cargadas en el kernel (TracingPolicies de Tetragon) se **mantienen activas**: la observabilidad no se pierde.
   - Se reserva espacio de emergencia (1 MB mínimo con `fallocate` al iniciar) para registrar el incidente de saturación.
   - **Prohibición de Terminaciones Nuevas:** No se ejecutan órdenes de `TERMINATE_PROCESS` nuevas cuya justificación requiera evidencia que no pudo persistirse. Las contenciones previamente autorizadas se mantienen.
   - **No se suspenden workloads de producción** automáticamente por saturación de disco. Se emite alerta crítica `STORAGE_SATURATION` hacia syslog y Sentinel Cloud.
   - **Recuperación:** Al liberar espacio, el ledger ejecuta `verifyLedgerIntegrity()` sobre los registros existentes, vuelca los eventos del búfer RAM al disco y reanuda operación normal solo si la verificación es exitosa.
2. **Corte de Conectividad con Sentinel Cloud:**
   - Los checkpoints se sellan y firman localmente con estado `PENDING` (ver sección 7.3).
   - Al restablecerse el enlace, sincronización secuencial catch-up en orden de `checkpoint_id`.
   - No se degrada la capacidad local de detección durante la desconexión.
3. **Corrupción de Archivo SQLite por Caída Eléctrica:**
   - `journal_mode = WAL` + `synchronous = FULL` garantiza recuperación hasta la última transacción atómica limpia.
   - Si la recuperación WAL falla, se activa `FORENSIC_LOCKDOWN`.

---

## 10. Criterios de Aceptación Verificables para EVIDENCE_LEDGER_V1

- [ ] **AC-LED-01 (Determinismo RFC 8785):** Dos payloads con diferente ordenación de claves en JSON deben producir idéntica salida de bytes canónicos e idéntico SHA-256.
- [ ] **AC-LED-02 (Detección de Manipulación):** Una prueba automatizada que modifique un solo byte de `reason` o `action` mediante un `UPDATE` directo en SQLite debe provocar el fallo inmediato de `verifyLedgerIntegrity()`.
- [ ] **AC-LED-03 (Detección de Truncamiento):** Una prueba que elimine la última fila de `evidence_records` debe provocar fallo de verificación al contrastar con el checkpoint previo.
- [ ] **AC-LED-04 (Acotamiento de Ventana No Anclada):** Bajo inyección masiva de eventos, ningún registro debe permanecer sin checkpoint firmado por más de 60 segundos o 500 registros.
