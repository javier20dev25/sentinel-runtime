# SENTINEL RUNTIME — EVENT ID & DEDUPLICATION ARCHITECTURE
## DESIGN-EVENT-ID-DEDUP-r2.3: Idempotency, Log Rotation, and Cursor Tracking (Revision R2.3)

**Estado:** `NORMATIVE DESIGN SPECIFICATION (R2.3)`  
**Fecha:** 2026-11-02  
**Estándares de Referencia:** RFC 9562 §5.4 (UUIDv4), RFC 9562 §5.5 (UUIDv5), RFC 9562 §5.8 (UUIDv8), RFC 8785 (JCS)  
**Autor:** Sentinel Runtime Engineering & Security Architecture

---

## 1. El Problema de la Identidad e Idempotencia en Logs del Kernel

En un sistema de telemetría de seguridad que consume JSON Lines desde archivos o sockets:

1. **Re-lectura de Archivos (Crash Recovery / Replay):** Si el agente recolector se reinicia o se reposiciona en el archivo, volverá a leer eventos ya procesados. Si cada lectura genera un `event_id` aleatorio (UUIDv4), el pipeline podría generar IDs distintos para el mismo evento del kernel, pero no causaría duplicación de estado si la deduplicación se realiza mediante `source_event_key` determinista (SHA-256).
2. **Ambigüedad entre Proceso y Evento:** Un proceso en Linux no es un evento; es una entidad que experimenta múltiples transiciones de estado (`exec`, `fork`, `exit`). Por tanto, `exec_id` identifica la instancia del proceso, **no al evento individual**.
3. **Rotación y Reciclaje de Inodos:** En Linux, los mecanismos como `logrotate` (con o sin `copytruncate`), `truncate`, o recreación de archivos en `/var/log` provocan que un número de inodo pueda ser reutilizado por el sistema de archivos para un archivo totalmente diferente horas después.
4. **Reinicio del Collector:** Cada vez que el proceso Collector se reinicia, genera un nuevo `collector_session_id`. Este identificador de sesión **no debe participar en la clave de deduplicación estable** (`source_event_key`), pues invalidaría la idempotencia de eventos ya procesados por sesiones anteriores.

---

## 2. Doctrina de Identificadores: RFC 9562 (Corrección R2)

Esta sección corrige la afirmación de R1 que declaraba UUIDv8 "universalmente superior" a UUIDv5. La comparación correcta es:

| Dimensión | UUIDv4 (Aleatorio) | UUIDv5 (SHA-1 + Namespace) | UUIDv8 (Formato Específico de Aplicación) |
| :--- | :--- | :--- | :--- |
| **Estándar RFC** | RFC 9562 §5.4 | RFC 9562 §5.5 | RFC 9562 §5.8 |
| **Algoritmo** | 122 bits CSPRNG | SHA-1 truncado a 128 bits | Campo `custom_c` libre; unicidad depende de la implementación |
| **Idempotencia ante Replay** | ❌ Cada parseo produce ID distinto | ✅ Mismo input → idéntico UUID | ⚠️ Solo si la implementación lo garantiza explícitamente |
| **Resistencia Criptográfica** | No aplicable (aleatorio puro) | ⚠️ SHA-1 tiene colisiones prácticas demostradas (SHAttered, 2017) | Depende del algoritmo usado en `custom_c` |
| **Recomendación RFC 9562** | Uso general | RFC 9562 §5.5: "prefer UUIDv5 over UUIDv3 when possible" | Solo cuando ninguna versión estándar aplica |

### Observaciones Normativas Correctas sobre RFC 9562

1. **UUIDv5 continúa siendo especificado y válido.** RFC 9562 no depreca UUIDv5; lo mantiene como la alternativa recomendada sobre UUIDv3 (MD5) cuando se requiere un UUID con nombre determinista.
2. **UUIDv8 no tiene unicidad garantizada por el estándar.** RFC 9562 §5.8 define UUIDv8 como un espacio para formatos específicos de aplicación. La unicidad depende completamente de la implementación; el estándar no la impone.
3. **SHA-1 en UUIDv5 no produce colisiones con adversario razonable** para el caso de uso de deduplicación de logs de kernel, pero se prefiere SHA-256 puro para la clave de deduplicación por robustez y alineación con el modelo de hash del Evidence Ledger.

### Decisión Arquitectónica Definitiva (R2.2)

| Campo | Función | Algoritmo | Justificación |
| :--- | :--- | :--- | :--- |
| `event_id` | Identidad de la instancia normalizada del evento | **UUIDv4** (RFC 9562 §5.4) | Identidad local del evento en el pipeline. No requiere determinismo ni idempotencia. |
| `source_event_key` | Deduplicación e idempotencia entre relecturas | **SHA-256 length-prefixed** (hex, 64 chars) | Máxima resistencia a colisiones y delimitador-safe. Computable sin dependencias externas. |
| `raw_payload_sha256` | Integridad del payload JSON del log | **SHA-256** de los bytes exactos del objeto JSON (**sin delimitador LF/CRLF**) | Invariante al formato de framing de archivo. Permite verificar que el JSON no fue alterado tras la captura. |

---

## 3. Modelo Cuádruple de Identidad y Deduplicación

```
   [ Raw Log Line (JSONL) — frame físico ]
              │
              ├─► SHA256(bytes_sin_delimitador) ───────► raw_payload_sha256
              │
              ├─► Source Cursor:
              │   ⟨ source_uri, device_id, inode, file_generation_id,
              │     byte_offset, byte_length, payload_byte_length,
              │     delimiter_byte_length, raw_payload_sha256 ⟩
              │
              ▼
   ┌──────────────────────────────────────────────────────────┐
   │ source_event_key (256 bits, Length-Prefixed Encoding):   │
   │ SHA256(len(host_id):host_id ∥ len(boot_id):boot_id       │
   │        ∥ len(exec_id):exec_id ∥ len(type):type           │
   │        ∥ len(source_ts):source_ts                        │
   │        ∥ len(raw_payload_sha256):raw_payload_sha256)     │
   └──────────────────────────────────────────────────────────┘
              │
              ▼
   ┌──────────────────────────────────────────────────────────┐
   │ event_id (UUIDv4, RFC 9562 §5.4):                        │
   │ Generado aleatoriamente por el Collector para cada       │
   │ instancia de procesamiento. NO determinista.             │
   │ La deduplicación se realiza exclusivamente mediante      │
   │ source_event_key, no mediante event_id.                  │
   └──────────────────────────────────────────────────────────┘
```

### Definición Matemática de las Claves

**`raw_payload_sha256`** — Huella de integridad del payload JSON:
$$\text{raw\_payload\_sha256} = \text{SHA256}(\text{bytes\_del\_objeto\_JSON\_sin\_delimitador})$$

> [!IMPORTANT]
> **Definición de Framing Físico y Delimitadores (LF, CRLF, EOF):**  
> El framing de logs en formato JSON Lines puede presentar tres variantes de delimitador:
> - **LF (`0x0a`):** Formato estándar en Linux / POSIX (`delimiter_byte_length = 1`).
> - **CRLF (`0x0d 0x0a`):** Formato Windows o transferencias de red con framing Telnet/HTTP (`delimiter_byte_length = 2`).
> - **EOF sin delimitador:** Última línea de un archivo sin newline final (`delimiter_byte_length = 0`).
>
> **Invariante física obligatoria:**
> $$\text{byte\_length} = \text{payload\_byte\_length} + \text{delimiter\_byte\_length}$$
>
> - `byte_length`: Longitud física total del frame en el archivo (utilizada para operaciones de seek / offset).
> - `payload_byte_length`: Longitud en bytes exactos del objeto JSON serializado.
> - `delimiter_byte_length`: Tamaño del delimitador de framing (0, 1 o 2 bytes).
> - **Prohibición:** Se prohíbe calcular la longitud del payload mediante una resta fija `byte_length - 1`. El normalizador debe inspeccionar activamente los bytes de cola del frame para determinar el delimitador exacto.
>
> **Ejemplo verificado empíricamente (Línea 14, dataset de laboratorio):**
> - `payload_byte_length` = 825 bytes (bytes del JSON)
> - `delimiter_byte_length` = 1 byte (`0x0a` LF)
> - `byte_length` = 826 bytes físicos
> - `raw_payload_sha256` = SHA-256 de 825 bytes = `0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818`
> - SHA-256 de 826 bytes (con `\n`) = `cc03288e...` (valor distinto — confirma que el framing no debe alterar la identidad del JSON).
> - El hash del dataset completo de 25 eventos (`93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe`) es una métrica de integridad del archivo completo en disco, **no** un `raw_payload_sha256` de evento individual.

**`source_event_key`** — Clave de idempotencia determinista:

Se utiliza **length-prefixed encoding** para garantizar la inequivocidad del input. Cada componente se codifica como `{longitud_en_decimal}:{valor}`, concatenados sin separador adicional. Este esquema evita cualquier ambigüedad por inyección de delimitadores (ej. un `host_id` que contiene `":"` no puede confundirse con el separador entre campos):

$$\text{input} = \prod_{i} |\text{field}_i|:\text{field}_i$$

donde $|\text{field}_i|$ es la longitud en bytes del valor UTF-8 del campo.

**Ejemplo para Línea 14 del dataset (calculado empíricamente):**
```
21:sentinel-host-prod-01
36:8f5a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c
44:REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEw
12:PROCESS_EXEC
19:1793662267642869315
64:0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818
```

$$\text{source\_event\_key} = \text{SHA256}(\text{input concatenado})$$

Resultado: `09eda1a503c87428a06cc5f9ee7d055f3483d93f628a2163e80683884251d52d`

> [!NOTE]
> La `source_timestamp` utilizada en la fórmula es `timestamps.source_timestamp` del evento normalizado (no `timestamps.provider_observation_timestamp`). Para PROCESS_EXIT, estos son distintos. Para PROCESS_EXEC, son el mismo valor.

Propiedades de diseño:
- **Estable ante reinicios del Collector:** `collector_session_id` queda **excluido** deliberadamente.
- **Discrimina eventos del mismo proceso:** PROCESS_EXEC y PROCESS_EXIT del mismo `exec_id` producen `source_event_key` distintos (difieren en `event_type` y `source_timestamp`).
- **Discrimina relecturas:** El mismo evento siempre produce el mismo `source_event_key`.

**`event_id`** — Identidad de instancia de procesamiento:
- UUIDv4 aleatorio, generado fresco por cada invocación del Collector.
- Es la clave primaria en la base de datos local del pipeline para ordenar eventos internos.
- No es idempotente; dos lecturas del mismo evento producen `event_id` distintos. La deduplicación se hace por `source_event_key`.

---

## 4. Source Cursor — Tupla Nónupla y Separación de Sesión

El cursor físico se modela como una tupla nónupla que identifica **sin ambigüedad** la posición exacta y el framing de una línea en el filesystem de Linux:

$$\text{source\_cursor} = \langle \underbrace{\text{source\_uri}}_{\text{ruta lógica}}, \underbrace{\text{device\_id}}_{\text{dispositivo}}, \underbrace{\text{inode}}_{\text{inodo}}, \underbrace{\text{file\_generation\_id}}_{\text{generación persistida}}, \underbrace{\text{byte\_offset}}_{\text{inicio frame}}, \underbrace{\text{byte\_length}}_{\text{total físico}}, \underbrace{\text{payload\_byte\_length}}_{\text{bytes JSON}}, \underbrace{\text{delimiter\_byte\_length}}_{\text{framing}}, \underbrace{\text{raw\_payload\_sha256}}_{\text{integridad payload}} \rangle$$

> [!NOTE]
> `collector_session_id` **no forma parte de la tupla del cursor ni de `source_event_key`**. Es un campo de `sensor_metadata` que identifica el ciclo de vida del proceso Collector, pero no la identidad estable del evento del kernel. Separar ambos conceptos es la garantía de que la deduplicación sobrevive a reinicios del Collector.

### Semántica de los Campos del Source Cursor

| Campo | Fuente | Semántica |
| :--- | :--- | :--- |
| `source_uri` | Config del Collector | Ruta lógica del archivo de log (ej. `file:///var/log/tetragon/tetragon.log`). |
| `device_id` | `stat.st_dev` | Número de dispositivo de bloque donde reside el inodo. Cambia si el archivo se mueve a otro filesystem. |
| `inode` | `stat.st_ino` | Número de inodo del archivo activo. Cambia con `rename`-based rotation. |
| `file_generation_id` | Checkpoint persistente | Entero monótono creciente guardado de forma durable que distingue generaciones del archivo ante rotaciones o truncamientos. |
| `byte_offset` | Posición del Collector | Byte de inicio del frame físico en el archivo activo. |
| `byte_length` | Total frame físico | Longitud en bytes del frame completo incluyendo delimitador (`payload_byte_length + delimiter_byte_length`). |
| `payload_byte_length` | Longitud JSON | Longitud en bytes exactos del objeto JSON serializado (sin incluir delimitadores). |
| `delimiter_byte_length` | Longitud framing | `1` para LF (`0x0a`), `2` para CRLF (`0x0d 0x0a`), `0` para EOF sin delimitador. |
| `raw_payload_sha256` | SHA-256(payload) | Huella criptográfica de los `payload_byte_length` bytes del objeto JSON. |

---

## 5. Comportamiento ante Escenarios de Filesystem, Rotación y Durabilidad

### A. Persistencia y Ciclo de Vida de `file_generation_id`
- **Almacenamiento Durable:** `file_generation_id` y el cursor activo se persisten de forma síncrona en una tabla de checkpoints persistente (SQLite / WAL de Evidence Ledger) con atomic rename (`.tmp` $\to$ `.dat`) o transacción WAL antes de procesar eventos descendentes.
- **Sobrevivencia a Reinicios:** Al iniciar, el Collector lee el checkpoint persistente para la tupla `(device_id, inode, source_uri)`. Si el inodo coincide y `st_size >= last_offset`, reanuda en `last_offset` con el mismo `file_generation_id`.
- **Detección de Cambio de Inodo (`rename`-based rotation):** `stat(path).st_ino != checkpoint.inode`. El Collector:
  1. Drena los bytes restantes del descriptor de archivo anterior (`old_fd`) hasta alcanzar EOF real.
  2. Cierra `old_fd`.
  3. Abre el nuevo inodo (`new_fd`).
  4. Incrementa de forma durable `file_generation_id = checkpoint.file_generation_id + 1`.
  5. Establece `byte_offset = 0` y guarda el nuevo checkpoint atómicamente.

### B. Análisis de `copytruncate` y Límites Estructurales de Detección
En sistemas con rotación por `copytruncate`, el daemon externo copia el contenido del archivo y luego ejecuta `truncate(path, 0)` sin cambiar el inodo:
- **Detección Estándar:** Si `stat(path).st_size < last_offset`, se detecta truncamiento evidente. El Collector:
  1. Emite un evento formal de pérdida: `EVENT_LOSS(loss_source: "log_rotation_copytruncate", state: "MEASURED")`.
  2. Incrementa `file_generation_id = file_generation_id + 1`.
  3. Reanuda la lectura en `byte_offset = 0`.
- **Límite Estructural Demostrado (Ventana de Polling):** Si el truncamiento ocurre y una ráfaga masiva de nuevos logs vuelve a llenar el archivo hasta un tamaño $\ge \text{last\_offset}$ antes de que el Collector realice la siguiente llamada a `stat()`, la condición `st_size < last_offset` **no se cumplirá**. En este escenario de carrera, el truncamiento no es detectable mediante sondeo pasivo de metadatos de archivo.
- **Taxonomía Honesta de Pérdida en Sentinel:**
  1. *Pérdida Medida / Observada (`MEASURED`):* Detectada formalmente cuando `st_size < last_offset`.
  2. *Pérdida Potencial (`POTENTIAL`):* Ventana de sondeo en entornos con `copytruncate` activo bajo alta tasa de escritura.
  3. *Pérdida Desconocida (`UNKNOWN`):* Estructuralmente no verificable.  
  > [!CAUTION]
  > Se prohíbe taxativamente declarar `loss_metrics.state = "ZERO_OBSERVED"` ante `copytruncate` si el mecanismo de detección no puede inspeccionar atómicamente cada llamada al sistema de truncamiento en el kernel.

### C. Reciclaje de Inodos y Continuidad de Descriptores
- **Reciclaje de Inodo:** Ocurre cuando un inodo liberado por el filesystem es reasignado a un nuevo archivo con el mismo path. Se detecta comparando `stat.st_ctime` / `stat.st_birthtime` con el checkpoint previo, o mediante una comprobación de huella del bloque inicial de bytes (`magic_bytes_sha256`). Ante cualquier discrepancia, se trata como un archivo nuevo: se incrementa `file_generation_id` y se reinicia el offset.
- **Continuidad de Lectura:** El Collector mantiene abierto el descriptor del archivo previo hasta consumir todos los frames completos. Nunca abandona un descriptor sin drenar el buffer de framing.

---

## 6. Arquitectura de Deduplicación e Idempotencia Persistente

### A. WAL frente a Deduplicación — Roles Claramente Separados
- **El Write-Ahead Log (WAL) provee Durabilidad y Recuperación:** El WAL registra transaccionalmente las operaciones antes de confirmarlas, permitiendo restaurar el estado tras un fallo abrupto del proceso o nodo. **El WAL por sí solo no garantiza deduplicación ni idempotencia.**
- **La Idempotencia Reside en Restricciones Persistentes:** La garantía persistente de no duplicación se implementa mediante una restricción formal de unicidad en la base de datos del Evidence Ledger:
  ```sql
  CREATE TABLE IF NOT EXISTS evidence_ledger (
      source_event_key TEXT NOT NULL PRIMARY KEY,
      event_id TEXT NOT NULL,
      ingest_timestamp INTEGER NOT NULL,
      payload_json TEXT NOT NULL
  );
  -- Inserción idempotente atómica:
  INSERT INTO evidence_ledger (source_event_key, event_id, ...)
  VALUES (?, ?, ...)
  ON CONFLICT(source_event_key) DO NOTHING;
  ```
- Si la inserción genera conflicto en `source_event_key`, el evento se clasifica como `ALREADY_INGESTED_IDEMPOTENT`, no muta el estado del pipeline ni incrementa el Evidence Ledger.

### B. Bounded Sliding Cache en Memoria (Optimización de Latencia)
- Para evitar consultas continuas a disco en streams de alta frecuencia, el Collector mantiene una caché volátil de claves recientes (LRU Set o Filtro de Bloom particionado).
- **Consumo de Memoria Real:**  
  - Tamaño matemático bruto: 200,000 hashes binarios $\times$ 32 bytes $= 6.4\text{ MB}$.
  - Overhead en Runtime Node.js / V8: En JavaScript, un `Set` de strings hexadecimales de 64 caracteres u objetos de nodo LRU tiene un coste de 80 a 100 bytes por entrada, resultando en un consumo de memoria real de **~16 a 20 MB**. La especificación adopta esta cifra realista para dimensionamiento de buffers en producción.
- La caché en memoria es **exclusivamente una optimización de rendimiento**. La fuente de verdad normativa para la deduplicación es el almacenamiento transaccional persistente.

---

## 7. Ejemplo Verificado: Línea 14 del Dataset de Laboratorio

Los valores a continuación fueron calculados algorítmicamente en el laboratorio con `Node.js v24.20.0`:

| Campo | Valor Calculado | Fuente de Cálculo |
| :--- | :--- | :--- |
| `payload_byte_length` (Línea 14) | `825` bytes | Longitud del string JSON serializado (sin delim) |
| `delimiter_byte_length` (Línea 14) | `1` byte | Byte de delimitador `0x0a` (LF) |
| `byte_length` (Línea 14) | `826` bytes | Longitud física total del frame en archivo |
| `raw_payload_sha256` (Línea 14) | `0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818` | `SHA256(bytes de la Línea 14 sin LF = 825 bytes)` |
| SHA-256 del dataset completo (25 eventos) | `93405604fdb1e1bc17527082a4854caaff2be4b69e49073ff56e5768f25dc8fe` | `SHA256(archivo completo = 19349 bytes)` |
| `source_timestamp` (Línea 14) | `1793662267642869315` nanos | Conversión aritmética pura de `"2026-11-02T23:31:07.642869315Z"` |
| `source_event_key` (Línea 14) | `09eda1a503c87428a06cc5f9ee7d055f3483d93f628a2163e80683884251d52d` | `SHA256(input length-prefixed)` |
| Input length-prefixed exacto | `21:sentinel-host-prod-0136:8f5a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c44:REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEw12:PROCESS_EXEC19:179366226764286931564:0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818` | Concatenación inequívoca UTF-8 |
| `byte_offset` (Línea 14) | `9872` | Posición del primer byte de la línea en el archivo |
