# SENTINEL RUNTIME — TIMESTAMP SPECIFICATION & LOSSLESS PARSER DESIGN
## DESIGN-TIMESTAMP-NANO-r2.3: Strict RFC 3339 Nano Validation & Pure Arithmetic Conversion (Revision R2.3)

**Estado:** `NORMATIVE DESIGN SPECIFICATION (R2.3)`  
**Fecha:** 2026-11-02  
**Estándares de Referencia:** RFC 3339 (Date and Time on the Internet: Timestamps), ISO 8601-1:2019, POSIX.1-2017 (IEEE Std 1003.1), IERS Leap Second Table  
**Autor:** Sentinel Runtime Engineering & Security Architecture

---

## 1. El Problema de la Precisión Temporal en Sensores eBPF

Los sensores modernos de kernel Linux (Tetragon, bpf_ktime_get_ns) operan con resolución de nanosegundos ($10^{-9}$ segundos).

La serialización de Tetragon entrega cadenas RFC 3339 Nano con 9 dígitos fraccionarios:
```text
"2026-11-02T23:31:07.642869315Z"
```

El contrato de Sentinel Runtime exige que las marcas temporales se preserven sin ninguna degradación en el tipo `$defs/uint64` (cadena decimal canónica de nanosegundos enteros en el rango $[0, 2^{64}-1]$ desde el Epoch UNIX `1970-01-01T00:00:00.000000000Z`).

### Restricción Matemática del Dominio `uint64`
Al requerirse que el tiempo se exprese en nanosegundos acumulados desde el Epoch UNIX dentro de un entero sin signo de 64 bits (`uint64`):
$$\text{Valor Mínimo: } 0 \implies \text{1970-01-01T00:00:00.000000000Z}$$
$$\text{Valor Máximo: } 2^{64}-1 = 18{,}446{,}744{,}073{,}709{,}551{,}615 \implies \text{2554-07-21T23:34:33.709551615Z}$$

Cualquier timestamp anterior al 1 de enero de 1970 (que generaría enteros negativos no representables en `uint64`) o posterior a `2554-07-21T23:34:33.709551615Z` (que desbordaría los 64 bits de precisión) **debe ser estrictamente rechazado con `RANGE_ERROR_UNIX_EPOCH_BOUNDS`**.

### Las 4 Trampas de la API Estándar de JavaScript (`Date` / `Date.UTC`)

1. **Truncamiento a Milisegundos:** `Date.parse()` y `new Date()` almacenan el tiempo como enteros de milisegundos de 64 bits flotantes (IEEE 754). Parsear `"2026-11-02T23:31:07.642869315Z"` descarta irreversiblemente los dígitos `869315` — destrucción del 99.9999% de la resolución temporal del kernel.
2. **Desplazamiento de Años 0000–0099:** Por convención legacy heredada de C (`struct tm`), `Date.UTC(99, 0, 1)` no representa el año 99 d.C., sino el año **1999 d.C.** Cualquier timestamp histórico, de simulación o corrupto entre los años 0 y 99 es desplazado un milenio hacia el futuro de forma silenciosa.
3. **Normalización Silenciosa y Desalineación POSIX:** JavaScript `Date.UTC()` no soporta segundos intercalares. Además, en POSIX (IEEE Std 1003.1), los días civiles se modelan con exactamente 86,400 segundos; pretender sumar un segundo extra ($10^9\text{ ns}$) a una marca `:60` colisiona con el segundo `00` del día siguiente.
4. **Truncamiento Silencioso de Sub-Nanosegundos:** Un parseador que aplica `.padEnd(9, '0').slice(0, 9)` trunca silenciosamente cualquier timestamp con 10 o más dígitos fraccionarios (ej. picosegundos o corrupción del serializador), ocultando la anomalía.

---

## 2. Algoritmo Aritmético Puro de Conversión (Pure Gregorian Epoch Math) — R2.3

### Garantías del Algoritmo R2.3:
- Cero uso de `Date`, `Date.UTC`, `new Date()` en cualquier ruta de ejecución.
- Cumplimiento estricto del dominio `uint64` ($[1970\text{-}01\text{-}01, 2554\text{-}07\text{-}21]$); rechazo de años anteriores a 1970 y de desbordamientos superiores a $2^{64}-1$.
- Rechazo estricto de sub-nanosegundos (> 9 dígitos fraccionarios).
- Rechazo estricto de segundos intercalares (`:60`), conforme a la definición de tiempo Epoch UNIX de POSIX.1 (86,400 segundos exactos por día civil; ni Go `time.Time` ni Tetragon emiten `:60`).
- Aritmética entera pura con `BigInt` (cero imprecisión de punto flotante IEEE 754).

```javascript
/**
 * Convierte un timestamp RFC 3339 Nano en una cadena decimal canónica
 * de nanosegundos desde el Epoch UNIX (1970-01-01T00:00:00Z) en formato uint64.
 *
 * GARANTÍAS DEL ALGORITMO R2.3:
 * - Cero uso de Date / Date.UTC / new Date().
 * - Dominio estrictamente acotado a [1970-01-01T00:00:00Z, 2554-07-21T23:34:33.709551615Z].
 * - Rechazo de fechas anteriores a 1970 (no representables en uint64).
 * - Rechazo de desbordamiento de 64 bits (> 2^64 - 1).
 * - Rechazo estricto de sub-nanosegundos (> 9 dígitos fraccionarios).
 * - Rechazo de segundos :60 (incompatibles con la definición POSIX de Epoch UNIX).
 * - Aritmética de días civiles puramente gregoriana (algoritmo Howard Hinnant).
 *
 * @param {string} ts - Timestamp en formato RFC 3339 Nano (UTC solamente, sufijo Z).
 * @returns {string} Cadena decimal de nanosegundos uint64.
 * @throws {TypeError} Si ts no es string.
 * @throws {Error|RangeError} Si el formato es inválido o el valor excede el dominio uint64.
 */
function parseRfc3339NanoToEpochNanos(ts) {
  if (typeof ts !== 'string') {
    throw new TypeError(`Timestamp must be a string, got ${typeof ts}`);
  }

  // Regex canónica RFC 3339 UTC: año 4 dígitos, mes 01-12, día 01-31,
  // hora 00-23, min 00-59, seg 00-60, fracción opcional (1-9 dígitos), sufijo Z.
  const match = ts.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/);
  if (!match) {
    throw new Error(`Invalid RFC 3339 Nano format: "${ts}"`);
  }

  const [, yearStr, monthStr, dayStr, hourStr, minStr, secStr, fracStr] = match;

  // REGLA R2.3-1: Rechazo estricto de sub-nanosegundos (> 9 dígitos).
  if (fracStr && fracStr.length > 9) {
    throw new Error(
      `Sub-nanosecond precision (> 9 fractional digits) strictly rejected: ".${fracStr}" in "${ts}"`
    );
  }

  const y = parseInt(yearStr, 10);
  const m = parseInt(monthStr, 10);
  const d = parseInt(dayStr, 10);
  const H = parseInt(hourStr, 10);
  const M = parseInt(minStr, 10);
  const S = parseInt(secStr, 10);

  // REGLA R2.3-2: Cota de rango uint64 [1970, 2554].
  // Un valor de nanosegundos en uint64 no puede ser negativo (pre-1970) ni superar 2^64 - 1 (~2554).
  if (y < 1970) {
    throw new RangeError(
      `Date before Unix Epoch 1970 cannot be represented in uint64 nanoseconds (RANGE_ERROR_UNIX_EPOCH_BOUNDS): "${ts}"`
    );
  }
  if (y > 2554) {
    throw new RangeError(
      `Timestamp overflows uint64 nanoseconds (max year ~2554, RANGE_ERROR_UNIX_EPOCH_BOUNDS): "${ts}"`
    );
  }

  // REGLA R2.3-3: Validación de rangos cronológicos básicos.
  if (m < 1 || m > 12) throw new RangeError(`Month out of range (1-12): ${m} in "${ts}"`);
  if (H < 0 || H > 23) throw new RangeError(`Hour out of range (0-23): ${H} in "${ts}"`);
  if (M < 0 || M > 59) throw new RangeError(`Minute out of range (0-59): ${M} in "${ts}"`);

  // REGLA R2.3-4: Política de segundos intercalares (:60) bajo POSIX.1 IEEE Std 1003.1.
  // El tiempo POSIX define formalmente que cada día civil contiene exactamente 86,400 segundos.
  // Ni Tetragon (Go time.Time) ni el kernel Linux emiten :60 en marcas de tiempo Unix.
  // Asignar un offset de 10^9 ns al segundo 60 colisionaría con las 00:00:00 del día siguiente.
  // Por tanto, :60 es estrictamente rechazado.
  if (S === 60) {
    throw new RangeError(
      `Second :60 (leap second) is not representable in POSIX Unix Epoch nanoseconds: "${ts}"`
    );
  }
  if (S < 0 || S > 59) {
    throw new RangeError(`Second out of range (0-59): ${S} in "${ts}"`);
  }

  // REGLA R2.3-5: Validación estricta de días de mes (bisiesto gregoriano puro).
  const isLeapYear = (y % 4 === 0 && y % 100 !== 0) || (y % 400 === 0);
  const daysInMonths = [0, 31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (d < 1 || d > daysInMonths[m]) {
    throw new RangeError(
      `Day ${d} invalid for month ${m} in year ${y} (max: ${daysInMonths[m]}) in "${ts}"`
    );
  }

  // REGLA R2.3-6: Cálculo puro de días civiles desde el Epoch 1970-01-01 (Howard Hinnant).
  const yAdj = m <= 2 ? y - 1 : y;
  const mAdj = m <= 2 ? m + 9 : m - 3;

  const era = Math.floor(yAdj >= 0 ? yAdj / 400 : (yAdj - 399) / 400);
  const yoe = yAdj - era * 400;                                     // [0, 399]
  const doy = Math.floor((153 * mAdj + 2) / 5) + d - 1;             // [0, 365]
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy; // [0, 146096]
  const daysSinceEpoch = era * 146097 + doe - 719468;               // 719468 = días de 0000-03-01 a 1970-01-01

  // REGLA R2.3-7: Conversión a nanosegundos en BigInt y validación de cota superior uint64.
  const daysBig = BigInt(daysSinceEpoch);
  const secondsInDay = BigInt(H * 3600 + M * 60 + S);
  const totalSeconds = daysBig * 86400n + secondsInDay;

  const fractionNanoStr = (fracStr || '').padEnd(9, '0');
  const nanosFraction = BigInt(fractionNanoStr);

  const totalEpochNanos = totalSeconds * 1_000_000_000n + nanosFraction;

  const MAX_UINT64 = 18_446_744_073_709_551_615n; // 2^64 - 1
  if (totalEpochNanos > MAX_UINT64) {
    throw new RangeError(
      `Timestamp overflows uint64 nanoseconds (RANGE_ERROR_UNIX_EPOCH_BOUNDS): "${ts}"`
    );
  }

  return totalEpochNanos.toString();
}
```

---

## 3. Matriz de Pruebas Unitarias de Casos Límite (Edge Cases) — R2.3

| Entrada de Prueba | Comportamiento Esperado | Resultado de Laboratorio | Justificación Normativa |
| :--- | :--- | :--- | :--- |
| `"1970-01-01T00:00:00.000000000Z"` | Retorna `"0"` | ✅ Verificado | Mínimo absoluto representable en `uint64`. |
| `"1970-01-01T00:00:00Z"` | Retorna `"0"` | ✅ Verificado | Epoch exacto sin fracción. |
| `"1969-12-31T23:59:59.999999999Z"` | **RECHAZO CON ERROR** | ✅ Verificado | Anterior a Epoch (`RANGE_ERROR_UNIX_EPOCH_BOUNDS`). No existen valores negativos en `uint64`. |
| `"0042-05-10T08:30:00Z"` | **RECHAZO CON ERROR** | ✅ Verificado | Año 42 < 1970 (`RANGE_ERROR_UNIX_EPOCH_BOUNDS`). |
| `"2026-11-02T23:31:07.642869315Z"` | Retorna `"1793662267642869315"` | ✅ Verificado (Node.js v24) | Telemetría real de Tetragon v1.8.0 (Línea 14 de Lab 01). |
| `"2026-11-03T00:11:32.334073686Z"` | Retorna `"1793664692334073686"` | ✅ Verificado | Evento del dataset de laboratorio. |
| `"2026-11-03T00:11:32.5Z"` | Retorna `"1793664692500000000"` | ✅ Verificado | Fracción de 1 dígito (`.5` → 500,000,000 ns). |
| `"2026-11-03T00:11:32.1234567891Z"` | **RECHAZO CON ERROR** | ✅ Verificado | 10 dígitos fraccionarios (> 9). Prohibición de truncamiento silencioso. |
| `"2026-02-29T12:00:00Z"` | **RECHAZO CON ERROR** | ✅ Verificado | 2026 no es bisiesto. Febrero tiene 28 días. |
| `"2024-02-29T12:00:00Z"` | Retorna valor exacto | ✅ Verificado | 2024 es bisiesto. Día 29 es válido. |
| `"2026-06-30T23:59:60Z"` (caso de prueba :60) | **RECHAZO CON ERROR** | ✅ Verificado | Segundo intercalar :60 no representable en nanosegundos POSIX Epoch (POSIX 86,400s/día). Eliminada la pretensión de R2 de considerarlo válido (inexistente según Boletín C del IERS y no admitido en POSIX). |
| `"2026-05-15T10:20:60Z"` | **RECHAZO CON ERROR** | ✅ Verificado | `:60` fuera de rango de segundos (0-59). |
| `"2554-07-21T23:34:33.709551615Z"` | Retorna `"18446744073709551615"` | ✅ Verificado | Límite superior exacto ($2^{64}-1$) de `uint64`. |
| `"2554-07-21T23:34:33.709551616Z"` | **RECHAZO CON ERROR** | ✅ Verificado | Desbordamiento de 64 bits (`RANGE_ERROR_UNIX_EPOCH_BOUNDS`). |
| `"2555-01-01T00:00:00Z"` | **RECHAZO CON ERROR** | ✅ Verificado | Año 2555 excede límite de 64 bits. |

---

## 4. Separación Ontológica de las Marcas Temporales

Event Contract v2 define con rigor formal el significado y origen de cada dimensión temporal reportada. Se prohíbe copiar o intercambiar campos artificialmente.

| Dimensión Temporal | Campo en v2 | Fuente de Verdad Documentada | Origen en Tetragon v1.8.0 | Semántica Formal |
| :--- | :--- | :--- | :--- | :--- |
| **Tiempo de Observación del Proveedor** | `timestamps.provider_observation_timestamp` | Instante en que Tetragon en userspace observó y emitió el evento. | `time` en la raíz de `GetEventsResponse`. | Momento en que el daemon Tetragon procesó y exportó el registro. |
| **Tiempo Canónico del Evento** | `timestamps.source_timestamp` | Para `PROCESS_EXEC`: derivado de `provider_observation_timestamp`.<br>Para `PROCESS_EXIT`: derivado de `provider_event_timestamp`. | `GetEventsResponse.time` (EXEC) o `ProcessExit.time` (EXIT). | Marca de tiempo canónica asignada para indexación y ordenamiento en Sentinel. |
| **Tiempo de Inicio de Instancia de Proceso** | `process_identity.process_start_time` | Instante de inicio de ejecución reportado por Tetragon (`Process.start_time`). | `process.start_time` de Tetragon. | Marca temporal de creación del proceso en el kernel reportada por el sensor. |
| **Tiempo de Terminación del Proveedor** | `timestamps.provider_event_timestamp` | Fecha y hora reportada por el hook de salida de Tetragon (`ProcessExit.time`). | `time` dentro del objeto `process_exit`. | Solo presente en `PROCESS_EXIT`. Registra el momento de salida según el sensor. |
| **Tiempo de Ingestión en Sentinel** | `timestamps.ingest_timestamp` | Reloj local del Sentinel Collector (`CLOCK_REALTIME` del host). | **NO proviene de Tetragon.** | Instante en que el parser de Sentinel leyó y validó el frame JSONL en memoria. |

---

## 5. Análisis Formal de Anomalía Temporal T-001

### Hecho Experimental Observado
En la Línea 14 del dataset de telemetría real de Tetragon v1.8.0 (Lab 01) se registró:
- `timestamps.source_timestamp` (derivado de `GetEventsResponse.time`): `1793662267642869315`
- `process_identity.process_start_time` (de `process.start_time`): `1793662267642871299`
- Diferencia: $\Delta t = +1984\text{ ns}$ (~2 microsegundos).

### Determinación Normativa R2.3
1. **Causa de Raíz Indeterminada:** Sentinel Runtime no formula especulaciones sin instrumentación de kernel sobre "órdenes de serialización" de Tetragon. El fenómeno se clasifica formalmente como:
   $$\text{\textbf{ANOMALÍA T-001:}} \quad \text{Inversión temporal entre } \texttt{process.start\_time} \text{ y } \texttt{GetEventsResponse.time} \text{ en Tetragon v1.8.0.}$$
2. **Eliminación del Invariante Falso:** Se elimina de forma concluyente el supuesto invariante:
   $$\text{process\_start\_time} \le \text{source\_timestamp} \quad \text{\textbf{(INVÁLIDO — ELIMINADO)}}$$
3. **Prohibición de Manipulación de Datos:** El normalizador tiene terminantemente prohibido modificar, truncar, o igualar los campos para forzar un orden temporal artificial. Ambos valores deben registrarse con estricta fidelidad para auditoría forense.
4. **Relación Causal Válida:** Para eventos `PROCESS_EXIT`, la terminación ocurre estrictamente con posterioridad al inicio del proceso:
   $$\text{process\_start\_time} \le \text{provider\_event\_timestamp}$$
   Cualquier evento donde $\text{provider\_event\_timestamp} < \text{process\_start\_time}$ indica corrupción estructural o reutilización de PID no detectada por el sensor y debe generar una advertencia de auditoría estructurada.

---

## 6. Decisiones de Diseño sobre el Conversor R2.3

1. **Cero `Date.UTC` en cualquier ruta de código:** El algoritmo de Howard Hinnant cubre el calendario gregoriano proléptico civil con aritmética entera pura.
2. **Dominio Estricto `uint64`:** El tipo de destino `$defs/uint64` restringe el rango a $[1970\text{-}01\text{-}01\text{T}00:00:00.000000000\text{Z}, 2554\text{-}07\text{-}21\text{T}23:34:33.709551615\text{Z}]$. Los años anteriores a 1970 y los desbordamientos posteriores a julio de 2554 son rechazados con `RANGE_ERROR_UNIX_EPOCH_BOUNDS`.
3. **Conformidad POSIX IEEE Std 1003.1 sobre Segundos Intercalares:** Todo día civil contiene 86,400 segundos. Los segundos intercalares se rechazan explícitamente para garantizar que no existan colisiones ni ambigüedades en la escala de nanosegundos acumulados.
4. **Rechazo de Precisión Sub-Nanosegundo:** Se prohíbe truncar silenciosamente fracciones mayores a 9 dígitos fraccionarios.
