# Manual de uso de PackTrace

[English](user-guide.md) · [Inicio del proyecto](../README.es.md)

Este manual describe el binario experimental actual, no una versión cualificada
para producción. Los comandos y las etiquetas permanecen en inglés. Los ejemplos
usan Bash salvo indicación contraria. Las rutas como `/operator/config/policy.json`
son ejemplos: elige rutas privadas, externas al proyecto, antes de ejecutar nada.
La documentación no autoriza automáticamente descargas, borrados, acceso a
proyectos reales ni campañas de cualificación nativa.

## Índice

1. [Propósito y límites](#1-propósito-y-límites)
2. [Compilación y requisitos](#2-compilación-y-requisitos)
3. [Primera configuración](#3-primera-configuración)
4. [Preparación de inteligencia](#4-prepara-y-mantén-la-inteligencia)
5. [Cómo leer el informe](#5-lee-el-informe-sin-confundir-cantidades-con-riesgo)
6. [Referencia de scan](#6-referencia-del-comando-scan)
7. [Políticas, referencias y excepciones](#7-políticas-referencias-y-excepciones)
8. [Privacidad y archivos de informe](#8-privacidad-y-archivos-de-informe)
9. [Códigos de salida y automatización](#9-códigos-de-salida-y-automatización)
10. [Problemas comunes](#10-solución-de-problemas)
11. [Herramientas de entrada suministrada](#11-herramientas-de-entrada-suministrada)
12. [Límites y referencias técnicas](#12-límites-y-referencias-técnicas)

## 1. Propósito y límites

Si no conoces un comando, empieza por `packtrace --help`: presenta **Scan a project
(offline)** —analizar—, **Prepare security advisory data** —preparar avisos— y
**Understand a result** —interpretar— antes de las herramientas avanzadas.
`packtrace scan --help` explica los conceptos del resultado antes de las opciones
técnicas. Los comandos, argumentos y controles de confianza no cambian; no hay
asistente automático, acceso de red ni reparación automática.

PackTrace investiga evidencia de dependencias. No ejecuta el proyecto, instala
paquetes, ejecuta scripts de instalación/compilación/pruebas, repara dependencias,
pone archivos en cuarentena, busca credenciales de registros del proyecto ni
certifica que el equipo esté limpio. `scan` no usa la red. La operación separada
`intel sync` sí usa la red explícitamente.

Son tres preguntas diferentes:

| Comprobación | Pregunta | Lo que un resultado positivo no demuestra |
| --- | --- | --- |
| `malicious` | ¿La evidencia admitida identifica un paquete/versión conocido como malicioso? | Que se ejecutara su código |
| `vulnerability` | ¿La versión observada coincide con un aviso admitido? | Que la funcionalidad vulnerable sea accesible en esta aplicación |
| `integrity` | ¿Los archivos instalados seleccionados difieren de una referencia preparada y validada? | Que una diferencia sea malware o que bytes idénticos sean benignos |

El resultado mantiene separados **declared** —intención del manifiesto—,
**locked** —resoluciones del lockfile— y **observed installed** —observaciones
físicas—. Una entrada del lockfile no demuestra instalación; un manifiesto
instalado no autentica ni el contenido ni al editor.

### Glosario sencillo

| Término | Significado en PackTrace |
| --- | --- |
| `intel` / inteligencia | Base local de avisos de seguridad; no inteligencia artificial |
| Advisory / aviso | Informe de una fuente sobre un paquete malicioso o una vulnerabilidad; no prueba impacto en la aplicación |
| Snapshot / generación | Una versión fija de la base local preparada |
| Origin / origen | Procedencia registrada de una dependencia; declararla no autentica al editor |
| Candidate / candidato | Pista de identidad/versión con origen o aplicabilidad no confirmados; no vulnerabilidad confirmada |
| Finding / hallazgo | La evidencia cumple las reglas seleccionadas; no demuestra ejecución |
| Coverage / cobertura | Qué comprobaciones requeridas se establecieron y cuáles faltan |
| Policy / enforcement | Reglas externas revisadas que eligen comprobaciones y qué hallazgos no aceptados hacen fallar la ejecución |
| Reference / integrity | Referencia preparada de comparación / comparación de archivos; bytes iguales no certifican seguridad |

Usa una cuenta normal. Mantén política, inteligencia, referencias e informes fuera
del proyecto. Las comprobaciones de propiedad y separación física pueden rechazar
rutas aunque su texto parezca correcto. No las debilites para obtener un resultado verde.

## 2. Compilación y requisitos

No hay instalador publicado ni binario de release cualificado. Utiliza una copia
revisada del repositorio y un toolchain ya instalado compatible con `go.mod`
—Go 1.27.1—. El programa principal solo depende de la biblioteca estándar de Go.
**No necesitas ejecutar npm ni Bun** para analizar; no los ejecutes contra un
proyecto sospechoso para prepararlo.

Desde la copia de PackTrace, no desde el proyecto investigado:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go build -o ./packtrace ./cmd/packtrace
./packtrace --help
./packtrace --version
```

Instala el binario en tu `PATH` con el procedimiento habitual de tu sistema.
En los ejemplos posteriores el comando es `packtrace`. En Windows puede ser
necesario invocar `.\packtrace.exe` según el shell; los ejemplos usan rutas Unix.
La compilación cruzada no demuestra soporte nativo. Las garantías de Linux y
Windows tienen evidencia acotada; la cualificación de macOS está aplazada.

Para comprobar avisos necesitas **inteligencia preparada**: compilar no incluye
un corpus vivo. La comparación de integridad requiere además mapas revisados y
archivos de referencia preparados; tener un lockfile no basta para activarla.

## 3. Primera configuración

### A. Selecciona inteligencia local preparada

Si un operador ya preparó un almacén, comprueba ese almacén exacto sin modificarlo:

```bash
packtrace intel status --state-dir /operator/state/intelligence
```

Si no existe, elige [preparación online explícita o importación offline](#4-prepara-y-mantén-la-inteligencia).
No crees una carpeta arbitraria esperando que `scan` la adopte o repare.
El almacén debe estar en un sistema de archivos persistente admitido y fuera del proyecto.

### B. Crea y revisa una política externa

Guarda este JSON como `/operator/config/policy.json`, dentro de una carpeta privada
externa al proyecto. Es un **ejemplo report-only de investigación de candidatos**
para Bun 1.3.x. Permite explícitamente búsquedas locales de identidad y versión
con origen desconocido; no autentica ese origen ni autoriza la red.

```json
{
  "version": 1,
  "designation": "user-designated",
  "reason": "Investigate recorded dependency identities and versions offline",
  "provenance": "Operator-reviewed external report-only policy",
  "manager": "bun@1.3.x",
  "requiredChecks": ["malicious", "vulnerability"],
  "failOn": [],
  "requireHardMemoryLimit": false,
  "minimumAssurance": "lockfile-consistent",
  "references": [],
  "advisoryCandidates": true
}
```

Para npm utiliza `"manager": "npm@10-11"` o `"npm@12.x"`, según corresponda.
Selecciona la interpretación realmente adecuada; no declares otro gestor para
eludir un rechazo. El ejemplo omite deliberadamente referencias de integridad y
permisos de origen público. No permite afirmar que se completó la integridad ni
que las vulnerabilidades estén confirmadas.

En Linux, si los manifiestos instalados por Bun están enlazados a una caché conocida,
puedes añadir explícitamente `"bunCacheDirectory": "/absolute/operator-selected/bun-cache"`
al JSON **antes** de revisarlo y registrarlo. La raíz debe estar físicamente
separada del proyecto y de las otras raíces requeridas. Este perfil opcional solo
lee manifiestos mediante un par verificado e inalterado de exactamente dos nombres
o enlaces. La caché no se convierte en prueba del editor. Más de dos enlaces
siguen rechazados; no hay descubrimiento de caché ni autorización general automática.

### C. Regístrala una vez

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence
```

`setup` valida la forma de la política, guarda un pin SHA-256 de los bytes
seleccionados explícitamente y escribe la configuración del usuario. **No** analiza
el proyecto, crea un almacén, descarga, actualiza ni poda inteligencia.

Para guardar salida portátil en vez del detalle local predeterminado:

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence --privacy portable
```

Elige uno de esos comandos, no ambos: una configuración existente nunca se
sobrescribe. Las comprobaciones guardadas proceden de `requiredChecks` de la
política; el enforcement sigue controlado por ella. El argumento opcional
`--trusted-snapshot-digest SHA256_SRI` fija una generación designada de forma
independiente; sin él se usa la generación local actual que ya exista. Un pin
no autentica al editor.

Se guarda en `os.UserConfigDir()/packtrace/setup.json`: normalmente
`$XDG_CONFIG_HOME/packtrace/setup.json` o `~/.config/packtrace/setup.json` en Linux,
`%AppData%\packtrace\setup.json` en Windows y la ubicación correspondiente en otros
sistemas —la ubicación no supone soporte de plataforma—. Se verifica su vinculación
con la raíz privada y su propietario. No copies `setup.json` entre raíces o equipos
como método de instalación. La política original permanece donde está; las rutas
relativas de referencias siguen interpretándose desde su directorio.

### D. Usa el comando corto

```bash
packtrace scan /ruta/al/proyecto
packtrace scan --verbose /ruta/al/proyecto
packtrace scan --format json /ruta/al/proyecto
```

Elige la raíz del paquete o workspace que contenga el manifiesto y lockfile
pertinentes. No necesitas instalar dependencias ni el programa lo hace.
El código `3` puede acompañar evidencia parcial útil: lee las limitaciones antes
de asumir un fallo operativo o concluir que todo es seguro.

### E. Cambiar ajustes después

Actualmente hay una política/gestor guardados, sin asistente de perfiles ni
subcomandos de sobrescritura, reset o desinstalación. Editar la política fijada
hace fallar el análisis normal: los bytes nuevos no se aprueban silenciosamente.
No borres evidencia ni edites el pin guardado para ocultar el error.

Para otra política revisada, haz una selección explícita de una sola ejecución:

```bash
packtrace scan --policy /operator/config/another-policy.json --trusted-policy-digest "$POLICY_SRI" --state-dir /operator/state/intelligence --privacy local /ruta/al/proyecto
```

`POLICY_SRI` debe ser el SRI canónico de la política revisada independientemente.
`--policy` explícito evita la configuración guardada: no mezcla sus valores de
estado, privacidad ni snapshot. Calcular un hash nuevo de bytes no revisados no
es aprobarlos. Los argumentos normales `--privacy`, `--checks` y `--state-dir`
solo sustituyen valores guardados cuando lo permite la política efectiva.
Los argumentos no pueden debilitar una política.

## 4. Prepara y mantén la inteligencia

**Solo `intel sync` usa la red.** Estos comandos no toman el directorio guardado
por `setup`; indica el mismo `--state-dir` expresamente. Sin ese argumento, usan
`os.UserCacheDir()/packtrace`, normalmente `~/.cache/packtrace` en Linux.
Las rutas deben superar comprobaciones de propiedad, persistencia y separación.

### Qué te dice status

`packtrace intel status --state-dir DIR` lee el almacén seleccionado: sustituye
`DIR` por la ruta revisada del almacén, no por la raíz del proyecto. La terminal
lo llama **Security advisory database (intel)** y explica la cantidad de avisos,
la comprobación de fuente de 24 horas y la reconciliación completa de siete días
—independientes—, la designación de fuente y la evidencia sin resolver. Los avisos
no son paquetes instalados ni vulnerabilidades confirmadas. Las fechas actuales
no resuelven identidades desconocidas ni establecen cobertura completa.

Si faltan datos, explica que no hay base local utilizable para comprobar avisos,
**no** que no existan amenazas. Si caducan fechas, sugiere una sync explícita con
sus efectos sobre red y disco. Una reconciliación completa caducada requiere
`--full`; una designación de fuente desconocida requiere revisión, no inventar
un pin. Las sugerencias nunca se ejecutan solas. Actualizar no arregla manifiestos
ilegibles, orígenes desconocidos ni cualificación pendiente de PackTrace. Los pins
de snapshot del análisis siguen vigentes hasta una selección de generación revisada
por separado.

### Preparación online: trabajo explícito de red y disco

Si autorizas obtener inteligencia pública de npm a través de OSV:

```bash
packtrace intel sync --full --state-dir /operator/state/intelligence
```

Para una sincronización incremental posterior:

```bash
packtrace intel sync --state-dir /operator/state/intelligence
```

Son operaciones importantes, no una consulta ligera sobre un paquete. El perfil
limita una operación a 900 segundos, el almacenamiento lógico gestionado más
reservas a 32 GiB, la reserva de staging por operación a 16 GiB y las respuestas
de sincronización a 2 GiB. Son límites, **no** estimaciones de espacio libre
necesario, garantías de ocupación física ni permiso para reintentar automáticamente.
Revisa almacenamiento, licencias y autorización de red primero. No se envían
nombres del proyecto ni listas de sus paquetes: se prepara la fuente pública
admitida. Un editor obligatorio desconocido o datos inválidos pueden bloquear
la preparación. Un fallo no autoriza reintentos ni descarta silenciosamente la
última generación válida.

La comprobación de fuente tiene una vigencia de 24 horas y la reconciliación
completa independiente de siete días. El instante límite aún es vigente; después
caduca. Una comprobación incremental no renueva la antigüedad de la reconciliación
completa. Importar datos o fijar su retención tampoco los hace actuales.

### Transferencia offline

Con un almacén preparado y un destino **nuevo**, fuera del almacén:

```bash
packtrace intel export --state-dir /operator/state/intelligence --output /operator/transfer/snapshot.bundle
```

En el almacén receptor, con un digest del descriptor obtenido independientemente:

```bash
packtrace intel import --state-dir /operator/state/imported --trusted-snapshot-digest "$SNAPSHOT_SRI" /operator/transfer/snapshot.bundle
packtrace intel status --state-dir /operator/state/imported --format json
```

`SNAPSHOT_SRI` es un único SRI SHA-256 canónico del descriptor del snapshot,
**no** el checksum del archivo bundle. El bundle no se concede confianza a sí mismo.
La importación puede inicializar un almacén propio nuevo y reconstruye las
proyecciones desde los originales, pero no hereda el sello de adquisición local
de otra instalación ni renueva fechas de fuente. No se adoptan directorios
existentes sin los marcadores propios. Exportar no sobrescribe archivos.

### Retención y borrado

`GENERATION_HEX` es el ID exacto de generación: 64 caracteres hexadecimales en
minúsculas, distinto de cero; no un SRI. Estos pins evitan que se pode una
generación elegible: no fijan la selección de `scan` ni cambian su vigencia.

```bash
packtrace intel pin --state-dir /operator/state/intelligence "$GENERATION_HEX"
packtrace intel unpin --state-dir /operator/state/intelligence "$GENERATION_HEX"
packtrace cache prune --state-dir /operator/state/intelligence --format json
```

El último comando es **solo una previsualización**. El siguiente es una operación
destructiva separada: revisa la previsualización exacta, aprueba el borrado e
indica su digest inalterado. No lo ejecutes solo porque aparezca en este manual.

```bash
packtrace cache prune --state-dir /operator/state/intelligence --apply "$PREVIEW_HEX" --format json
```

Antes de aplicar se revalidan lectores, pins, propiedad y generaciones protegidas.
Una previsualización copiada o caducada no es autorización de borrado. Ante
incertidumbre se conservan y contabilizan los datos; borrar carpetas de forma
amplia no es el procedimiento de recuperación.

## 5. Lee el informe sin confundir cantidades con riesgo

### Orden recomendado

1. **Summary:** ¿qué inventario y comprobaciones estaban realmente disponibles?
2. **Packages to review:** ¿qué paquetes/versiones tienen hallazgos o candidatos?
3. **Why these matches need review:** ¿qué dice el original, qué condición
   coincide y qué hay que verificar?
4. **Coverage limitations / Project checks:** ¿qué evidencia del proyecto falta? Después lee **PackTrace validation**: garantías de herramienta, no defectos del proyecto.
5. **Required coverage / código de salida:** ¿se completó la política seleccionada?

### Etiquetas y colores

| Etiqueta | Color en terminal compatible | Significado |
| --- | --- | --- |
| `[OK]` | Verde | Esa comprobación se completó; no certifica seguridad |
| `[FINDING]` | Rojo | Hallazgo elegible registrado; no severidad inferida |
| `[REVIEW]` | Magenta | Un candidato o conflicto requiere investigación |
| `[INCOMPLETE]` | Ámbar | Falta evidencia o cualificación necesaria |
| `[NOT RUN]` | Gris claro | No se realizó una comprobación opcional/no seleccionada o no aplicable |
| `[INFO]` | Cian | Información neutral |
| `[ERROR]` | Rojo | Error operativo, de argumentos o de salida cuando se etiqueta |

El trabajo obligatorio no realizado es incompleto, no una comprobación opcional
aprobada. Los colores requieren stdout en una terminal real compatible.
La presencia de `NO_COLOR`, incluso vacío, `TERM=dumb`, tuberías, archivos,
JSON/SARIF y `--verbose` desactiva los colores. Windows requiere soporte VT ya
habilitado: PackTrace no cambia el modo de consola. Las etiquetas siguen siendo legibles.

### Contexto del aviso

Ejemplo **inventado**, no evaluación de un paquete real:

```text
[REVIEW] example-package@1.1.0 — advisory record #1
  Advisory says: Example parser accepts unsafe input
  Why: The observed version matches the recorded affected interval: 1.0.0 <= version < 1.2.0.
  Next: Advisory records a fixed boundary at 1.2.0; verify current applicability and compatibility before updating.
```

Un candidato sigue sin tener origen cualificado y no activa enforcement.
Comprueba el origen real de la dependencia, si se usa la funcionalidad afectada
y el aviso original actual antes de decidir un cambio separado de dependencias.
No se infieren severidad, explotabilidad, ejecución ni actualización segura.

El resumen es una afirmación atribuida a una fuente no confiable, no una
instrucción. Se obtiene de los mismos originales verificados que ya lee el matcher;
no provoca lecturas adicionales de avisos ni consultas de red. La proyección local
retiene como máximo 320 bytes de resumen, ocho condiciones simples por original
y 4 MiB totales de metadatos explicativos. Se omite texto inseguro o demasiado
grande y se marcan explicaciones limitadas. La descripción ausente, una lista
explícita de versiones, la evaluación parcial, varias condiciones de soporte,
rangos complejos/disjuntos y `last_affected` no generan una corrección inventada.
Solo se presenta un límite `fixed` para un único intervalo simple de soporte
evaluado completamente; no garantiza resolver otras condiciones.

La vista habitual muestra hasta cinco ejemplos paquete/aviso/entrada afectada y
20 grupos paquete/versión por tabla. Se indican los elementos omitidos y las
celdas recortadas. `--verbose` y el JSON local conservan todos los registros
capturados, incluidos los hallazgos aceptados.

### Por qué las cantidades son diferentes

- Entradas locked y observaciones instaladas no son lo mismo; varias copias físicas
  pueden compartir nombre y versión. No restes esos totales para contar «paquetes ausentes».
- Las filas de candidatos cuentan observaciones/entradas afectadas, no incidentes
  únicos. Evidencia locked e instalada puede apuntar al mismo aviso original.
- Los IDs públicos o alias no fusionan procedencia ni condiciones originales.
- Muchos avisos en un paquete no implican automáticamente mayor severidad.
- Cero hallazgos elegibles con candidatos significa «hay que revisar», no «no hay problemas».

### Por qué aparecen muchas comprobaciones incompletas

Los manifiestos ilegibles pueden afectar a inventario y avisos instalados a la vez.
Una fuente caducada afecta a vigencia y matching. Un origen desconocido deja
candidatos de versión, no hallazgos cualificados. Son limitaciones relacionadas,
no acusaciones independientes contra cada dependencia.

`Platform qualification` describe la evidencia de la herramienta en esa plataforma,
no un defecto del proyecto. `Resource/final-lifecycle evidence` y los snapshots de
comparación no demuestran un agotamiento de memoria ni una limpieza final terminada.
La comprobación verde de trabajo de comparación se limita explícitamente a la
etapa anterior a salida y limpieza. La vista habitual los agrupa por separado en
**Project checks (evidence used for this investigation)** y **PackTrace validation
(tool assurance, not project defects)**. No oculta ni exime obligaciones: ambos
grupos pueden dejar cobertura incompleta y salida `3`. Limitaciones relacionadas
de inventario o vigencia no son hallazgos adicionales ni acusaciones independientes.
Actualizar inteligencia no resuelve enlaces
no admitidos, orígenes desconocidos, integridad no seleccionada ni cualificación
del producto pendiente.

## 6. Referencia del comando scan

```text
packtrace scan [options] ROOT
```

`ROOT` es exactamente una ruta. Las opciones van antes; `--` termina su interpretación
si la ruta empieza con un guion. Las opciones desconocidas o repetidas fallan.
La ayuda se usa sola: `packtrace scan --help`.

| Opción | Valores y comportamiento |
| --- | --- |
| `--manager` | `auto`, `npm`, `npm@10-11`, `npm@12.x`, `npm@VERSION`, `bun`, `bun@1.3.x`, `bun@VERSION`; solo perfiles estables admitidos |
| `--checks` | Subconjunto no vacío de `malicious,vulnerability,integrity`, separado por comas, sin espacios ni repetidos |
| `--fail-on` | `none` o categorías seleccionadas; no debilita enforcement de la política |
| `--policy` | Política JSON externa versión 1; evita la configuración guardada |
| `--trusted-policy-digest` | Un SRI SHA-256/384/512 canónico de bytes revisados |
| `--state-dir` | Almacén externo ya preparado; no lo inicializa |
| `--trusted-snapshot-digest` | Un SRI SHA-256 canónico del descriptor designado independientemente |
| `--privacy` | `portable` o `local` permitido por la política |
| `--format` | `terminal` por defecto, `json`, `sarif` |
| `--verbose` | Solo terminal, sin valor; incompatible con JSON/SARIF |
| `--output` | Archivo nuevo en un directorio externo existente admitido; restricciones más abajo |

Sin configuración guardada ni política explícita se seleccionan las tres
comprobaciones, report-only, privacidad portable y ningún permiso de referencias,
origen o búsquedas de candidatos. Puede inventariar entradas admitidas, pero no
supone una investigación de avisos e integridad completamente configurada.

Seleccionar gestor interpreta formatos: no autentica al productor ni al origen.
`auto` acepta una raíz admitida sin ambigüedad, sin exigir pista de productor.
Varios locks npm sin pista requieren selección npm explícita. Mezclas npm/Bun o
pistas no admitidas siguen siendo limitaciones. npm 10/11 usa prioridad de
shrinkwrap y v2/v3; npm 12 ignora shrinkwrap, no recurre a él y solo admite v3.
Bun 1.3.x admite texto v0/v1 con configuración ausente/0/1. Locks binarios, npm v4,
extensiones/preliminares no admitidas y propiedad insegura o ambigua dejan cobertura incompleta.

## 7. Políticas, referencias y excepciones

Las políticas son datos, no configuración ejecutable del proyecto. No se descubre
`.npmrc`, política del proyecto ni credenciales. El parser exige nombres canónicos,
sin campos desconocidos/duplicados ni permisos null; máximo 256 KiB.

| Campos | Significado |
| --- | --- |
| `version`, `designation` | `1` y `user-designated` |
| `reason`, `provenance` | Razón no vacía del operador; declararla no demuestra independencia |
| `manager` | Perfil concreto o de rango admitido; no `auto`/`npm`/`bun` sin versión |
| `requiredChecks`, `failOn` | Cobertura requerida y categorías exigibles; arrays; `failOn` puede estar vacío |
| `requireHardMemoryLimit` | Actualmente debe ser `false`; no hay garantía hard-RSS no admitida |
| `minimumAssurance` | `lockfile-consistent` o `independently-anchored` |
| `references` | Array requerido; vacío si no se seleccionan referencias preparadas |
| `advisoryCandidates` | Búsqueda local explícita con origen ambiguo; no cualifica el origen |
| `bunCacheDirectory` | Raíz Bun absoluta explícita opcional; solo perfil Linux de par cerrado |
| `npmOrigins` | Hasta 64 correspondencias npm exactas de ubicación/nombre/versión/origen; no autenticidad general |
| `npmRegistry` | Permiso opcional revisado para el registro público npm; no acceso de red ni prueba del contenido instalado |
| `requirePortable` | Rechaza salida local si es true |
| `exceptions`, `maxExceptionDays` | Aceptación exacta revisada; nunca exención de cobertura |

Se requiere pin independiente de política para candidatos, caché Bun, permisos de
origen/registro npm, excepciones y referencias independently-anchored. `setup`
guarda esa designación una vez; una ejecución explícita debe recibir el pin por
separado. No declares público un paquete privado/desconocido para obtener hallazgos.
La investigación de candidatos Bun no establece origen npm público.

### Referencias de integridad

La integridad requiere un mapa explícito de cada ámbito instalado admitido y un
archivo preparado. Cada objeto contiene `location`, `lockKey`, `name`, `version`,
`origin`, `classification` (`public|private|unknown`), `expectedSRI`, `archive` y
`context` (`none|patch|generated`). Las rutas de ámbito y archivo son selectores
relativos acotados; `archive` se resuelve desde el directorio de la política.

Un SRI de lockfile normalmente identifica un **archivo publicado**, no el directorio
instalado. Una caché o archivo arbitrario no es automáticamente una referencia
autenticada. `lockfile-consistent` e `independently-anchored` son garantías distintas;
colocar archivos fuera del proyecto o calcular su hash no establece la segunda.
El contexto de patch/build no ejecuta transformaciones ni elimina diferencias.
No hay comando general de descarga de artefactos en PackTrace: prepara las
referencias confiables por separado. Consulta el [contrato de política e integridad](increments/issue-8-trusted-policy-and-exceptions.md).

### Excepciones revisadas

Cada excepción contiene `id`, `reason`, `owner`, `approvedAt`/`expiresAt` UTC,
un `scope` exacto y un fingerprint `acceptance` vinculado a la evidencia.
El ámbito incluye `project`, `category`, `rule`, `class`, `package`, `version`,
`origin`, `instance`, `path`, `advisory` y `change`: son campos exactos, no comodines.
Usa evidencia revisada, no fingerprints inventados ni exclusiones solo por nombre.

Se permiten hasta 64 excepciones. La duración máxima por defecto es 30 días UTC
transcurridos; una ampliación explícita fijada por política alcanza como máximo
365. Fechas futuras, caducidad, falta de correspondencia o cambios de evidencia
no aceptan nada. Los hallazgos aceptados siguen visibles. Los candidatos no se
convierten en alertas aceptadas y ninguna excepción completa trabajo no realizado.

## 8. Privacidad y archivos de informe

**Portable** oculta identidades, rutas absolutas, credenciales, claves/MAC de fuente
y pins de autoridad. Conserva referencias opacas, cantidades, estados y limitaciones.
**Local** permite nombres/versiones acotados, IDs públicos, hashes de originales,
ubicaciones relativas, fingerprints y explicaciones de avisos. No es una
exportación de contenido crudo ni permiso de subida. Una política puede exigir portable.

```bash
packtrace scan --privacy portable --format json /ruta/al/proyecto
packtrace scan --format sarif /ruta/al/proyecto
```

El JSON operativo usa esquema **1.7**, con campos locales explicativos opcionales
acotados. El soporte histórico de informes 1.0–1.6 y los esquemas de entrada
suministrada son distintos. Las vistas usan un único resultado validado, no
detectores separados. SARIF no convierte candidatos no cualificados en alertas.
Un JSON guardado no puede reconstruir el contexto privado de autoridad necesario
para un renderizado autoritativo.

La configuración guardada y el perfil opcional de caché Bun admiten actualmente
**solo stdout**: rechazan `--output FILE`. La publicación de archivo con política
explícita independiente requiere un directorio existente separado físicamente
de proyecto, almacén y referencias, nombre nuevo y mecanismo nativo Linux admitido.
Nunca crea directorios ausentes ni sobrescribe informes; rechaza destinos
antecesores, padres comunes o no admitidos.

La redirección `>` del shell **no** es la publicación protegida de PackTrace.
El shell abre o trunca el destino antes de analizar y puede seguir enlaces o
escribir dentro del proyecto. Úsala solo tras revisar un destino externo con
protección contra sobrescritura adecuada y comprobar el código final del proceso.
No publiques informes privados en issues o PR de GitHub sin aprobación explícita.

## 9. Códigos de salida y automatización

| Código | Significado |
| --- | --- |
| `0` | Completado según la política, no seguridad |
| `1` | Hallazgo exigible no aceptado |
| `2` | Error de argumentos/política/operación/informe/salida |
| `3` | Cobertura requerida incompleta, con posible evidencia parcial útil |
| `130` | Interrumpido |

Prioridad: `130` → `2` → `3` → `1` → `0`. El código de comparación del informe
puede preceder a un error posterior de salida/limpieza: usa el estado final del
proceso. Report-only afecta al enforcement, no elimina cobertura incompleta ni errores.

Bash, capturando el estado inmediatamente:

```bash
packtrace scan --format json /ruta/al/proyecto
status=$?
printf 'PackTrace exit: %s\n' "$status"
```

Nushell:

```nu
packtrace scan --format json /ruta/al/proyecto
let status = $env.LAST_EXIT_CODE
print $status
```

En CI decide explícitamente si un informe parcial debe bloquear el trabajo.
No ocultes errores con `|| true`, uses `--fail-on none` para eximir cobertura ni
interpretes cero alertas SARIF como investigación completada. Una política revisada
puede exigir categorías `failOn`; los argumentos no pueden debilitarlas.
No se garantiza código `0` en un proyecto real mientras haya limitaciones de
cobertura o cualificación pendientes en este binario experimental.

## 10. Solución de problemas

Los errores frecuentes mantienen su código fijo en la primera línea y añaden
**Effect** —qué no pudo hacerse— y/o **Next** —un paso acotado—. La orientación no
cambia códigos de salida, añade rutas privadas, aprueba pins nuevos ni evita el
escritor de diagnósticos observado. El JSON/SARIF de stdout no cambia; las
explicaciones de error van al canal de diagnósticos. Los errores desconocidos no
reciben soluciones inventadas. `DIR` es un marcador en comandos sugeridos: setup
no aporta valores guardados a las operaciones de mantenimiento.

| Síntoma | Significado y siguiente paso seguro |
| --- | --- |
| `command not found` | Compila/instala fuera del proyecto y revisa `PATH`; no es un paquete npm |
| `cli: unsupported-command` con `intel --help` | No existe ese dispatcher de ayuda; usa `packtrace --help` y este manual |
| No aparecen nombres | Portable los oculta deliberadamente; selecciona local explícitamente si la política lo permite |
| `scan: user-setup-invalid; run packtrace setup --help` | Configuración modificada/ausente/corrupta, discrepancia de política o problema de raíz/propiedad; conserva originales y revisa, no edites el pin |
| No se reemplazó la configuración existente | Setup es exclusivo; usa política explícita revisada para otra ejecución |
| `scan: unsupported-or-conflicting-options` | Discrepancia entre política, comprobaciones, privacidad, gestor o pin; no debilites controles a ciegas |
| `scan: intelligence-binding-unavailable` | Vinculación del almacén ausente, insegura, incompatible o no cualificada; revisa el almacén externo y sistema de archivos, no copies un marcador |
| Fuente caducada | Una sync autorizada puede renovar una comprobación exitosa; la reconciliación completa sigue siendo independiente |
| `installed-manifest-unavailable` | Manifiesto ausente, ilegible, inestable o inadmisible, incluidos nombres extra de hardlinks; no demuestra que falte el paquete |
| Manifiestos Bun con más de dos enlaces | Fuera del perfil de par cerrado; no borres enlaces, copies para aparentar seguridad ni relajes el control |
| `lock-version-unsupported` | Formato no admitido; registra la limitación, no instales/migres dependencias como parte del análisis |
| Cero hallazgos pero hay candidatos | Investigación de versión sin origen/aplicabilidad cualificados; revisa contexto, no los llames vulnerabilidades confirmadas |
| Muchas comprobaciones incompletas | Pueden compartir una limitación de inventario/vigencia; plataforma y ciclo final describen la herramienta, no un defecto del proyecto |
| Integridad `[NOT RUN]` | No se seleccionó la comparación; revisa comprobaciones y referencias, no la trates como aprobada |
| Se rechaza archivo de salida | Restricción stdout de setup/caché Bun, plataforma, archivo existente o destino inseguro; consulta las reglas de salida |
| `--verbose` rechazado | No lo combines con JSON/SARIF, no lo repitas ni le asignes valor |
| Sin colores | Normal con tuberías/archivos, verbose/salida de máquina, `NO_COLOR` o terminal no compatible; las etiquetas mantienen el significado |

No eleves privilegios, cambies propiedad del proyecto, reinstales dependencias,
actualices datos ni borres estado automáticamente para «arreglar» un rechazo de investigación.

## 11. Herramientas de entrada suministrada

Son experimentos avanzados y acotados sobre **stdin**, no alternativas que analicen
el proyecto de forma oculta. Obtén metadatos autorizados por separado; los ejemplos
usan datos inventados. Admiten terminal o JSON, no SARIF. Los informes útiles de
investigación siguen saliendo con `3`; argumentos, entrada o salida inválidos con
`2`. `--help` devuelve `0` sin leer stdin. Los escenarios útiles de demo también
mantienen cobertura incompleta.

| Comando | Entrada suministrada y propósito |
| --- | --- |
| `inspect` | Objeto JSON con `lockfile` y `advisory`; hipótesis de metadatos npm |
| `inspect-batch` | `lockfile` y `advisories` —1 a 16—; lote acotado |
| `inspect-bun` | Cadena original `lockfile_text` y objeto `advisory` |
| `inspect-bun-batch` | `lockfile_text` y `advisories` —1 a 16— |
| `compare-npm-root` | Objetos `manifest` y `lockfile` npm v2/v3; requisitos textuales de raíz |
| `compare-bun-root` | Objeto `manifest` y `lockfile_text` original; requisitos textuales |
| `check-reference-digest` | Bytes crudos stdin y `--integrity SRI`; solo igualdad de digest |
| `demo` | Escenario sintético propio incorporado; sin stdin ni acceso al proyecto |

`inspect`/`inspect-batch` de npm admiten `--identity-profile explicit-only` por
defecto o `npm-lock-v2-v3`; sus equivalentes Bun no. Los lotes tienen límite de
1 MiB de entrada, 64 tuplas/registros locked, 64 entradas afectadas totales y
4096 pares. Las comparaciones de raíz admiten 1 MiB; diferencia textual no es
inequivalencia semántica de rangos. La entrada del digest tiene máximo predeterminado
512 MiB —`--max-bytes` decimal 0–536870912—. Solo un token SHA-256/384/512 canónico
puede coincidir o diferir; varios tokens o formatos no admitidos dejan unknown
sin leer entrada. Igualdad no es autenticidad de referencia.

```bash
packtrace demo --scenario candidate
packtrace demo --scenario no-version-match --format json
printf '%s' abc | packtrace check-reference-digest --integrity 'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=' --format json
printf '%s' '{"manifest":{"dependencies":{"example":"^1"}},"lockfile":{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.x"}}}}}' | packtrace compare-npm-root --format json
```

Escenarios demo: `candidate`, `no-version-match`, `unsupported`, `withdrawn`,
`different-identity`, `malformed`. Consulta la ayuda de cada herramienta, por
ejemplo `packtrace inspect --help`, para su envelope exacto.

## 12. Límites y referencias técnicas

Se interpretan npm estables 10/11 v2/v3, npm 12 v3, formatos de texto Bun 1.3.x
acotados y los perfiles anteriores retenidos explícitamente. No se cualifica
cada parche de productor, distribución, sistema operativo, sistema de archivos,
almacén externo ni runtime. La evidencia instalada no constituye un grafo completo
de resolución en ejecución o accesibilidad de dependencias.

El matching está acotado: 64 observaciones activas, 4096 unidades de trabajo/filas
y 512 MiB de lecturas reales del matcher. El worker de análisis tiene un plazo de
cinco minutos. No son garantías hard-memory de todo el proceso;
`requireHardMemoryLimit: true` no se admite. Recursos, publicación, propiedad nativa
y limpieza confirmada se comprueban de forma independiente. Licencias y vigencia
siguen siendo obligatorias. No aumentes límites para esconder entradas no admitidas.

- [Decisiones de diseño](design-decisions.md): alcance y seguridad autoritativos.
- [Compatibilidad de inventario](inventory-compatibility.md): evidencia acotada de productores y distribuciones.
- [Compatibilidad de inteligencia](intelligence-compatibility.md): fuentes, licencias, mantenimiento y presupuestos; evidencia histórica por incremento.
- [Política y publicación](increments/issue-8-trusted-policy-and-exceptions.md): contratos exactos de excepciones y salida a archivo.
- [Candidatos de origen](increments/issue-6-offline-origin-candidates.md): por qué una coincidencia de versión no es un hallazgo confirmado.
- [Checklist de release](pre-1.0-features.md): cualificación pendiente, no inferida de issues cerradas.
- [Licencias de datos](../internal/intelstore/licenses/README.md): atribución y avisos de editores admitidos.

Para comprobaciones de contribución consulta [Desarrollo local](../README.es.md#desarrollo-local).
