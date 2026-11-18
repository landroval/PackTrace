# Offline npm integrity check (Linux, unreleased)

## English

```text
packtrace verify-integrity --policy FILE --trusted-policy-digest SRI ROOT
packtrace verify-integrity --help
```

Use an explicitly reviewed **external version-1 policy** and its independently
trusted canonical SHA-256/384/512 SRI. The pin identifies the exact policy bytes;
do not calculate a new pin merely to make changed, unreviewed input pass.
The policy must select a supported npm profile (for example `npm@10.9.4`), require
only integrity, and use `minimumAssurance: "independently-anchored"`. Its local
reference archives must be outside the target, under the external policy root.
Each reference maps an exact installed location and selected lock claim to an
expected archive SRI. The existing policy/reference syntax is documented in the
[user manual](user-guide.md#7-policies-references-and-exceptions).

Both options are mandatory. No other options or saved setup are used. Output is
short portable text: comparison completeness and positive drift count, without
package identities, paths or hashes. There is no JSON authority import or output
file option; redirect stdout to an external file if needed. No network requests,
installs, target configuration/credentials, or package code execution occur.

- **0:** every installed instance and selected reference joins uniquely; actual
  reference verification and readable content comparison completed, with no drift.
- **1:** the same complete comparison found modified, missing, added or type-changed
  content. Drift is not malware. Scan-policy exceptions do not suppress this count.
- **3:** missing reference, unreadable/unstable input, extra/unmapped/ambiguous
  instance, unsupported layout, or insufficient original evidence. This takes
  precedence over positive drift. A positively closed empty installed scope with
  no references can complete; missing inventory is not an empty scope.
- **2:** invalid input/pin, fatal acquisition, resource observation, output, close,
  or reap failure. **130:** actual interruption. Precedence: `130 > 2 > 3 > 1 > 0`.

This is **not `scan`** and does not weaken its existing gates. It performs no
malicious-package or vulnerability advisory checks and makes no cross-platform
release-qualification claim. npm workspaces, links/stores or other unsupported
ownership layouts remain incomplete, not silently excluded. It uses the same
bounded supervised parser, original-byte receipts, unique reference/instance
joins, source leases, and final lifecycle checks as scan.

### Qualification boundaries

Untouched owned offline `npm pack` artifacts are regression-tested in ordinary,
scoped and nested instance locations, including nested file paths. This does not
establish compatibility with every npm version or registry archive. The reference
profile is bounded gzip/USTAR regular files/directories with exactly two terminal
zero blocks; extra tar record padding, PAX/GNU extensions and links are unsupported
and remain incomplete. Never truncate or repack a reference to obtain acceptance.
See [fixture provenance](../cmd/packtrace/testdata/npm-pack/README.md).

Only this command explicitly selects **`verify-npm-v1`**; legacy `scan` and the
legacy archive API keep their prior semantics. It permits exactly one safe,
case-sensitive top-level envelope, explicit or inferred, strips exactly that
component, and permits directory headers with or without one final `/`. The
envelope is never package identity. Mixed roots, root files, collisions, unsafe
components, special entries and nonzero unused link/padding fields are rejected.
A historical USTAR variant permits only an otherwise empty prefix containing two
identical 11-digit octal/NUL timestamps at offsets 476 and 488, with zero bytes
345–475 and 500–511. This does not enable GNU/PAX interpretation or arbitrary
nonzero prefix tails. Checksums, numeric grammar, resource bounds, exact tar/gzip
termination and SRI over the **unaltered compressed bytes** remain mandatory.

Authenticated published files may qualify their exact ancestor namespaces for
native traversal, including package-shaped fixture directories. This is not an
ownership grant from archive membership: the entire physical subtree, including
extras, must be captured and bounded/stably read and compared. Separately mapped
or locked owners take precedence; a captured manifest at a content-only candidate
also retains a potential separate-owner gap. Deeper unpublished package boundaries, links,
unreadable/unstable content and ambiguous ownership remain negative evidence.
Empty published directories alone do not qualify traversal. Distinct negative
boundaries retain distinct opaque evidence identities through portable reporting.

An offline public pilot covers all 160 original SRI-verified archives of the
retained `node-js-getting-started` lock snapshot. The installed tree was previously
reconstructed from those archives, **not independently installed**; equality is
not independent producer or publisher authentication. Intact, drift, missing,
mixed and restored controls use one binary, policy and pin without repacking.
This evidence does not qualify all registry archives or every assurance dimension.

Command-level tests cover an expired deadline, a real blocked-output deadline
(with joined/reaped writer), and a real supervisor observation gap that trips the
resource guard. These supplement output-failure and interruption coverage; they
are **not qualification of every lifecycle limit**. Resident-threshold exhaustion
and actual late close/reap failures have not been induced through this command.
Shared execution tests exercise additional finalization faults, not a substitute
for command-level fault qualification. No production fault-injection switches exist.

Output describes the frozen comparison snapshot, not predicted output/cleanup
success. A late error can override the process status after bytes were emitted;
those bytes are not rewritten. Always inspect the actual process exit status.
Live filesystem checks are not an immutable snapshot or protection against a
host-controlling attacker. Equality is not a safety verdict or publisher identity.

## Español

```text
packtrace verify-integrity --policy ARCHIVO --trusted-policy-digest SRI RAÍZ
packtrace verify-integrity --help
```

Selecciona una **política externa versión 1 revisada** y el SRI canónico
SHA-256/384/512 de sus bytes exactos, obtenido de una fuente de confianza.
No recalcules el pin para aceptar cambios sin revisar. La política debe seleccionar
un perfil npm compatible (por ejemplo `npm@10.9.4`), requerir únicamente integridad
y usar `minimumAssurance: "independently-anchored"`. Los archivos de referencia
locales deben estar fuera del proyecto, dentro de la raíz externa de la política.
Cada referencia relaciona ubicación instalada, identidad del lockfile y SRI exacto
del archivo. Véase la sintaxis existente en el [manual](user-guide.es.md).

Ambas opciones son obligatorias; no acepta otras opciones ni configuración guardada.
La salida breve y portable indica comparación completa/incompleta y número de
cambios, sin identidades, rutas ni hashes. No importa autoridad desde JSON público.
No usa red, instalaciones, configuración/credenciales del proyecto ni ejecuta código.

- **0:** todas las instancias y referencias tienen correspondencia única; se
  verificaron las referencias y se compararon los contenidos legibles, sin cambios.
- **1:** comparación completa con cambios positivos (modificados, ausentes, añadidos
  o de tipo). No implica malware; las excepciones de `scan` no ocultan estos cambios.
- **3:** falta una referencia o evidencia, hay datos ilegibles/inestables, instancias
  extra/ambiguas o un diseño no compatible. Prevalece aunque haya cambios. Un alcance
  vacío enumerado completamente puede completarse; ausencia de evidencia no es vacío.
- **2:** entrada/pin inválidos o fallo fatal de adquisición, recursos, salida, cierre
  o recolección de procesos. **130:** interrupción real. Orden: `130 > 2 > 3 > 1 > 0`.

**No es `scan`**: no cambia sus requisitos ni sus salidas. No consulta avisos de
paquetes maliciosos/vulnerabilidades ni declara calificación multiplataforma.
Los diseños no compatibles (workspaces, enlaces/almacenes, propiedad ambigua) siguen
incompletos. Reutiliza el análisis supervisado, evidencia original, correspondencias
únicas, leases y controles finales de `scan`.

### Límites de calificación

Se prueban archivos propios de `npm pack` offline, sin modificar, en ubicaciones
normales, con scope y anidadas, con rutas internas anidadas. No demuestra
compatibilidad con todas las versiones npm ni archivos del registro. El perfil
admite gzip/USTAR acotado, archivos regulares/directorios y exactamente dos bloques
cero finales. Padding adicional, extensiones PAX/GNU y enlaces siguen incompletos.
No trunques ni reempaquetes una referencia para conseguir aceptación.
Véase la [procedencia del fixture](../cmd/packtrace/testdata/npm-pack/README.md).

Solo este comando selecciona explícitamente **`verify-npm-v1`**; `scan` y la API
antigua conservan sus semánticas. Admite una única envoltura superior segura,
sensible a mayúsculas, explícita o inferida; elimina exactamente ese componente
y permite directorios con o sin una `/` terminal. La envoltura no establece
identidad. Rechaza raíces mixtas, archivos raíz, colisiones, componentes inseguros,
entradas especiales y bytes no nulos en campos de enlace/padding sin uso.
La variante histórica USTAR solo admite dos marcas octales idénticas de 11 dígitos
más NUL en offsets 476 y 488, con ceros en 345–475 y 500–511 y sin prefijo de ruta.
No habilita GNU/PAX ni colas arbitrarias. Conserva checksum, gramática numérica,
límites, terminación exacta tar/gzip y SRI de los **bytes comprimidos originales**.

Los archivos publicados autenticados pueden habilitar el recorrido nativo de sus
ancestros exactos, incluso directorios fixture con forma de paquete. La pertenencia
al archivo no concede propiedad: se captura y compara todo el subárbol físico,
incluidos extras, con lecturas estables y acotadas. Propietarios mapeados o del
lock separados prevalecen; un manifiesto físico en un candidato de contenido
mantiene el hueco de posible propietario separado. Límites más profundos no publicados, enlaces, contenido
ilegible/inestable y propiedad ambigua siguen siendo evidencia negativa. Directorios
publicados vacíos no bastan. Los límites negativos distintos mantienen identidades
opacas de evidencia distintas, incluso en la salida portable.

El piloto público offline cubre los 160 archivos originales verificados por SRI del
lock retenido de `node-js-getting-started`. El árbol instalado fue reconstruido
previamente desde esos archivos, **no instalado independientemente**. Igualdad no
autentica al productor/editor. Los controles intacto, cambios, referencia ausente,
mixto y restaurado usan el mismo binario, política y pin, sin reempaquetar. Esto no
califica todos los archivos del registro ni todas las dimensiones de garantía.

Las pruebas del comando cubren plazo vencido, plazo con salida realmente bloqueada
(y writer recolectado), y una pausa real de observación que activa el control de
recursos. No califican todos los límites: no se han provocado agotamiento del
umbral residente ni fallos reales tardíos de cierre/recolección mediante este
comando. Las pruebas compartidas de ejecución cubren otros fallos, sin sustituir
esa calificación. No existen interruptores de inyección de fallos en producción.

La salida describe la comparación congelada, no predice el éxito de escritura o
limpieza. Un error posterior puede cambiar el estado del proceso sin reescribir
bytes emitidos: comprueba siempre el código real. No es una instantánea inmutable,
ni protege frente a quien controla el host. Igualdad no significa seguridad ni
autenticación del editor.
