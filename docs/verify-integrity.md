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
package identities, paths or hashes. It also reports how many selected references
were fully compared and the reasons for incomplete coverage. `ownership-ambiguous`
means the owner of some content could not be established. A full reference count
alone does not establish that every installed package was accounted for.
There is no JSON authority import or output
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

Only this command explicitly selects **`verify-npm-v2`**; legacy `scan` and the
legacy archive API keep their prior semantics. It permits exactly one safe,
case-sensitive top-level envelope, explicit or inferred, strips exactly that
component, and permits directory headers with or without one final `/`. The
envelope is never package identity. Mixed roots, root files, collisions, unsafe
components, special entries and nonzero unused link/padding fields are rejected.
A historical USTAR variant permits only an otherwise empty prefix containing two
11-digit octal/NUL timestamps at offsets 476 and 488, with zero bytes
345–475 and 500–511. Unlike v1, v2 checks the two fields independently; neither
value contributes to a path or a content comparison. This does not enable GNU/PAX interpretation or arbitrary
nonzero prefix tails. Checksums, numeric grammar, resource bounds, exact tar/gzip
termination and SRI over the **unaltered compressed bytes** remain mandatory.

Authenticated published files may qualify their exact ancestor namespaces for
native **observation**, including package-shaped fixture directories. Archive
membership does not establish installed ownership: such directories retain an
`ownership-ambiguous` gap even if all bytes match and no manifest or lock entry
exists. A separate manifestless package with identical bytes cannot be distinguished
from parent-owned fixtures. Observed content under that negative scope does not
become a parent comparison; independent drift elsewhere is still reported. Explicit
mapped/locked owners take precedence; the existing literal bundled-lock qualification
is unchanged. Deeper unpublished boundaries, links and unreadable/unstable content
remain negative evidence. Empty published directories do not qualify traversal.

**Intentional shared evidence change:** distinct negative boundaries now retain
distinct opaque `:boundary:N` identities, including in legacy `scan`. Its archive
acceptance and decision gates are unchanged, but its evidence representation is not
byte-for-byte compatible: prior `:nested`/`:unmapped` identities could alias separate
boundaries, and portable evidence ordinals can change. A local-base differential
probe (`8d60af6`, `TestLegacyBoundaryPublicContract`) covers a mapped nested owner
and two unknown boundaries: completeness, gap codes and comparisons are unchanged;
the three gaps now have three evidence identities rather than two.

The retained offline public pilot contains 160 original SRI-verified archives of
`node-js-getting-started`. Its tree was reconstructed from those same archives,
**not independently installed**. Its pin was calculated for the original experiment,
not obtained from independent policy review. Neither the old controls nor the
collector establish publisher authentication or independent installation equality.

With the conservative ownership correction, 159 instance comparisons complete;
`resolve` (instance 131) retains one `ownership-ambiguous` gap. Therefore intact and
restored whole-tree runs exit **3**, not 0. Express drift and each of the nine
formerly unusable archive instances still produce one positive drift finding, but
exit **3** because the unrelated ownership gap remains. Missing-reference and mixed
controls also exit **3**. Modifying/removing content beneath the ambiguous boundary
cannot claim a parent-owned comparison. The historical 0/1 results describe the
older inferred-ownership implementation, not this corrected executable.

### Reusable offline replay

From the repository, supply the retained evidence directory, the exact built
executable, and a **new** external output directory (none may be target code):

```text
python3 probes/offline-integrity/replay_public_pilot.py OLD_EVIDENCE EXACT_BINARY NEW_EVIDENCE
```

`OLD_EVIDENCE` must contain `owned-case/`, `owned.baseline.json`, and the existing
`policy.pin`. The script checks all 160 original archive SRIs and the retained pin,
copies the restored pilot and executable, and never creates a new pin, installs,
downloads, repacks or executes package code. It records 17 real process controls
(including nine individual archive mutations and two targeted ambiguous-ownership
probes), exact argv/status, binary SHA-256 and before/after input hashes. It restores
its copy after every control and verifies the original is unchanged. Any unexpected
exit, mutation or drift count fails the replay; it cannot upgrade experimental
trust. These results do not qualify every registry archive or lifecycle limit.

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
cambios, sin identidades, rutas ni hashes. También muestra cuántas referencias
seleccionadas se compararon por completo y los motivos de cobertura incompleta.
`ownership-ambiguous` significa que no pudo determinarse a qué paquete pertenece
parte del contenido. Completar todas las referencias no demuestra por sí solo que
se hayan verificado todos los paquetes instalados. No importa autoridad desde JSON público.
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

**No es `scan`**: no relaja sus requisitos de decisión. Las identidades compartidas
de evidencia de límites sí cambian intencionadamente (véase abajo). No consulta avisos de
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

Solo este comando selecciona explícitamente **`verify-npm-v2`**; `scan` y la API
antigua conservan sus semánticas. Admite una única envoltura superior segura,
sensible a mayúsculas, explícita o inferida; elimina exactamente ese componente
y permite directorios con o sin una `/` terminal. La envoltura no establece
identidad. Rechaza raíces mixtas, archivos raíz, colisiones, componentes inseguros,
entradas especiales y bytes no nulos en campos de enlace/padding sin uso.
La variante histórica USTAR solo admite dos marcas octales de 11 dígitos
más NUL en offsets 476 y 488, con ceros en 345–475 y 500–511 y sin prefijo de ruta.
A diferencia de v1, v2 valida cada marca por separado; ninguno de los valores
interviene en las rutas ni en la comparación del contenido.
No habilita GNU/PAX ni colas arbitrarias. Conserva checksum, gramática numérica,
límites, terminación exacta tar/gzip y SRI de los **bytes comprimidos originales**.

Los archivos publicados autenticados permiten **observar** sus ancestros exactos,
incluso directorios con forma de paquete, pero no demuestran propiedad instalada.
Esos límites conservan `ownership-ambiguous` aunque todos los bytes coincidan y
no haya manifiesto ni entrada lock: un paquete separado sin registrar puede tener
los mismos bytes. El subárbol ambiguo no se compara como propiedad del padre;
los cambios independientes fuera de él siguen detectándose. Propietarios explícitos
prevalecen; no se altera la calificación existente de bundles con evidencia literal
del lock. Límites más profundos, enlaces y lecturas ilegibles/inestables siguen
siendo negativos. Directorios publicados vacíos no habilitan el recorrido.

**Cambio compartido intencional:** también en `scan`, límites distintos usan
identidades opacas `:boundary:N`, en lugar de `:nested`/`:unmapped`, que podían
colapsarlos. No cambia la aceptación legacy de archivos ni las decisiones, pero
sí puede cambiar la representación pública y los ordinales portables. La prueba
diferencial contra el base local `8d60af6` cubre un propietario anidado y dos límites
desconocidos: conserva completitud, códigos de gaps y comparaciones; las tres
identidades de evidencia ahora son distintas, antes eran dos.

El piloto retenido contiene los 160 archivos originales verificados por SRI de
`node-js-getting-started`. El árbol se reconstruyó desde esas mismas referencias,
**no se instaló independientemente**; el pin se calculó para el experimento, no
procede de revisión independiente. Ni los controles ni el colector autentican al
editor ni demuestran igualdad frente a una instalación independiente.

Con la corrección conservadora completan 159 instancias; `resolve` (131) conserva
un gap de propiedad. Intacto y restaurado salen **3**, no 0. Cambiar Express o cada
una de las nueve instancias con archivos antes inutilizables produce una diferencia
positiva, pero sigue saliendo **3** por el límite de propiedad independiente.
Referencia ausente y caso mixto también salen **3**. Cambiar/eliminar contenido
bajo el límite ambiguo no inventa una comparación atribuida al padre. Los antiguos
0/1 corresponden a la implementación anterior que infería propiedad.

El replay offline reutilizable se ejecuta con el comando de la sección inglesa:
requiere la evidencia retenida (`owned-case/`, `owned.baseline.json`, `policy.pin`),
el ejecutable exacto y un directorio externo nuevo. Verifica los 160 SRI y el pin
existente sin regenerarlo; trabaja solo sobre copias. Guarda 17 controles reales,
argv, salidas, estados, hash del binario y snapshots antes/después; restaura su copia
y comprueba que el original no cambió. Incluye nueve mutaciones individuales y dos
sondas de propiedad ambigua. No usa red, npm/node, instalación, reempaquetado ni
código de paquetes; tampoco convierte el pin experimental en confianza independiente.

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
