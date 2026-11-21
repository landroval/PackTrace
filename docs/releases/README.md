# Releases and versioning / Versiones

- **Current local candidate / candidato local actual, not published / sin publicar:**
  v0.3.0-alpha.1 — [English](v0.3.0-alpha.1.md) / [Español](v0.3.0-alpha.1.es.md); Linux amd64 only.
- **Historical published releases / releases publicados históricos:**
- [v0.2.0-alpha.2](v0.2.0-alpha.2.md): partial pnpm 9.x–12.x ranges and expanded owned layout evidence.
- [v0.2.0-alpha.1](v0.2.0-alpha.1.md): partial pnpm inventory and accumulated fixes.
- [v0.1.0-alpha.1](v0.1.0-alpha.1.md): first numbered experimental release.

## English

PackTrace versions describe an accumulated release, not each commit or lines of
code. Use SemVer-shaped `MAJOR.MINOR.PATCH` with explicit prerelease suffixes:

- **Patch:** compatible bug fixes in a released feature line.
- **Minor:** new capabilities; before 1.0, documented incompatible changes also
  use a minor increment. The 0.x interface remains unstable.
- **Major:** incompatible public-contract changes after 1.0.
- **alpha.N:** iterations toward the same unreleased version. For example, fixes
  within the 0.2.0 experimental cycle normally become `0.2.0-alpha.2`, not a new
  patch for every fix. Once 0.2.0 is stable, compatible fixes can become 0.2.1.

The first pnpm capability release was **0.2.0-alpha.1**. **0.2.0-alpha.2** groups
its broader stable9.x–12.x hint ranges, real layout evidence and stronger replay
checks within the same experimental cycle. The current **0.3.0-alpha.1** local
candidate groups the new Linux offline `verify-integrity` command and accumulated
CLI, inventory, reporting and evidence changes; it is not a wider beta or an
integrity-only distribution. Versions are not incremented per commit.
Prereleases do not imply production, native-platform or security qualification.
Current operational report schema **1.8** (published alpha.2: **1.7**) is separate and
changes only when its own contract requires it. Never rewrite a published tag or
silently migrate user policies. Release publication, protected-branch integration
and local binary installation are separately authorized operations.

## Español

La versión agrupa cambios de un release: no se incrementa por cada commit ni por
cantidad de líneas. **Patch** corresponde a correcciones compatibles; **minor** a
funciones nuevas y, antes de 1.0, también a incompatibilidades documentadas.
**Major** identifica rupturas de contrato después de 1.0. La interfaz 0.x sigue
siendo inestable.

**alpha.N** itera dentro del mismo ciclo: correcciones del ciclo experimental
0.2.0 normalmente producen `0.2.0-alpha.2`, no un patch por cada arreglo. Después
de 0.2.0 estable, una corrección compatible puede ser 0.2.1. La primera capacidad
pnpm llegó en **0.2.0-alpha.1**; **0.2.0-alpha.2** agrupa los rangos estables
9.x–12.x, las muestras reales de layouts y las pruebas reforzadas del mismo ciclo.
El candidato local actual **0.3.0-alpha.1** agrupa el nuevo comando Linux offline
`verify-integrity` y cambios acumulados de CLI, inventario, reportes y evidencia;
no es una beta ampliada ni una distribución exclusiva de integridad.

La etiqueta preliminar no garantiza producción, seguridad ni ejecución nativa.
El esquema operativo actual **1.8** (alpha.2 publicado: **1.7**) es independiente. No se reescriben tags publicados
ni se migran políticas automáticamente. Publicar, integrar en la rama protegida
e instalar el binario local requieren autorizaciones separadas.
