# Releases and versioning / Versiones

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

New pnpm capability makes this release **0.2.0-alpha.1**; smaller safety and
correctness fixes are included in its notes. Prereleases do not imply production,
native-platform or security qualification. Report schema **1.7** is separate and
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
de 0.2.0 estable, una corrección compatible puede ser 0.2.1. PNPM justifica ahora
**0.2.0-alpha.1**, junto con las correcciones pequeñas acumuladas.

La etiqueta preliminar no garantiza producción, seguridad ni ejecución nativa.
El esquema de reportes **1.7** es independiente. No se reescriben tags publicados
ni se migran políticas automáticamente. Publicar, integrar en la rama protegida
e instalar el binario local requieren autorizaciones separadas.
