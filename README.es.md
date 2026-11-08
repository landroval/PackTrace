# PackTrace

**Investiga las dependencias de JavaScript sin ejecutar el proyecto.**

[English](README.md) · [Manual completo en español](docs/user-guide.es.md) · [English manual](docs/user-guide.md)

PackTrace es una CLI de investigación de solo lectura y análisis sin conexión.
Ayuda a responder:

1. **¿Qué dependencia necesita atención?** Paquete y versión observada.
2. **¿Por qué?** Un aviso de paquete malicioso, una vulnerabilidad o una diferencia en archivos instalados.
3. **¿Qué evidencia existe?** Lockfile, manifiesto instalado, aviso y referencia se mantienen separados.
4. **¿Qué revisar después?** Aplicabilidad, evidencia ausente o un límite de corrección registrado por el aviso.

> **Software experimental, no una versión cualificada para producción.** No hay
> paquetes de instalación publicados ni garantías generales de plataforma. macOS
> sigue aplazado. Cero hallazgos nunca significa que el proyecto o el equipo sean seguros.

## Empieza aquí

Si no sabes qué comando necesitas, `packtrace --help` empieza por tareas:
**Scan a project (offline)** —analizar—, **Prepare security advisory data**
—preparar avisos— y **Understand a result** —interpretar—. La lista avanzada viene
después. No se inicia un asistente ni una preparación automática.

**¿Ya está configurado?** El comando habitual es:

```bash
packtrace scan /ruta/al/proyecto
```

**¿Es la primera vez?** Compila el binario, prepara u obtén un almacén de inteligencia
y registra una política externa una vez. Sigue el [recorrido inicial](docs/user-guide.es.md#3-primera-configuración).
`setup` no instala el programa, no redacta políticas y no descarga datos. Cuando
esas fuentes externas estén preparadas y revisadas:

```bash
packtrace setup --policy /operator/config/policy.json --state-dir /operator/state/intelligence
packtrace scan /ruta/al/proyecto
```

Desde una copia del repositorio **fuera del proyecto que investigarás**, con una
versión de Go ya instalada compatible con `go.mod` —actualmente Go 1.27.1—:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go build -o ./packtrace ./cmd/packtrace
./packtrace --help
```

Instala o mueve ese binario a un directorio de tu `PATH` según tu sistema operativo.
No lo instales como dependencia del proyecto JavaScript investigado. Los ejemplos
públicos usan Bash; el manual incluye ejemplos de estado de salida en Nushell.

## Comandos habituales

| Tarea | Comando |
| --- | --- |
| Análisis legible | `packtrace scan .` |
| Decisiones técnicas completas | `packtrace scan --verbose .` |
| Evidencia estructurada local, con configuración local guardada | `packtrace scan --format json .` |
| JSON portátil para revisar antes de compartir | `packtrace scan --privacy portable --format json .` |
| SARIF | `packtrace scan --format sarif .` |
| Opciones del análisis | `packtrace scan --help` |
| Opciones de configuración inicial | `packtrace setup --help` |

Las opciones van **antes** de la ruta final. El análisis nunca descarga avisos,
instala dependencias, ejecuta scripts de paquetes ni repara el proyecto.
Los comandos y las etiquetas de la CLI permanecen en inglés.

Las operaciones largas `intel sync`, `intel import` e `intel export` muestran
un spinner pequeño de una sola línea en terminales Linux compatibles. Es automático:
no hay modo interactivo ni argumento adicional. Indica actividad, no porcentaje
ni garantía de éxito. Tuberías, JSON, `NO_COLOR` y terminales pequeñas/no admitidas
conservan salida plana.

## Entiende el resultado

La CLI explica conceptos y evidencia ausente, no solo estados técnicos:
**Effect** indica qué consecuencia tiene una limitación; **Next**, una acción acotada.
Los errores frecuentes mantienen su código original en la primera línea.
Los comandos sugeridos no se ejecutan solos. `DIR` es un marcador que debes
sustituir por el mismo almacén externo revisado, no por la ruta del proyecto.

- **Finding / hallazgo:** la evidencia cumple las reglas seleccionadas. No demuestra ejecución de código.
- **Candidate / `[REVIEW]`:** coincidencia de identidad y versión que merece revisión;
  su origen o aplicabilidad siguen sin confirmar. **No** es una vulnerabilidad
  confirmada ni un hallazgo que pueda activar enforcement.
- **`[INCOMPLETE]`:** falta algo necesario para completar la comprobación.
  No significa que otro paquete sea malicioso.
- **`[NOT RUN]`:** no se realizó esa comprobación opcional. No ha aprobado.
- **`[OK]`:** se completó esa comprobación concreta, no «el proyecto es seguro».

La vista habitual muestra tablas agrupadas y hasta cinco ejemplos atribuidos al
aviso: **Advisory says** —qué dice—, **Why** —por qué coincide— y **Next** —qué
verificar—. No están ordenados por severidad. `--verbose` y el JSON local conservan
todos los detalles capturados. Descripción, severidad y corrección desconocidas
siguen siendo desconocidas. Un límite `fixed` no garantiza que actualizar a esa
versión resuelva todos los problemas.

**Separa las limitaciones del proyecto de las garantías de la herramienta.**
Manifiestos ilegibles o inteligencia caducada limitan el análisis del proyecto.
La cualificación de plataforma y la evidencia pendiente del ciclo final pertenecen
a PackTrace. El informe separa **Project checks** —comprobaciones del proyecto— de
**PackTrace validation (tool assurance, not project defects)** —garantías de la
herramienta, no defectos del proyecto—. Ambas influyen en cobertura y código de salida.
Varias líneas incompletas pueden describir una misma falta de
evidencia, no fallos independientes de dependencias.

«23 advisory records» no significa severidad 23, 23 incidentes ni 23 vulnerabilidades
confirmadas. Consulta [cómo leer el informe](docs/user-guide.es.md#5-lee-el-informe-sin-confundir-cantidades-con-riesgo).

## ¿Qué se admite?

| Entrada | Interpretación acotada actual |
| --- | --- |
| npm 10.x / 11.x | Versiones estables, lockfile v2/v3; prioridad de shrinkwrap |
| npm 12.x | Versiones estables, solo lockfile v3; ignora shrinkwrap y no recurre a él |
| Bun 1.3.x | `bun.lock` de texto v0/v1; configuración ausente/0/1 |
| Perfiles anteriores explícitos | npm 8.19.4; Bun 1.4.2 |
| Workspaces | Miembros relativos explícitos y patrones acotados de un nivel; la propiedad ambigua sigue siendo una limitación |

Se interpreta el formato: **no** se garantiza cada productor, distribución,
sistema de archivos o plataforma. Los locks binarios de Bun, lockfile v4 de npm,
versiones preliminares o desconocidas, enlaces inseguros y distribuciones no
admitidas generan limitaciones explícitas. El perfil opcional de caché Bun en
Linux solo admite un par verificado de **exactamente dos nombres** para el
hardlink del manifiesto; tres o más siguen siendo ilegibles.

[Evidencia de inventario](docs/inventory-compatibility.md) · [Evidencia de inteligencia](docs/intelligence-compatibility.md) · [Requisitos de publicación](docs/pre-1.0-features.md)

## Privacidad y códigos de salida

Sin configuración guardada, la salida es **portable**, sin permisos de origen,
candidatos o referencias. Una configuración registrada explícitamente usa detalle
**local** por defecto, salvo otra elección; la política puede exigir portable.
Detalle local no equivale a permiso para subir el informe. Revísalo antes de compartirlo.

| Código | Significado |
| --- | --- |
| `0` | Completado según la política; no certifica seguridad |
| `1` | Un hallazgo no aceptado activa la política de enforcement |
| `2` | Fallaron argumentos, política, operación, informe o salida |
| `3` | Cobertura requerida incompleta; puede existir un informe parcial útil |
| `130` | Interrumpido |

Prioridad: interrupción → error operativo/de salida → cobertura incompleta →
hallazgo exigible → éxito. Report-only **no** convierte una cobertura incompleta en `0`.

## Preparación de inteligencia

**Intel es la base de avisos de seguridad, no inteligencia artificial:** informes
locales sobre paquetes maliciosos y vulnerabilidades. `intel status` explica
cantidades de avisos, vigencia de comprobación/reconciliación y evidencia sin
resolver; no son cantidades de paquetes instalados ni vulnerabilidades confirmadas.
Que las fechas sean actuales no significa cobertura completa.

El análisis es offline. Preparar inteligencia es una acción separada del operador:
`intel sync` usa la red; importación, exportación, estado, retención y poda operan
sobre datos locales. Ni `scan` ni `setup` los inicializan o actualizan.
Los valores guardados para análisis no se aplican al mantenimiento: indica el
mismo `--state-dir` expresamente. Consulta [preparación y mantenimiento](docs/user-guide.es.md#4-prepara-y-mantén-la-inteligencia).

## Desarrollo local

El módulo Go principal solo usa la biblioteca estándar. Con el toolchain requerido
ya instalado, desde este repositorio, no desde el proyecto investigado:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off GOTELEMETRY=off
export GOMAXPROCS=2
go test -p=1 -parallel=4 -count=1 -timeout=180s ./...
go vet ./...
```

Comprueba la salida de cada comando. Estas variables no son un sandbox de red.
Las pruebas usan fixtures propios; los módulos de `probes/`, la ejecución de
productores, los proyectos reales, las descargas y la cualificación nativa tienen
alcances independientes.

## Contribuir y documentación técnica

- [Manual en español](docs/user-guide.es.md) / [English manual](docs/user-guide.md): primer uso, comandos, políticas, informes y problemas comunes.
- [Decisiones de diseño](docs/design-decisions.md) y [guía de desarrollo](docs/development-guidelines.md): contratos de ingeniería y seguridad.
- [Colaboración en GitHub](docs/github-collaboration.md): coordinación, cambios acotados con `jj` y revisión de PR.
- [Incrementos](docs/increments/) y [registros compartidos](.pi/README.md): evidencia histórica, no permiso vigente para ejecutar acciones.
- [Licencias y atribución de datos](internal/intelstore/licenses/README.md): avisos de fuentes, no licencia general sobre todos los editores.

Un análisis exitoso o un PR fusionado no implica remediación automática, ejecución
del proyecto, descubrimiento de credenciales, seguridad del equipo ni cualificación
para producción.
