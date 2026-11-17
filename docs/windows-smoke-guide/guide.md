# PackTrace · Windows · 0.1.0-alpha.1

Guía de pruebas corregida · revisión 1 · issue #114

Fuente reconstruida a partir del PDF original. No es una nueva versión del binario ni una cualificación de Windows. El PDF original no se modifica. Esta guía conserva el ensayo de la alpha antigua: no sustituir el ZIP por otra versión manteniendo este hash.

## Prueba 01 / Empezar sin riesgos

Ensayo de 10–15 minutos con datos ficticios. Necesitas Windows 11 x64, PowerShell 5.1 o 7 y disco local NTFS. Evita OneDrive, carpetas de red y administrador. Si usas ARM/Snapdragon, indica que pruebas emulación. El resultado no certifica detección de amenazas ni soporte general.

Descarga packtrace_0.1.0-alpha.1_windows_amd64.zip exclusivamente desde https://github.com/landroval/PackTrace/releases/tag/v0.1.0-alpha.1 . Abre PowerShell normal en la carpeta del ZIP y conserva la misma consola durante todo el ensayo.

Los archivos .ps1 contienen exactamente los bloques de esta guía. Ábrelos como texto y pega su contenido completo; no cambies ExecutionPolicy para ejecutarlos. Si la política permite scripts locales, usa dot-sourcing: por ejemplo, . .\01-verificar.ps1 (punto, espacio, ruta). No uses una consola nueva ni powershell -File entre bloques: se perderían las variables. Si al pegar ves comandos unidos sin separadores, detente. El PDF no es un transporte fiable de código.

### Verificar antes de ejecutar · 01-verificar.ps1

```powershell
$ErrorActionPreference = 'Stop';
$PSNativeCommandUseErrorActionPreference = $false;
$Zip = '.\packtrace_0.1.0-alpha.1_windows_amd64.zip';
$Esperado = '81ab676295f1b9df982d6754a9faf040144fa0f9e0c5746e8c449b8a5a6bd0fd';
$Real = (Get-FileHash $Zip -Algorithm SHA256).Hash;
if ($Real -ne $Esperado) { throw 'Hash incorrecto: detente.' };
$Out = Join-Path (Get-Location) 'PackTrace-alpha-prueba';
if (Test-Path $Out) { throw 'Usa una carpeta nueva.' };
Expand-Archive -LiteralPath $Zip -DestinationPath $Out;
$Folder = 'packtrace_0.1.0-alpha.1_windows_amd64';
$Exe = Join-Path (Join-Path $Out $Folder) 'packtrace.exe';
& $Exe --version;
$LASTEXITCODE;
```

Esperado: packtrace 0.1.0-alpha.1 (experimental; not production-qualified), código 0. El hash comprueba bytes, no es una firma digital. Si SmartScreen o Defender bloquean algo, detente y conserva el aviso. No desactives protecciones, añadas exclusiones, cambies ExecutionPolicy ni ejecutes como administrador.

## Prueba 02 / Preparar el ensayo

### Solo datos ficticios · 02-preparar.ps1

En la misma consola. Crea una carpeta nueva en LocalAppData, sin tocar proyectos ni instalar paquetes. Los cambios de entorno solo afectan a esta sesión. Los separadores ; son explícitos, también dentro de las tablas $M y $L: no dependen de los saltos de línea.

```powershell
$StateSource = Join-Path $env:LOCALAPPDATA ('PackTrace-prueba-' + [Guid]::NewGuid().ToString('N'));
$Project = Join-Path $StateSource 'proyecto con espacios';
$Modules = Join-Path $Project 'node_modules\packtrace-fixture';
$Config = Join-Path $StateSource 'config-vacia';
if (Test-Path $StateSource) { throw 'La carpeta ya existe: detente.' };
New-Item -ItemType Directory -Path $StateSource | Out-Null;
New-Item -ItemType Directory -Path $Modules,$Config | Out-Null;
$env:APPDATA = $Config;
$State = Join-Path $StateSource 'sin-datos';
$Utf8 = [Text.UTF8Encoding]::new($false);
$M = @{
  name='packtrace-fixture-root'; version='1.0.0'; private=$true;
  packageManager='npm@9.9.4';
  dependencies=@{ 'packtrace-fixture'='1.0.0' };
};
$L = @{ lockfileVersion=3; packages=@{
  ''=@{ dependencies=@{ 'packtrace-fixture'='1.0.0' } };
  'node_modules/packtrace-fixture'=@{
    name='packtrace-fixture'; version='1.0.0';
  };
} };
$P = @{ name='packtrace-fixture'; version='1.0.0' };
[IO.File]::WriteAllText((Join-Path $Project 'package.json'), ($M | ConvertTo-Json -Depth 10), $Utf8);
[IO.File]::WriteAllText((Join-Path $Project 'package-lock.json'), ($L | ConvertTo-Json -Depth 10), $Utf8);
[IO.File]::WriteAllText((Join-Path $Modules 'package.json'), ($P | ConvertTo-Json -Depth 10), $Utf8);
$Scan = @('scan','--manager','npm@9.9.4','--checks','malicious','--state-dir',$State,'--privacy','portable');
```

No crees sin-datos: la ausencia de avisos es intencional. config-vacia aísla el setup anterior. Se escribe UTF-8 sin BOM. No ejecutes npm install, bun install, intel sync, setup ni cache prune. No hace falta red después de la descarga. No borres carpetas existentes ni uses -Force para repetir.

Respecto al original, la preparación usa una carpeta única, evita continuaciones con acento grave y hace explícita la profundidad JSON. No cambia los datos ficticios ni los resultados esperados del ensayo.

## Prueba 03 / Ejecutar y comparar

### Consola · 03-comprobar.ps1

```powershell
& $Exe --help;
$HelpExit = $LASTEXITCODE;
& $Exe demo --scenario candidate;
$DemoExit = $LASTEXITCODE;
& $Exe demo --scenario malformed;
$BadDemoExit = $LASTEXITCODE;
"help=$HelpExit; demo=$DemoExit; malformed=$BadDemoExit";
& $Exe @Scan $Project;
$ScanExit = $LASTEXITCODE;
"scan=$ScanExit";
```

Esperado: help=0; demo candidate=3 (cobertura incompleta); demo malformed=2 (error controlado); scan=3 (inventario visible y avisos ausentes). Un código 2 en scan, un bloqueo o un cierre inesperado se registran, no se esquivan. INCOMPLETE no significa malware. Se espera 1 dependencia declarada y 1 instancia instalada; el registro raíz puede sumar al contador locked.

### JSON portable · 04-json.ps1

```powershell
if ($ScanExit -ne 3) { throw 'Anota scan y su error: detente.' };
$Json = & $Exe @Scan --format json $Project;
$JsonExit = $LASTEXITCODE;
if ($JsonExit -ne 3) { throw 'Anota JSON y su error: detente.' };
$Text = $Json -join "`n";
$Text | ConvertFrom-Json | Out-Null;
$Report = Join-Path $StateSource 'resultado-portable.json';
[IO.File]::WriteAllText($Report, $Text, $Utf8);
"JSON=$JsonExit; archivo=$Report";
```

## Prueba 04 / Compartir el resultado

### Entorno · 05-entorno.ps1

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture;
Get-CimInstance Win32_Processor | Select-Object Name,Architecture;
$PSVersionTable.PSVersion;
```

CPU 9 = x64; 12 = ARM64. Indica Windows/build/CPU, PowerShell, terminal, VM o equipo físico, NTFS local, coincidencia del hash y versión. Envía los códigos help/demo/malformed/scan/JSON, si el JSON se parsea, legibilidad, cuelgues y errores completos. Revisa que lo compartido no incluya datos privados.

Si tarda más de 30 segundos, pulsa Ctrl+C y anota comando, duración y código. No fuerces permisos ni pruebes un proyecto real. Conserva la carpeta para revisar el informe. Al terminar, cierra la consola para descartar el entorno temporal. No se ha instalado nada en el sistema.

## Comprobación de los ejemplos

verify-samples.ps1 analiza la sintaxis de los cinco archivos, tanto multilínea como sin saltos, sin ejecutarlos ni lanzar PackTrace. Con -ExecuteFixture también ejecuta únicamente la preparación de datos ficticios (02-preparar.ps1) en una carpeta temporal nueva y comprueba el JSON generado en ambos formatos; restaura las variables de entorno al terminar. Conserva esa carpeta temporal para inspección. Comprueba además que el ejemplo defectuoso del issue #114 es rechazado. Abre PowerShell 5.1 en la carpeta de los cinco archivos .ps1, abre verify-samples.ps1 como texto y pega su contenido para registrar esa comprobación. Esto no sustituye la ejecución manual del ensayo ni certifica el binario.

## Regenerar esta guía

Fuente y scripts de generación: docs/windows-smoke-guide/ en el repositorio. Con Python y ReportLab disponibles, ejecuta python render.py RUTA_NUEVA. La salida incluye PDF, fuente Markdown, cinco bloques .ps1 y verify-samples.ps1. El destino debe ser una carpeta inexistente. El generador no descarga ni ejecuta PowerShell, PackTrace o los ejemplos. La opción --scripts-only genera solo la fuente y los scripts con la biblioteca estándar, sin necesitar ReportLab.
