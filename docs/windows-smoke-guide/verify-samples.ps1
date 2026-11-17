# Default: syntax only. -ExecuteFixture runs only owned fixture preparation.
# Never launches PackTrace. Compatible with Windows PowerShell 5.1.
param([switch]$ExecuteFixture)
$ErrorActionPreference = 'Stop'
$Directory = $PSScriptRoot
if (-not $Directory) { $Directory = (Get-Location).Path }
$Names = @('01-verificar.ps1','02-preparar.ps1','03-comprobar.ps1','04-json.ps1','05-entorno.ps1')
foreach ($Name in $Names) {
    $Source = [IO.File]::ReadAllText((Join-Path $Directory $Name))
    foreach ($Text in @($Source, ($Source -replace '[\r\n]+', ' '))) {
        $Tokens = $null
        $ParseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$Tokens, [ref]$ParseErrors)
        if ($ParseErrors.Count -ne 0) { throw "$Name : $($ParseErrors | Out-String)" }
    }
    "OK multiline + flattened: $Name"
}
$Broken = '$L = @{ lockfileVersion=3; packages=@{ ''''=@{ dependencies=@{ ''packtrace-fixture''=''1.0.0'' } } ''node_modules/packtrace-fixture''=@{ name=''packtrace-fixture''; version=''1.0.0'' } }}'
$Tokens = $null
$ParseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($Broken, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count -eq 0) { throw 'Broken baseline unexpectedly parsed.' }
'OK: issue #114 baseline rejected.'
if ($ExecuteFixture) {
    $Preparation = [IO.File]::ReadAllText((Join-Path $Directory '02-preparar.ps1'))
    $SavedAppData = $env:APPDATA
    $SavedLocalAppData = $env:LOCALAPPDATA
    $Owned = Join-Path ([IO.Path]::GetTempPath()) ('packtrace-guide-check-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Owned | Out-Null
    try {
        $env:LOCALAPPDATA = $Owned
        foreach ($Text in @($Preparation, ($Preparation -replace '[\r\n]+', ' '))) {
            & {
                . ([scriptblock]::Create($Text))
                $Manifest = Get-Content -LiteralPath (Join-Path $Project 'package.json') -Raw | ConvertFrom-Json
                $LockText = [IO.File]::ReadAllText((Join-Path $Project 'package-lock.json'))
                # PS 5.1 ConvertFrom-Json cannot represent an empty property name.
                # Rename only in the test's in-memory copy; never change fixture bytes.
                if ([regex]::Matches($LockText, '""\s*:').Count -ne 1) { throw 'Expected one empty root key.' }
                $Locked = ($LockText -replace '""\s*:', '"__fixture_root__":') | ConvertFrom-Json
                $Installed = Get-Content -LiteralPath (Join-Path $Modules 'package.json') -Raw | ConvertFrom-Json
                if ($Manifest.name -ne 'packtrace-fixture-root' -or $Manifest.version -ne '1.0.0' -or
                    $Manifest.private -ne $true -or $Manifest.packageManager -ne 'npm@9.9.4' -or
                    $Manifest.dependencies.'packtrace-fixture' -ne '1.0.0') { throw 'Manifest mismatch.' }
                if ($Locked.lockfileVersion -ne 3 -or @($Locked.packages.PSObject.Properties).Count -ne 2 -or
                    $Locked.packages.__fixture_root__.dependencies.'packtrace-fixture' -ne '1.0.0' -or
                    $Locked.packages.'node_modules/packtrace-fixture'.name -ne 'packtrace-fixture' -or
                    $Locked.packages.'node_modules/packtrace-fixture'.version -ne '1.0.0') { throw 'Lockfile mismatch.' }
                if ($Installed.name -ne 'packtrace-fixture' -or $Installed.version -ne '1.0.0') { throw 'Installed mismatch.' }
                if (Test-Path $State) { throw 'Expected absent advisory state.' }
                foreach ($File in @((Join-Path $Project 'package.json'), (Join-Path $Project 'package-lock.json'), (Join-Path $Modules 'package.json'))) {
                    $Bytes = [IO.File]::ReadAllBytes($File)
                    if ($Bytes.Length -gt 8192) { throw 'Fixture unexpectedly large.' }
                    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { throw 'Unexpected JSON BOM.' }
                }
                'OK fixture execution: manifest, lockfile, installed manifest, UTF-8 without BOM, absent state.'
            }
        }
    } finally {
        $env:APPDATA = $SavedAppData
        $env:LOCALAPPDATA = $SavedLocalAppData
    }
}
$PSVersionTable.PSVersion
