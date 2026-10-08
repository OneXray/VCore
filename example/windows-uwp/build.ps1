param(
    [string] $IdentityName = 'Vole.UwpDemo.Dev',
    [Parameter(Mandatory = $true)]
    [string] $Publisher,
    [string] $Version = '1.0.0.0',
    [Parameter(Mandatory = $true)]
    [string] $PfxPath,
    [Parameter(Mandatory = $true)]
    [string] $PfxPassword,
    [switch] $SkipVoleBuild,
    [switch] $Install
)

$ErrorActionPreference = 'Stop'
$example = $PSScriptRoot
$root = Split-Path (Split-Path $example -Parent) -Parent
$nativeArchitecture = (Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
    -Name PROCESSOR_ARCHITECTURE).PROCESSOR_ARCHITECTURE.ToLowerInvariant()
$Architecture = if ($nativeArchitecture -eq 'amd64') { 'x64' } else { $nativeArchitecture }
if ($Architecture -notin @('arm64', 'x64')) {
    throw "unsupported native Windows processor architecture: $nativeArchitecture"
}
if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    throw 'Version must contain four numeric components'
}
if (($Version.Split('.') | ForEach-Object { [int] $_ }) | Where-Object { $_ -gt 65535 }) {
    throw 'each Version component must fit 0..65535'
}
if (-not (Test-Path $PfxPath -PathType Leaf)) {
    throw "signing certificate not found: $PfxPath"
}
$PfxPath = (Resolve-Path $PfxPath).Path

$voleDist = Join-Path $root "dist\windows\$Architecture\uwp"
$importLibrary = Join-Path $voleDist 'vole.dll.lib'
$build = Join-Path $root "target\windows-uwp-demo\$Architecture"
$stage = Join-Path $build 'stage'
$packageDir = Join-Path $root 'dist\windows-uwp-demo'

Push-Location $root
try {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Auxiliary\Build\vcvarsall.bat' |
        Select-Object -First 1
    if (-not $vcvars) { throw 'Visual Studio C++ tools were not found' }
    $vcTarget = if ($Architecture -eq 'arm64') { 'amd64_arm64' } else { 'amd64' }

    if (-not $SkipVoleBuild) {
        & uv run --project (Join-Path $root 'scripts') --locked vole-scripts build windows --backend uwp
        if ($LASTEXITCODE) { throw "Vole build failed: $LASTEXITCODE" }
    }
    foreach ($artifact in @('vole.dll', 'vole-windows-vpn-host.exe', 'vole-windows-session-host.exe')) {
        if (-not (Test-Path (Join-Path $voleDist $artifact) -PathType Leaf)) {
            throw "missing Vole artifact: $artifact"
        }
    }
    if (-not (Test-Path $importLibrary -PathType Leaf)) {
        throw "missing Vole import library: $importLibrary"
    }

    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $stage, (Join-Path $stage 'Assets'), $packageDir -ItemType Directory -Force | Out-Null
    $demoExe = Join-Path $stage 'VoleUwpDemo.exe'
    $compile = 'call "{0}" {1} >nul && cl.exe /nologo /std:c++20 /EHsc /O2 /MT /utf-8 /Fo"{2}" "{3}" /I"{4}" /link /out:"{5}" "{6}"' -f `
        $vcvars, $vcTarget, (Join-Path $build 'demo.obj'), (Join-Path $example 'demo.cpp'), (Join-Path $root 'include'), $demoExe, $importLibrary
    & $env:ComSpec /d /s /c $compile
    if ($LASTEXITCODE) { throw "demo compile failed: $LASTEXITCODE" }

    Copy-Item (Join-Path $voleDist 'vole.dll'), `
        (Join-Path $voleDist 'vole-windows-vpn-host.exe'), `
        (Join-Path $voleDist 'vole-windows-session-host.exe') $stage

    $logo = 'iVBORw0KGgoAAAANSUhEUgAAAJYAAACWCAYAAAA8AXHiAAABIklEQVR42u3SMQ0AAAjAMAThDO1oAAOcnD1qYFlk9cC3EAFjYSwwFsbCWGAsjIWxwFgYC2OBsTAWxgJjYSyMBcbCWBgLjIWxMBYYC2NhLDAWxsJYYCyMhbHAWBgLY4GxMBbGAmNhLIwFxsJYGAuMhbEwFhgLY2EsMBbGwlhgLIyFscBYGAtjgbEwFsYCY2EsjAXGwlgYC4yFsTAWGAtjYSwwFsbCWBhLBIyFsTAWGAtjYSwwFsbCWGAsjIWxwFgYC2OBsTAWxgJjYSyMBcbCWBgLjIWxMBYYC2NhLDAWxsJYYCyMhbHAWBgLY4GxMBbGAmNhLIwFxsJYGAuMhbEwFhgLY2EsMBbGwlhgLIyFseC2BofOkWDAMyEAAAAASUVORK5CYII='
    [IO.File]::WriteAllBytes((Join-Path $stage 'Assets\Logo.png'), [Convert]::FromBase64String($logo))

    $manifest = Get-Content (Join-Path $example 'AppxManifest.xml.in') -Raw
    $manifest = $manifest.Replace('__IDENTITY_NAME__', [Security.SecurityElement]::Escape($IdentityName))
    $manifest = $manifest.Replace('__PUBLISHER__', [Security.SecurityElement]::Escape($Publisher))
    $manifest = $manifest.Replace('__VERSION__', $Version)
    $manifest = $manifest.Replace('__ARCHITECTURE__', $Architecture)
    Set-Content (Join-Path $stage 'AppxManifest.xml') $manifest -Encoding utf8 -NoNewline

    $sdk = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\*\x64\makeappx.exe') |
        Sort-Object FullName -Descending |
        Select-Object -First 1 |
        Split-Path -Parent
    if (-not $sdk) { throw 'Windows SDK packaging tools were not found' }
    $package = Join-Path $packageDir "$($IdentityName)_$($Version)_$Architecture.msix"
    Remove-Item $package -Force -ErrorAction SilentlyContinue
    & (Join-Path $sdk 'makeappx.exe') pack /d $stage /p $package /o
    if ($LASTEXITCODE) { throw "makeappx failed: $LASTEXITCODE" }
    & (Join-Path $sdk 'signtool.exe') sign /fd SHA256 /f $PfxPath /p $PfxPassword $package
    if ($LASTEXITCODE) { throw "signtool failed: $LASTEXITCODE" }

    if ($Install) {
        if (Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue) {
            throw 'disconnect the active VPN before installing or updating the demo'
        }
        $installed = Get-AppxPackage -Name $IdentityName
        if ($installed -and [version] $Version -le $installed.Version) {
            throw "increment Version above $($installed.Version) before updating $IdentityName"
        }
        Add-AppxPackage $package -ForceApplicationShutdown
    }
    Get-FileHash $package -Algorithm SHA256 | Format-Table Path, Hash -AutoSize
} finally {
    Pop-Location
}
