param(
    [ValidateSet('arm64', 'x64')]
    [string] $Architecture = 'arm64',
    [string] $IdentityName = 'VCore.UwpDemo.Dev',
    [string] $Publisher = 'CN=OneVCore Phase0',
    [string] $Version = '1.0.0.0',
    [string] $PfxPath,
    [string] $PfxPassword = 'onevcore-phase0',
    [switch] $SkipVCoreBuild,
    [switch] $Install
)

$ErrorActionPreference = 'Stop'
$example = $PSScriptRoot
$root = Split-Path (Split-Path $example -Parent) -Parent
if (-not $PfxPath) {
    $PfxPath = Join-Path (Split-Path $root -Parent) 'cert\OneVCore.Phase0.pfx'
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

$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$vcoreDist = Join-Path $root "dist\windows\$Architecture"
$importLibrary = Join-Path $root "target\$target\release\vcore.dll.lib"
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

    if (-not $SkipVCoreBuild) {
        & uv run --project (Join-Path $root 'scripts') --locked vcore-scripts build windows --architecture $Architecture
        if ($LASTEXITCODE) { throw "VCore build failed: $LASTEXITCODE" }
    }
    foreach ($artifact in @('vcore.dll', 'vcore-windows-vpn-host.exe', 'vcore-windows-session-host.exe')) {
        if (-not (Test-Path (Join-Path $vcoreDist $artifact) -PathType Leaf)) {
            throw "missing VCore artifact: $artifact"
        }
    }
    if (-not (Test-Path $importLibrary -PathType Leaf)) {
        throw "missing VCore import library: $importLibrary"
    }

    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $stage, (Join-Path $stage 'Assets'), $packageDir -ItemType Directory -Force | Out-Null
    $demoExe = Join-Path $stage 'VCoreUwpDemo.exe'
    $compile = 'call "{0}" {1} >nul && cl.exe /nologo /std:c++20 /EHsc /O2 /MT /utf-8 /Fo"{2}" "{3}" /I"{4}" /link /out:"{5}" "{6}"' -f `
        $vcvars, $vcTarget, (Join-Path $build 'demo.obj'), (Join-Path $example 'demo.cpp'), (Join-Path $root 'include'), $demoExe, $importLibrary
    & $env:ComSpec /d /s /c $compile
    if ($LASTEXITCODE) { throw "demo compile failed: $LASTEXITCODE" }

    Copy-Item (Join-Path $vcoreDist 'vcore.dll'), `
        (Join-Path $vcoreDist 'vcore-windows-vpn-host.exe'), `
        (Join-Path $vcoreDist 'vcore-windows-session-host.exe') $stage

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
