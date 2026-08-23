param(
    [ValidateSet('arm64', 'x64')]
    [string] $Architecture = 'arm64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$release = Join-Path $root "target\$target\release"
$dist = Join-Path $root "dist\windows\$Architecture"

Push-Location $root
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE) { throw "cargo fmt failed: $LASTEXITCODE" }
    cargo build --locked --all-features --release --target $target --lib
    if ($LASTEXITCODE) { throw "VCore Windows DLL build failed: $LASTEXITCODE" }
    cargo build --locked --all-features --release --target $target --bin vcore-windows-vpn-host
    if ($LASTEXITCODE) { throw "VCore Windows provider host build failed: $LASTEXITCODE" }
    cargo build --locked --all-features --release --target $target --bin vcore-windows-session-host
    if ($LASTEXITCODE) { throw "VCore Windows session host build failed: $LASTEXITCODE" }

    Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $dist -ItemType Directory | Out-Null
    Copy-Item (Join-Path $release 'vcore.dll') $dist
    Copy-Item (Join-Path $release 'vcore-windows-vpn-host.exe') $dist
    Copy-Item (Join-Path $release 'vcore-windows-session-host.exe') $dist
    Get-FileHash (Join-Path $dist 'vcore.dll'), (Join-Path $dist 'vcore-windows-vpn-host.exe'), (Join-Path $dist 'vcore-windows-session-host.exe') -Algorithm SHA256 |
        Format-Table Path, Hash -AutoSize
} finally {
    Pop-Location
}
