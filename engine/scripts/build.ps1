<#
.SYNOPSIS
  Build the Vanta engine (vanta-chromium.exe) on your own Windows PC (R8: no
  dependency on GitHub runners). Same layers and scripts as CI stages S1/S2.

.DESCRIPTION
  1. Clones ungoogled-chromium-windows at the tag in engine/upstream.lock and
     verifies every SHA (scripts/fetch_upstream.py).
  2. Downloads and hash-checks the Chromium tarball and the Windows toolchain
     downloads, prunes, applies ungoogled + windows + Vanta patches, domain
     substitution, rust toolchain, args.gn (+ flags.vanta.gn), gn gen --check
     (scripts/prepare.py).
  3. Unless -PrepareOnly: ninja chrome chromedriver, then out\Default holds
     vanta-chromium.exe.

  Needs: Visual Studio 2022+ with "Desktop development with C++", Windows SDK
  10.0.28000.0, Python 3.12, Git, 7-Zip. ~120 GB free disk, 16+ GB RAM.
  A full compile takes many hours.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File engine\scripts\build.ps1 -Work D:\vanta-build
#>
param(
  [string]$Work = "C:\vanta-build",
  [int]$Jobs = 0,
  [switch]$PrepareOnly,
  [switch]$NoGnCheck
)
$ErrorActionPreference = "Stop"
$Engine = Split-Path -Parent $PSScriptRoot
$Ucw = Join-Path $Work "ungoogled-chromium-windows"

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found: $hint" }
}
Need python "install Python 3.12 and add it to PATH"
Need git "install Git for Windows"
if (-not (Test-Path "${env:ProgramFiles}\7-Zip\7z.exe")) { throw "7-Zip not found (https://www.7-zip.org)" }
if (-not (Test-Path "${env:ProgramFiles(x86)}\Windows Kits\10\Include\10.0.28000.0")) {
  Write-Warning "Windows SDK 10.0.28000.0 not found; ungoogled-chromium-windows 156 expects it."
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null
python "$Engine\scripts\fetch_upstream.py" $Ucw
if ($LASTEXITCODE -ne 0) { throw "upstream pin check failed" }

python -m pip install --quiet httplib2==0.22.0 clang==21.1.7
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

$prep = @("$Engine\scripts\prepare.py", "--ucw", $Ucw,
          "--steps", "source,windeps,prune,patch,domsub,rust,args,gngen")
if ($NoGnCheck) { $prep += "--no-gn-check" }
python @prep
if ($LASTEXITCODE -ne 0) { throw "prepare failed" }

if ($PrepareOnly) { Write-Host "Prepared: $Ucw\build\src (out\Default generated)"; exit 0 }

$src = Join-Path $Ucw "build\src"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -products * -prerelease -latest -property installationPath
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$j = if ($Jobs -gt 0) { "-j $Jobs" } else { "" }
$cmd = "call `"$vcvars`" >nul && set DEPOT_TOOLS_WIN_TOOLCHAIN=0 && " +
       "third_party\ninja\ninja.exe $j -C out\Default chrome chromedriver"
Push-Location $src
try {
  if (-not (Test-Path "third_party\rust-toolchain\bin\bindgen.exe")) {
    # Same as build.py: bindgen is built locally before ninja.
    cmd.exe /c "call `"$vcvars`" >nul && set DEPOT_TOOLS_WIN_TOOLCHAIN=0 && python tools\rust\build_bindgen.py --skip-test"
    if ($LASTEXITCODE -ne 0) { throw "build_bindgen failed ($LASTEXITCODE)" }
  }
  cmd.exe /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "ninja failed ($LASTEXITCODE)" }
} finally { Pop-Location }
Write-Host "Built: $src\out\Default\vanta-chromium.exe"
