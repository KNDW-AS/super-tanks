<#
 Super Tanks — developer / research install for Windows 11 (no Docker needed)
 Sets up Python 3.12, a virtual environment, the package with dev extras,
 runs the test suite and the ZEF red-team baseline.

 Usage (PowerShell, run as your normal user):
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\installer\windows\install-dev.ps1            # install + tests
   .\installer\windows\install-dev.ps1 -Ollama    # also install Ollama + local models
   .\installer\windows\install-dev.ps1 -SkipTests
 Or double-click installer\windows\install-dev.bat
#>
param(
  [switch]$Ollama,
  [switch]$SkipTests,
  [string]$Dir = ""
)
$ErrorActionPreference = "Stop"
function Say($m){ Write-Host "  $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "  [!!] $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Super Tanks — developer install (Windows 11)" -ForegroundColor White
Write-Host ""

# 1. winget
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Warn "winget not found. Install 'App Installer' from Microsoft Store, then rerun."; exit 1
}
Ok "winget found"

# 2. Git
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Say "Installing Git..."
  winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { Warn "winget could not install Git. Install it from https://git-scm.com and rerun."; exit 1 }
  $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
}
Ok ("Git: " + (git --version))

# 3. Python 3.12
$py = $null
foreach ($cand in @("py -3.12","py -3.11","py -3.10","python3.12","python")) {
  try {
    $v = & cmd /c "$cand -c ""import sys;print(sys.version_info[:2])""" 2>$null
    if ($v -match "\(3, (10|11|12)\)") { $py = $cand; break }
  } catch {}
}
if (-not $py) {
  Say "Installing Python 3.12..."
  winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { Warn "winget could not install Python 3.12. Install it from https://python.org (tick 'Add to PATH') and rerun."; exit 1 }
  $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
  $py = "py -3.12"
}
Ok ("Python: " + (& cmd /c "$py --version"))

# 4. Repo
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $here "..\..") -ErrorAction SilentlyContinue
if ($repoRoot -and (Test-Path (Join-Path $repoRoot "pyproject.toml"))) {
  $target = $repoRoot.Path
  Ok "Using this checkout: $target"
} else {
  if (-not $Dir) { $Dir = Join-Path $env:USERPROFILE "super-tanks" }
  if (Test-Path (Join-Path $Dir ".git")) { Say "Updating $Dir"; git -C $Dir pull --ff-only | Out-Null }
  else { Say "Cloning into $Dir"; git clone https://github.com/KNDW-AS/super-tanks.git $Dir | Out-Null }
  $target = $Dir
}
Set-Location $target

# 5. venv + package
if (-not (Test-Path ".venv")) { Say "Creating virtual environment"; & cmd /c "$py -m venv .venv" }
$venvPy = Join-Path $target ".venv\Scripts\python.exe"
& $venvPy -m pip install --upgrade pip --quiet
Say "Installing super-tanks with dev extras (this takes a few minutes the first time)"
& $venvPy -m pip install -e ".[dev]" --quiet
if ($LASTEXITCODE -ne 0) { Warn "pip install failed — see output above. Usually: wrong Python version (need 3.10–3.12) or no internet."; exit 1 }
Ok "Package installed"
Say "Environment check"
& $venvPy -m supertanks doctor

# 6. Tests
if (-not $SkipTests) {
  Say "Running unit tests (expect ~1,300 passed)"
  & $venvPy -m pytest -q --no-cov -p no:cacheprovider
  if ($LASTEXITCODE -ne 0) { Warn "Some tests FAILED. Do not continue on a red suite: copy the output above and send it to William (billyxp@gmail.com)." }
  else { Ok "All tests passed" }
  Say "ZEF red-team baseline (report only)"
  & $venvPy -m scripts.zef_baseline --tier local-dev --report-only
}

# 7. Ollama (optional)
if ($Ollama) {
  if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Say "Installing Ollama"
    winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
  }
  Say "Pulling local models (llama3.2:3b ~2 GB, nomic-embed-text ~0.3 GB)"
  ollama pull llama3.2:3b; ollama pull nomic-embed-text
  Ok "Ollama ready on http://localhost:11434"
}

Write-Host ""
Write-Host "  Done. Next steps:" -ForegroundColor White
Write-Host "    cd $target"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    python -m supertanks doctor              # environment check"
Write-Host "    python -m supertanks demo                # GO-Gate demo"
Write-Host "    python -m supertanks test                # tests"
Write-Host "    python -m scripts.zef_baseline --tier local-dev --report-only"
Write-Host "    code .                                   # read core\security, tests\security\redteam"
Write-Host ""
