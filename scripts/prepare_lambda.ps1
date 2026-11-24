$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$packageRoot = Join-Path $projectRoot 'build-lambda'

if ($packageRoot -ne (Join-Path $projectRoot 'build-lambda')) {
    throw 'Unexpected Lambda package path.'
}
if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $packageRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'backend'), (Join-Path $projectRoot 'database') -Destination $packageRoot -Recurse
uv pip install --target $packageRoot --python-platform x86_64-manylinux_2_17 --python-version 3.12 -r (Join-Path $projectRoot 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { throw 'Lambda dependency installation failed.' }
