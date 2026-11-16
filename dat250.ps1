param(
  [Parameter(Position = 0)]
  [string]$Command
)

Set-Location $PSScriptRoot

# Self-signed certificate for local HTTPS; the key stays out of git (nginx/certs/ is ignored).
function Ensure-Certs {
  $certDir = "nginx/certs"
  if ((Test-Path "$certDir/server.crt") -and (Test-Path "$certDir/server.key")) { return }
  New-Item -ItemType Directory -Force $certDir | Out-Null

  $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
  if (-not $openssl) {
    foreach ($candidate in @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe")) {
      if (Test-Path $candidate) { $openssl = $candidate; break }
    }
  }
  if (-not $openssl) {
    throw "openssl not found. Install Git for Windows or OpenSSL, or run ./dat250.sh from Git Bash."
  }

  Write-Host "Generating self-signed TLS certificate in $certDir ..."
  & $openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 `
    -keyout "$certDir/server.key" -out "$certDir/server.crt" `
    -subj "/CN=localhost" `
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  if ($LASTEXITCODE -ne 0) { throw "Certificate generation failed." }
}

switch ($Command) {
  "start" {
    Ensure-Certs
    docker compose up --build
  }
  "stop" {
    docker compose down
  }
  "reset" {
    docker compose down -v
    Ensure-Certs
    docker compose up --build
  }
  "rebuild" {
    Ensure-Certs
    docker compose pull --ignore-pull-failures
    docker compose build --no-cache
    docker compose up -d --force-recreate --remove-orphans
    Write-Host "Stack running in the background: https://localhost:18443"
  }
  "logs" {
    docker compose logs -f
  }
  default {
    Write-Host "Usage: .\dat250.ps1 {start|stop|reset|rebuild|logs}"
    Write-Host "  start   - foreground: compose up --build"
    Write-Host "  stop    - compose down"
    Write-Host "  reset   - remove volumes (fresh DB), then up --build (foreground)"
    Write-Host "  rebuild - pull bases, rebuild backend (--no-cache), recreate containers (-d)"
    Write-Host "  logs    - follow compose logs"
    exit 1
  }
}
