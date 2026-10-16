$ErrorActionPreference = 'Stop'
$exe = Join-Path (Get-Location) 'dist\CEOAI-Juwet.exe'
if (-not (Test-Path $exe)) { throw "EXE not found: $exe" }

$data = Join-Path $env:RUNNER_TEMP 'CEOAI-Juwet-exe-smoke-data'
if (Test-Path $data) { Remove-Item -LiteralPath $data -Recurse -Force }
$env:PROXY_PORT = '18080'
$env:DASHBOARD_PORT = '18787'
$env:CEOAI_DATA_DIR = $data
$env:CEOAI_OPEN_BROWSER = '0'
$proc = $null
try {
  $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
  $status = $null
  for ($i = 0; $i -lt 50; $i++) {
    if ($proc.HasExited) { throw "Packaged EXE exited early with code $($proc.ExitCode)" }
    try {
      $status = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:18787/api/status' -TimeoutSec 2
      if ($status.ok) { break }
    } catch {}
    Start-Sleep -Milliseconds 250
  }
  if (-not $status -or -not $status.ok) { throw 'Packaged EXE dashboard did not become ready' }
  if ($status.proxyPort -ne 18080) { throw "Unexpected proxy port: $($status.proxyPort)" }

  $page = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:18787/' -TimeoutSec 5
  if ($page.StatusCode -ne 200 -or $page.Content -notmatch 'CEOAI Juwet') { throw 'Packaged dashboard HTML failed' }
  $logo = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:18787/logo.svg' -TimeoutSec 5
  if ($logo.StatusCode -ne 200 -or $logo.Content -notmatch '<svg') { throw 'Packaged logo asset failed to load' }

  $client = [System.Net.Sockets.TcpClient]::new()
  try {
    $connect = $client.BeginConnect('127.0.0.1', 18080, $null, $null)
    if (-not $connect.AsyncWaitHandle.WaitOne(3000)) { throw 'Proxy port did not accept connections' }
    $client.EndConnect($connect)
  } finally { $client.Dispose() }

  # Exercise real cache paths inside the packaged Windows EXE, not only its listener.
  $env:CEOAI_TEST_EXECUTABLE = $exe
  node tests/integration.js
  if ($LASTEXITCODE -ne 0) { throw 'Packaged EXE HTTP cache integration failed' }
  node tests/tls-integration.js
  if ($LASTEXITCODE -ne 0) { throw 'Packaged EXE HTTPS TLS-inspection/cache integration failed' }
  Remove-Item Env:CEOAI_TEST_EXECUTABLE -ErrorAction SilentlyContinue

  Write-Host 'Packaged EXE verified: dashboard, HTTP MISS/HIT, HTTPS TLS-inspection MISS/HIT, upstream request counts, and CA recovery.'
} finally {
  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force
    $proc.WaitForExit()
  }
  if (Test-Path $data) { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }
}
