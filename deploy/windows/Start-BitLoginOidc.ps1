$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'oidc-settings.ps1')
$settings = $OidcSettings
if (-not $settings) { throw 'OIDC settings are missing.' }
$java = Join-Path $root 'runtime\bin\java.exe'
$classPath = Join-Path $root 'app\lib\*'
$data = Join-Path $root 'data'
$logs = Join-Path $root 'logs'
$pidFile = Join-Path $data 'bit-login-oidc.pid'

foreach ($path in @($java, (Join-Path $root 'app\lib\bit-login-server-4.0.0.jar'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required deployment file is missing: $path" }
}
New-Item -ItemType Directory -Force -Path $data, $logs | Out-Null

$listener = Get-NetTCPConnection -State Listen -LocalPort $settings.Port -ErrorAction SilentlyContinue
if ($listener) { throw "TCP port $($settings.Port) is already in use" }

$env:HOST = $settings.Host
$env:PORT = [string]$settings.Port
$env:IDENTITY_ONLY = 'true'
$env:AUTH_DB_PATH = Join-Path $data 'auth.db'
$env:OIDC_ISSUER = $settings.Issuer
$env:OIDC_CLIENT_ID = $settings.ClientId
$env:OIDC_REDIRECT_URIS = $settings.RedirectUris -join ','
$env:OIDC_SIGNING_KEY_FILE = Join-Path $data 'oidc-signing-key.pem'
$env:OIDC_ADMIN_STUDENT_IDS = @($settings.AdminStudentIds | Where-Object { $_ }) -join ','
$adminSessionTtl = $settings.AdminSessionTtlSeconds
if (-not $adminSessionTtl) { $adminSessionTtl = 1800 }
$env:OIDC_ADMIN_SESSION_TTL = [string]$adminSessionTtl
$env:OIDC_ADMIN_COOKIE_SECURE = if ($settings.AdminCookieSecure) { 'true' } else { 'false' }
$env:HTTP_CONNECT_TIMEOUT = '5'
$env:HTTP_READ_TIMEOUT = '25'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stdout = Join-Path $logs "stdout-$stamp.log"
$stderr = Join-Path $logs "stderr-$stamp.log"
$quotedClassPath = '"{0}"' -f $classPath
$process = Start-Process -FilePath $java -ArgumentList @('-cp', $quotedClassPath, 'cn.bit101.bitlogin.server.ApplicationKt') `
    -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
Start-Sleep -Seconds 3
if ($process.HasExited) {
    $detail = (Get-Content -LiteralPath $stderr -Tail 20 -ErrorAction SilentlyContinue) -join "`n"
    throw "BIT Login OIDC exited during startup. $detail"
}
[System.IO.File]::WriteAllText($pidFile, [string]$process.Id, [System.Text.Encoding]::ASCII)
Write-Output "BIT Login OIDC started (PID $($process.Id)) on $($settings.Host):$($settings.Port)."
