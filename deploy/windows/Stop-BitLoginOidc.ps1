$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$pidFile = Join-Path (Join-Path $root 'data') 'bit-login-oidc.pid'
if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Output 'No BIT Login OIDC PID file is present.'
    exit 0
}

$processId = 0
if (-not [int]::TryParse((Get-Content -LiteralPath $pidFile -Raw).Trim(), [ref]$processId)) {
    throw 'The BIT Login OIDC PID file is invalid.'
}
$process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
if ($process) {
    $java = [System.IO.Path]::GetFullPath((Join-Path $root 'runtime\bin\java.exe'))
    $actual = [System.IO.Path]::GetFullPath($process.ExecutablePath)
    if (-not [string]::Equals($java, $actual, [System.StringComparison]::OrdinalIgnoreCase) -or
        $process.CommandLine -notlike '*cn.bit101.bitlogin.server.ApplicationKt*') {
        throw 'The PID no longer belongs to BIT Login OIDC; refusing to stop another process.'
    }
    Stop-Process -Id $processId
    Wait-Process -Id $processId -Timeout 15 -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $pidFile -Force
Write-Output 'BIT Login OIDC stopped.'
