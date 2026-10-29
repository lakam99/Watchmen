$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$resultFile = Join-Path (Get-Location) 'test-results/elevated-status.json'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator access was not granted.' }
    $testExitCode = 1
    $deadline = (Get-Date).AddMinutes(5)
    do {
        $collectorVersion = (Get-Item -LiteralPath native/bin/0.5.0/Watchmen.Agent.exe).LastWriteTimeUtc
        $ErrorActionPreference = 'Continue'
        & 'C:\Program Files\nodejs\node.exe' scripts/collector-smoke.cjs *> test-results/elevated-smoke.log
        $testExitCode = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($testExitCode -eq 0) { break }
        @{ complete = $false; exitCode = $testExitCode; waitingForRebuild = $true } | ConvertTo-Json | Set-Content -LiteralPath $resultFile
        while ((Get-Date) -lt $deadline -and (Get-Item -LiteralPath native/bin/0.5.0/Watchmen.Agent.exe).LastWriteTimeUtc -eq $collectorVersion) { Start-Sleep -Seconds 2 }
    } while ((Get-Date) -lt $deadline)
    @{ complete = $true; exitCode = $testExitCode } | ConvertTo-Json | Set-Content -LiteralPath $resultFile
} catch {
    @{ complete = $true; exitCode = 1; error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $resultFile
}

