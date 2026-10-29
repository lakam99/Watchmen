$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$resultFile=Join-Path (Get-Location) 'test-results/elevated-firewall-status.json'
try {
    $deadline=(Get-Date).AddMinutes(10)
    do {
        $scriptStamp=(Get-Item -LiteralPath scripts/firewall-live-smoke.cjs).LastWriteTimeUtc
        $agentStamp=(Get-Item -LiteralPath native/bin/0.5.0/Watchmen.Agent.dll).LastWriteTimeUtc
        $ErrorActionPreference='Continue'
        & 'C:\Program Files\nodejs\node.exe' scripts/firewall-live-smoke.cjs *> test-results/firewall-live-smoke.log
        $testExit=$LASTEXITCODE
        $ErrorActionPreference='Stop'
        if($testExit -eq 0){break}
        @{complete=$false;exitCode=$testExit;waitingForRebuild=$true}|ConvertTo-Json|Set-Content -LiteralPath $resultFile
        while((Get-Date) -lt $deadline -and (Get-Item -LiteralPath scripts/firewall-live-smoke.cjs).LastWriteTimeUtc -eq $scriptStamp -and (Get-Item -LiteralPath native/bin/0.5.0/Watchmen.Agent.dll).LastWriteTimeUtc -eq $agentStamp){Start-Sleep -Seconds 2}
    }while((Get-Date) -lt $deadline)
    @{complete=$true;exitCode=$testExit}|ConvertTo-Json|Set-Content -LiteralPath $resultFile
}catch{ @{complete=$true;exitCode=1;error=$_.Exception.Message}|ConvertTo-Json|Set-Content -LiteralPath $resultFile }

