$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$resultFile=Join-Path (Get-Location) 'test-results/elevated-packet-status.json'
try {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator access was not granted.'}
    $deadline=(Get-Date).AddMinutes(5)
    do {
        $version=(Get-Item -LiteralPath electron/packets.cjs).LastWriteTimeUtc
        $decoderVersion=(Get-Item -LiteralPath electron/packet-decode.cjs).LastWriteTimeUtc
        $ErrorActionPreference='Continue'
        & 'C:\Program Files\nodejs\node.exe' scripts/packet-live-smoke.cjs *> test-results/elevated-packet-smoke.log
        $testExitCode=$LASTEXITCODE
        $ErrorActionPreference='Stop'
        if($testExitCode -eq 0){break}
        @{complete=$false;exitCode=$testExitCode;waitingForRebuild=$true}|ConvertTo-Json|Set-Content -LiteralPath $resultFile
        while((Get-Date) -lt $deadline -and (Get-Item -LiteralPath electron/packets.cjs).LastWriteTimeUtc -eq $version -and (Get-Item -LiteralPath electron/packet-decode.cjs).LastWriteTimeUtc -eq $decoderVersion){Start-Sleep -Seconds 2}
    }while((Get-Date) -lt $deadline)
    @{complete=$true;exitCode=$testExitCode}|ConvertTo-Json|Set-Content -LiteralPath $resultFile
}catch{ @{complete=$true;exitCode=1;error=$_.Exception.Message}|ConvertTo-Json|Set-Content -LiteralPath $resultFile }
