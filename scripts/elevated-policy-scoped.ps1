$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$statusFile='test-results/elevated-policy-scoped-status-v0.6.0.json'
$testMutex=$null
$held=$false
try {
    # Share the production mutation mutex, but operate only on the native test sublayer.
    $testMutex=New-Object System.Threading.Mutex($false,'Global\Watchmen.NetworkRules.v1')
    $deadline=(Get-Date).AddMinutes(15)
    $lastReport=[DateTime]::MinValue
    do {
        try {$held=$testMutex.WaitOne(500)} catch [System.Threading.AbandonedMutexException] {$held=$true}
        if(-not $held -and ((Get-Date)-$lastReport).TotalSeconds -ge 5){
            @{complete=$false;stage='waiting-for-active-rule-change';updatedAt=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $statusFile
            $lastReport=Get-Date
        }
    } while(-not $held -and (Get-Date) -lt $deadline)
    if(-not $held){throw 'The active Watchmen rule change did not finish within 15 minutes. The scoped retry was not started.'}
    @{complete=$false;stage='running-scoped-test';updatedAt=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $statusFile
    & 'C:\Program Files\nodejs\node.exe' scripts/policy-scoped-smoke.cjs *> test-results/policy-scoped-smoke-v0.6.0.log
    @{complete=$true;exitCode=$LASTEXITCODE;updatedAt=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $statusFile
} catch {
    @{complete=$true;exitCode=1;error=$_.Exception.Message;updatedAt=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $statusFile
} finally {
    if($held){$testMutex.ReleaseMutex()}
    if($null -ne $testMutex){$testMutex.Dispose()}
}
