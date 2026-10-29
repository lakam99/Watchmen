param([switch]$Elevated)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework
try {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        if($Elevated){throw 'Administrator access was not granted.'}
        Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Elevated') -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
        exit
    }
    $collector=Join-Path $PSScriptRoot 'resources\app.asar.unpacked\native\bin\__WATCHMEN_VERSION__\Watchmen.Agent.exe'
    if(-not (Test-Path -LiteralPath $collector)){throw 'Keep this recovery launcher with the complete Watchmen application folder.'}
    $reply=(& $collector --unblock-watchmen | Out-String | ConvertFrom-Json)
    if(-not $reply.ok){throw $reply.error}
    [void][System.Windows.MessageBox]::Show('All Watchmen network restrictions are off.','Watchmen recovery','OK','Information')
}catch{[void][System.Windows.MessageBox]::Show($_.Exception.Message,'Watchmen recovery','OK','Error');exit 1}
