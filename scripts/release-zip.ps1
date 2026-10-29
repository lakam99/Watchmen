param([Parameter(Mandatory=$true)][string]$ApplicationFolder,[Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
$applicationPath=(Resolve-Path -LiteralPath $ApplicationFolder).Path
$destinationPath=[IO.Path]::GetFullPath($Destination)
if((Split-Path -Leaf $applicationPath) -ne 'Watchmen-win32-x64' -or (Split-Path -Parent $applicationPath) -ne (Split-Path -Parent $destinationPath)){throw 'The release archive must stay beside its versioned application folder.'}
Compress-Archive -LiteralPath $applicationPath -DestinationPath $destinationPath -CompressionLevel Optimal -Force
