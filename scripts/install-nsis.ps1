[CmdletBinding()]
param(
    [string]$Version = "3.12",
    [string]$Sha256 = "3bc2b06253a7e4957111be152ac6a536e0c7478a706e19da814038db5d706495"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "RUNNER_TEMP is required to install NSIS."
}

$installDir = Join-Path $env:RUNNER_TEMP "nsis-$Version"
$makensis = Join-Path $installDir "makensis.exe"
if (Test-Path -LiteralPath $makensis) {
    Write-Output $makensis
    exit 0
}

$installer = Join-Path $env:RUNNER_TEMP "nsis-$Version-setup.exe"
$url = "https://downloads.sourceforge.net/project/nsis/NSIS%203/$Version/nsis-$Version-setup.exe"

& curl.exe --fail --location --silent --show-error --retry 3 `
    --output $installer $url
if ($LASTEXITCODE -ne 0) {
    throw "Failed to download NSIS $Version from its official SourceForge release."
}

$actualSha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $Sha256.ToLowerInvariant()) {
    throw "NSIS installer checksum verification failed."
}

$process = Start-Process -FilePath $installer -ArgumentList @(
    "/S",
    "/D=$installDir"
) -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "NSIS installer exited with code $($process.ExitCode)."
}
if (-not (Test-Path -LiteralPath $makensis)) {
    throw "NSIS compiler was not installed at $makensis"
}

Write-Output $makensis
