[CmdletBinding()]
param(
    [Parameter()]
    [string] $Version,

    [Parameter()]
    [string] $BinDir,

    [Parameter()]
    [string] $BaseUrl,

    [Parameter()]
    [string] $Repository
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The whodis PowerShell installer supports Windows only.'
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = if ([string]::IsNullOrWhiteSpace($env:WHODIS_VERSION)) { 'latest' } else { $env:WHODIS_VERSION }
}
if ([string]::IsNullOrWhiteSpace($BinDir)) {
    $BinDir = if ([string]::IsNullOrWhiteSpace($env:BINDIR)) {
        Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\whodis\bin'
    } else {
        $env:BINDIR
    }
}
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    $BaseUrl = $env:WHODIS_BASE_URL
}
if ([string]::IsNullOrWhiteSpace($Repository)) {
    $Repository = if ([string]::IsNullOrWhiteSpace($env:WHODIS_REPOSITORY)) { 'Alex9001/whodis' } else { $env:WHODIS_REPOSITORY }
}
$BinDir = [IO.Path]::GetFullPath($BinDir)

$processorArchitecture = if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}

$architecture = switch -Regex ($processorArchitecture) {
    '^(AMD64|x86_64)$' { 'amd64'; break }
    '^(ARM64|aarch64)$' { 'arm64'; break }
    default { throw "Unsupported Windows architecture: $processorArchitecture" }
}

$asset = "whodis_windows_${architecture}.zip"

if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    if ($Version -eq 'latest') {
        $BaseUrl = "https://github.com/$Repository/releases/latest/download"
    } else {
        $releaseTag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
        $BaseUrl = "https://github.com/$Repository/releases/download/$releaseTag"
    }
}
$BaseUrl = $BaseUrl -replace '[\\/]+$', ''

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("whodis-install-" + [Guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $tempDir $asset
$checksumsPath = Join-Path $tempDir 'checksums.txt'
$extractDir = Join-Path $tempDir 'extract'

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    $sourceUri = $null
    if ([Uri]::TryCreate($Source, [UriKind]::Absolute, [ref] $sourceUri)) {
        if ($sourceUri.IsFile) {
            Copy-Item -LiteralPath $sourceUri.LocalPath -Destination $Destination
        } else {
            Invoke-WebRequest -Uri $sourceUri -OutFile $Destination -UseBasicParsing
        }
        return
    }

    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Copy-Item -LiteralPath $Source -Destination $Destination
        return
    }

    Invoke-WebRequest -Uri $Source -OutFile $Destination -UseBasicParsing
}

function Test-PathEntry {
    param(
        [AllowEmptyString()]
        [string] $PathValue,

        [Parameter(Mandatory)]
        [string] $Entry
    )

    $normalizedEntry = $Entry -replace '[\\/]+$', ''
    foreach ($candidate in ($PathValue -split ';')) {
        $normalizedCandidate = $candidate.Trim() -replace '[\\/]+$', ''
        if ($normalizedCandidate -ieq $normalizedEntry) {
            return $true
        }
    }
    return $false
}

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    New-Item -ItemType Directory -Path $extractDir | Out-Null

    # Windows PowerShell may otherwise negotiate obsolete TLS versions.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    Write-Host "Downloading whodis for windows/$architecture..."
    Copy-ReleaseFile -Source "$BaseUrl/checksums.txt" -Destination $checksumsPath
    Copy-ReleaseFile -Source "$BaseUrl/$asset" -Destination $archivePath

    $assetPattern = [Regex]::Escape($asset)
    $checksumMatch = Select-String -LiteralPath $checksumsPath -Pattern "^([0-9A-Fa-f]{64})\s+\*?$assetPattern\s*$" | Select-Object -First 1
    if ($null -eq $checksumMatch) {
        throw "No valid checksum found for $asset."
    }

    $expectedChecksum = $checksumMatch.Matches[0].Groups[1].Value
    $actualChecksum = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($actualChecksum -ine $expectedChecksum) {
        throw "Checksum verification failed for $asset."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
    $executable = Join-Path $extractDir 'whodis.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw 'The release archive does not contain whodis.exe.'
    }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item -LiteralPath $executable -Destination (Join-Path $BinDir 'whodis.exe') -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (Test-PathEntry -PathValue $userPath -Entry $BinDir)) {
        $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $BinDir } else { "$userPath;$BinDir" }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    }

    if (-not (Test-PathEntry -PathValue $env:Path -Entry $BinDir)) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $BinDir } else { "$($env:Path);$BinDir" }
    }

    Write-Host "Installed whodis to $(Join-Path $BinDir 'whodis.exe')"
    Write-Host 'Open a new terminal, then run: whodis google.com'
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
