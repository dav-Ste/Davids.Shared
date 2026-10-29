[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Configuration = 'Release',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$sharedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $sharedRoot ("artifacts/package/" + $Configuration.ToLowerInvariant())
}

Push-Location $sharedRoot
try {
    dotnet restore 'Davids.Shared.slnx' --locked-mode -m:1 -nr:false --tl:off
    if ($LASTEXITCODE) { throw 'Locked restore failed for Davids.Shared.slnx.' }

    dotnet pack 'src/Davids.ServiceDefaults/Davids.ServiceDefaults.csproj' `
        --no-restore `
        -c $Configuration `
        -o $OutputDirectory `
        "/p:DavidsServiceDefaultsVersion=$Version" `
        -warnaserror -m:2 -nr:false --tl:off
    if ($LASTEXITCODE) { throw 'dotnet pack failed for Davids.ServiceDefaults.' }

    $nupkg = Join-Path $OutputDirectory "Davids.ServiceDefaults.$Version.nupkg"
    if (-not (Test-Path -LiteralPath $nupkg)) {
        throw "Expected NuGet package was not produced at $nupkg."
    }

    Write-Host "Packed Davids.ServiceDefaults v$Version -> $nupkg"
} finally {
    Pop-Location
}
