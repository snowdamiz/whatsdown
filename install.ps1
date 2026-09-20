# Install or update Morse for Windows from the newest desktop release:
#
#   irm https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.ps1 | iex
#
# Options are environment variables, set before running the command:
#   $env:MORSE_VERSION    release to install (for example 0.1.0) instead of the newest
#   $env:MORSE_NO_LAUNCH  set to anything to skip opening Morse afterwards
#
# macOS: curl -fsSL https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.sh | sh

# `iex` runs in the caller's session; a child scope keeps these preferences out of it.
& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell downloads crawl while it renders a progress bar.
    $ProgressPreference = 'SilentlyContinue'

    $repo = 'snowdamiz/whatsdown'
    $releasesApi = if ($env:MORSE_RELEASES_API_URL) { $env:MORSE_RELEASES_API_URL } else { "https://api.github.com/repos/$repo/releases?per_page=100" }
    $releaseBase = if ($env:MORSE_RELEASE_BASE_URL) { $env:MORSE_RELEASE_BASE_URL } else { "https://github.com/$repo/releases/download" }

    $version = "$env:MORSE_VERSION" -replace '^(desktop-)?v', ''
    if (-not $version) {
        # Mobile and backend tags share this repository, so "latest" is not enough.
        # ponytail: reads the newest 100 releases; page the API if desktop tags fall off it.
        $version = (Invoke-RestMethod -UseBasicParsing $releasesApi) |
            ForEach-Object { $_.tag_name } | Where-Object { $_ -like 'desktop-v*' } |
            ForEach-Object { $_ -replace '^desktop-v', '' } |
            Sort-Object { [version]($_ -replace '[-+].*$', '') } | Select-Object -Last 1
    }
    if (-not $version) { throw "morse: no desktop release found at $releasesApi" }
    if ($version -notmatch '^[0-9A-Za-z.+-]+$') { throw "morse: unexpected release version: $version" }

    $asset = "Morse_${version}_x64-setup.exe"
    $url = "$releaseBase/desktop-v$version"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "morse-install-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $installer = Join-Path $tmp $asset
        Write-Host "Downloading Morse $version..."
        Invoke-WebRequest -UseBasicParsing "$url/$asset" -OutFile $installer
        Invoke-WebRequest -UseBasicParsing "$url/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
        $expected = Get-Content (Join-Path $tmp 'SHA256SUMS') |
            ForEach-Object { $hash, $name = $_ -split '\s+', 2; if ($name -eq $asset) { $hash } } |
            Select-Object -First 1
        if (-not $expected -or $expected -ne (Get-FileHash $installer -Algorithm SHA256).Hash) {
            throw "morse: $asset does not match its SHA256SUMS entry; nothing was installed"
        }

        $signature = (Get-AuthenticodeSignature $installer).Status
        if ("$signature" -eq 'NotSigned') {
            # ponytail: release signing is not configured yet, so an unsigned installer is
            # expected; delete this branch once desktop-release.yml signs Windows builds.
            Write-Warning "$asset is not code signed yet. Its SHA256SUMS entry matched."
        } elseif ("$signature" -ne 'Valid') {
            throw "morse: $asset has an invalid Authenticode signature ($signature); nothing was installed"
        }

        # /S installs silently for the current user; /R opens Morse afterwards.
        $flags = if ($env:MORSE_NO_LAUNCH) { '/S' } else { '/S', '/R' }
        $setup = Start-Process -FilePath $installer -ArgumentList $flags -PassThru
        # -Wait would also wait for Morse itself. Reading Handle first keeps ExitCode available.
        $null = $setup.Handle
        $setup.WaitForExit()
        if ($setup.ExitCode -ne 0) { throw "morse: the installer exited with code $($setup.ExitCode)" }
        Write-Host "Installed Morse $version."
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
