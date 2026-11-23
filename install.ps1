$ErrorActionPreference = 'Stop'

try {
    $launcher = Get-Command py.exe -CommandType Application
    $package = $PSScriptRoot + '[static-analysis]'
    & $launcher.Source -m pip install $package
    if ($LASTEXITCODE -ne 0) { throw 'Instalacja pakietow Python nie powiodla sie.' }

    & $launcher.Source -I -c 'import yara, esprima, semgrep'
    if ($LASTEXITCODE -ne 0) { throw 'Python wybrany przez py nie widzi wszystkich pakietow.' }

    $shellCheckDirectory = Join-Path $env:LOCALAPPDATA 'Programs\ShellCheck'
    $shellCheck = Join-Path $shellCheckDirectory 'shellcheck.exe'
    if (-not (Get-Command shellcheck.exe -CommandType Application -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path -LiteralPath $shellCheck -PathType Leaf)) {
            $work = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Path $work | Out-Null
            try {
                $archive = Join-Path $work 'shellcheck.zip'
                $url = 'https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.zip'
                $sha256 = '8A4E35AB0B331C85D73567B12F2A444DF187F483E5079CEFFA6BDA1FAA2E740E'
                Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive
                if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $sha256) {
                    throw 'Suma SHA-256 archiwum ShellCheck jest niezgodna.'
                }
                Expand-Archive -LiteralPath $archive -DestinationPath $work
                New-Item -ItemType Directory -Path $shellCheckDirectory -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $work 'shellcheck.exe') -Destination $shellCheck
            } finally {
                # The installer only owns the files created in this unique temporary directory.
                Get-ChildItem -LiteralPath $work -File | Remove-Item
                Remove-Item -LiteralPath $work
            }
        }
        & $shellCheck --version
        if ($LASTEXITCODE -ne 0) { throw 'ShellCheck nie uruchamia sie.' }
    }

    # Persist the local installation even if it is already visible in this process.
    if (Test-Path -LiteralPath $shellCheck -PathType Leaf) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (($userPath -split ';') -notcontains $shellCheckDirectory) {
            $entries = @($userPath, $shellCheckDirectory) | Where-Object { $_ }
            [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
        }
    }

    Write-Host 'Gotowe. Otworz nowe okno CMD i uruchom:'
    Write-Host 'py src/main.py examples/engine_check.sh'
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
