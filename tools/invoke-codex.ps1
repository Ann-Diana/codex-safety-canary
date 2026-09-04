$ErrorActionPreference = "Stop"

try {
    $codexExe = $env:CANARY_CODEX_EXE
    if ([string]::IsNullOrWhiteSpace($codexExe)) {
        $codexExe = "codex"
    }
    & $codexExe @args
    [Console]::Error.WriteLine("__CODEX_SAFETY_CANARY_EXECUTABLE_STARTED__")
    if ($null -eq $LASTEXITCODE) {
        exit 0
    }
    exit $LASTEXITCODE
}
catch {
    Write-Error $_
    exit 127
}
