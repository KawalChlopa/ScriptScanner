# Dane testowe YARA: DownloadString i Invoke-Expression.
# Funkcja sluzy do analizy statycznej i nie jest wywolywana.
function Test-EngineCheck {
    & 'Invoke-Expression' '1 + 1'
    [ScriptBlock]::Create('1 + 1')
}
