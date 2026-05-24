#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$CATEGORY = "Web Server"
$PLATFORM = "JEUS_Windows"
$TOTAL_ITEMS = 26
$RESULTS_JSON = @()
$env:POWERSHELL_RUNALL_MODE = "1"
$env:WS_RUNALL_MODE = "1"

foreach ($i in 1..26) {
    $itemId = "WEB-{0:D2}" -f $i
    $scriptName = $itemId -replace '-', ''
    $scriptFile = Join-Path $SCRIPT_DIR "$scriptName_check.ps1"
    if (Test-Path $scriptFile) {
        $output = & $scriptFile 2>&1 | Out-String
        $json = $output | Select-String -Pattern '^\s*\{' -Context 0,20 | Select-Object -First 1
        if ($output) {
            $RESULTS_JSON += $output
            Write-Output $output
        }
    }
}

New-RunallAggregatedResults -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR -TotalItems $TOTAL_ITEMS -ResultsJson $RESULTS_JSON