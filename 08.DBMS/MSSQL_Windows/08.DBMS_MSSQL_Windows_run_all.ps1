# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (?묒슦??. All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# MSSQL Database Vulnerability Assessment - All Check Runner
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

# Script information
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
$CATEGORY = "DBMS"
$PLATFORM = "MSSQL_Windows"

# Load library
. "${LIB_DIR}\result_manager.ps1"

# Set environment variable for run_all mode
$env:POWERSHELL_RUNALL_MODE = "1"

# Array to store results
$results = @()
$totalItems = 26
$completedItems = 0
$goodCount = 0
$vulnCount = 0
$manualCount = 0
$naCount = 0

# Function to display progress
function Show-Progress {
    param(
        [int]$Current,
        [int]$Total,
        [string]$ItemId
    )
    $percent = [math]::Round(($Current / $Total) * 100, 1)
    Write-Host "`r[$percent%] 吏꾨떒 以? $itemId ($Current/$Total)" -NoNewline
}

# Get all check scripts
$checkScripts = Get-ChildItem -Path $SCRIPT_DIR -Filter "D*_check.ps1" | Sort-Object Name

if ($checkScripts.Count -eq 0) {
    Write-Error "?먭? ?ㅽ겕由쏀듃瑜?李얠쓣 ???놁뒿?덈떎."
    exit 1
}

Write-Host "============================================================"
Write-Host "KISA-CIIP-2026 MSSQL 痍⑥빟??吏꾨떒 - ?꾩껜 ??ぉ"
Write-Host "============================================================"
Write-Host "移댄뀒怨좊━: $CATEGORY"
Write-Host "?뚮옯?? $PLATFORM"
Write-Host "진단 항목: $($checkScripts.Count)개"
Write-Host "?쒖옉 ?쒓컙: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"
Write-Host ""

# Initialize text file
$TXT_FILE = Initialize-RunallTextFile -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR

# Run each check script
foreach ($script in $checkScripts) {
    $completedItems++
    Show-Progress -Current $completedItems -Total $totalItems -ItemId $script.Name

    try {
        # Run the script and capture output
        $output = & $script.FullName 2>&1 | Out-String

        # Try to parse JSON from output
        $jsonLine = $output | Select-String -Pattern '^\{.*\}$' | Select-Object -First 1

        if ($jsonLine) {
            try {
                $jsonObj = $jsonLine.Line | ConvertFrom-Json
                $results += $jsonLine.Line

                # Update counters
                switch ($jsonObj.final_result) {
                    "GOOD" { $goodCount++ }
                    "VULNERABLE" { $vulnCount++ }
                    "MANUAL" { $manualCount++ }
                    "N/A" { $naCount++ }
                }

                # Append to text file
                Append-RunallTextResult -JsonObj $jsonLine.Line -TxtFile $TXT_FILE
            }
            catch {
                # JSON parse failed, treat as error
                $naCount++
                $results += "{}"
            }
        }
        else {
            # No JSON output found
            $naCount++
            $results += "{}"
        }
    }
    catch {
        $naCount++
        $results += "{}"
    }
}

Write-Host ""
Write-Host ""

# Generate aggregated results
New-RunallAggregatedResults -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR -TotalItems $totalItems -ResultsJson $results

Write-Host ""
Write-Host "============================================================"
Write-Host "吏꾨떒 ?꾨즺"
Write-Host "============================================================"
Write-Host "珥???ぉ: $totalItems"
Write-Host "?묓샇: $goodCount"
Write-Host "痍⑥빟: $vulnCount"
Write-Host "?섎룞吏꾨떒: $manualCount"
Write-Host "N/A: $naCount"
if ($totalItems -gt 0) {
    $goodRate = [math]::Round(($goodCount * 100.0) / $totalItems, 1)
    Write-Host "?묓샇?? $goodRate%"
}
Write-Host "醫낅즺 ?쒓컙: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"

exit 0
