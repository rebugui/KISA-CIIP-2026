# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-04
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 웹 서비스 디렉터리 리 스팅 방지 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-04"
$ITEM_NAME = "웹 서비스 디렉터리 리 스팅 방지 설정"
$SEVERITY = "상"

$purpose = "웹 서버에 대한 디렉터리 리스 팅 기능을 차단하여 디렉터리 내의 모든 파일에 대한 접근 및 정보 노출을 차단하기 위함"
$threat = "디렉터리 리스 팅 기능이 차단되지 않은 경우, 비인가자가 해당 디렉터리 내의 모든 파일의 리스트 확인 및 접근이 가능하고, 웹 서버의 구조 및 백업 파일이나 소스 파일 등 공개되면 안 되는 중요 파일들이 노출될 위험이 존재함"
$criteria_good = "디렉터리 리스팅이 설정되지 않은 경우"
$criteria_bad = "디렉터리 리스팅이 설정된 경우"
$remediation = "디렉터리 리스팅 기능 차단 설정"

try {
    $services = @(Get-ApacheWindowsServices)
    $configCandidates = @(Get-ApacheWindowsConfigCandidates)

    if ($services.Count -eq 0 -and $configCandidates.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service or known httpd.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    elseif ($configCandidates.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache service was found, but httpd.conf could not be located automatically."
        $commandOutput = ($services | Select-Object Name, DisplayName, State, PathName | Format-List | Out-String).Trim()
        $commandExecuted = "Get-CimInstance Win32_Service | Where-Object Name/DisplayName matches Apache/httpd"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configCandidates
        $activeLines = @($config.Text -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^#' })
        $optionsLines = @($activeLines | Where-Object { $_ -match '^\s*Options\b' })

        $indexesEnabled = @()
        $indexesDisabled = @()

        foreach ($line in $optionsLines) {
            $trimmed = $line.Trim()
            $tokens = @($trimmed -replace '^\s*Options\s+', '' -split '\s+' | Where-Object { $_ })
            if (($tokens | Where-Object { $_ -match '^\+?(Indexes|All)$' }) -and
                -not ($tokens | Where-Object { $_ -match '^-Indexes$' })) {
                $indexesEnabled += $trimmed
            }
            elseif ($tokens | Where-Object { $_ -match '^-Indexes$' }) {
                $indexesDisabled += $trimmed
            }
        }

        $indexesEnabled = @($indexesEnabled | Select-Object -Unique)
        $indexesDisabled = @($indexesDisabled | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "Options directives: $($optionsLines.Count)",
            "Indexes enabled evidence count: $($indexesEnabled.Count)",
            "Indexes disabled evidence count: $($indexesDisabled.Count)"
        )

        if ($indexesEnabled.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache directory listing may be enabled. Remove Indexes/All from Options or set Options -Indexes for every served directory."
            $evidence += "Matched directory listing directives:"
            $evidence += $indexesEnabled
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            if ($indexesDisabled.Count -gt 0) {
                $summary = "Apache directory listing is explicitly disabled with Options -Indexes."
                $evidence += "Matched disabling directives:"
                $evidence += $indexesDisabled
            }
            else {
                $summary = "Apache directory listing enabling directives were not found in active configuration."
                $evidence += "No active Options Indexes, Options +Indexes, Options All, or Options +All directive found."
            }
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for Options Indexes/All and -Indexes"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows directory listing configuration discovery"
}

$resultParams = @{
    ItemId = $ITEM_ID
    ItemName = $ITEM_NAME
    Status = $status
    FinalResult = $finalResult
    InspectionSummary = $summary
    CommandResult = $commandOutput
    CommandExecuted = $commandExecuted
    GuidelinePurpose = $purpose
    GuidelineThreat = $threat
    GuidelineCriteriaGood = $criteria_good
    GuidelineCriteriaBad = $criteria_bad
    GuidelineRemediation = $remediation
    ScriptDir = $SCRIPT_DIR
}

Save-DualResult @resultParams

if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "Diagnostic complete: $ITEM_ID ($finalResult)"
}

exit 0
