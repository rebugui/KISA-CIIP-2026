# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-19
# @Category    : 웹서비스>3.보안설정
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 SSI(Server Side Includes)사용 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-19"
$ITEM_NAME = "웹 서비스 SSI(Server Side Includes)사용 제한"
$SEVERITY = "중"

$purpose = "웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함"
$threat = "웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함"
$criteria_good = "웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
$criteria_bad = "웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
$remediation = "웹 서비스 내 불필요한 SSI 사용 제한 설정"

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
        $activeText = $activeLines -join "`n"

        $includeModuleMatches = @([regex]::Matches($activeText, '(?im)^\s*LoadModule\s+include_module\b.*') | ForEach-Object { $_.Value.Trim() })
        $optionsIncludeMatches = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?<![-\w])Includes(?:NOEXEC)?\b).*$') | ForEach-Object { $_.Value.Trim() })
        $addOutputFilterMatches = @([regex]::Matches($activeText, '(?im)^\s*AddOutputFilter\s+INCLUDES\b.*') | ForEach-Object { $_.Value.Trim() })
        $setOutputFilterMatches = @([regex]::Matches($activeText, '(?im)^\s*SetOutputFilter\s+INCLUDES\b.*') | ForEach-Object { $_.Value.Trim() })
        $xBitHackMatches = @([regex]::Matches($activeText, '(?im)^\s*XBitHack\s+(?:on|full)\b.*') | ForEach-Object { $_.Value.Trim() })

        $ssiEvidence = @()
        $ssiEvidence += $includeModuleMatches
        $ssiEvidence += $optionsIncludeMatches
        $ssiEvidence += $addOutputFilterMatches
        $ssiEvidence += $setOutputFilterMatches
        $ssiEvidence += $xBitHackMatches
        $ssiEvidence = @($ssiEvidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "SSI evidence count: $($ssiEvidence.Count)"
        )

        if ($ssiEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache SSI appears to be enabled. Disable mod_include and remove Options Includes/IncludesNOEXEC or INCLUDES output filters unless explicitly required."
            $evidence += "Matched SSI directives:"
            $evidence += $ssiEvidence
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache SSI enabling directives were not found in active configuration."
            $evidence += "No active LoadModule include_module, Options Includes, AddOutputFilter INCLUDES, SetOutputFilter INCLUDES, or XBitHack On/Full directive found."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for SSI-related directives"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows SSI configuration discovery"
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
