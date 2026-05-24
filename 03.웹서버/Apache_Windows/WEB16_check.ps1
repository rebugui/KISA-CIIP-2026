# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-16
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 헤더 정보 노출 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-16"
$ITEM_NAME = "웹 서비스 헤더 정보 노출 제한"
$SEVERITY = "중"

$purpose = "HTTP 응답 헤더에서 웹 서버 버전 및 종류,OS 정보 등 웹 서버와 관련된 정보가 불필요하게 노출되는 것을 최소화하기 위함"
$threat = "웹 서버 및 OS 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함"
$criteria_good = "HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
$criteria_bad = "HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
$remediation = "응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"

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

        $serverTokensMatches = @([regex]::Matches($activeText, '(?im)^\s*ServerTokens\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
        $serverSignatureMatches = @([regex]::Matches($activeText, '(?im)^\s*ServerSignature\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
        $serverTokens = if ($serverTokensMatches.Count -gt 0) { $serverTokensMatches[-1] } else { "Full" }
        $serverSignature = if ($serverSignatureMatches.Count -gt 0) { $serverSignatureMatches[-1] } else { "On" }

        $tokensSecure = $serverTokens -match '^(?i)Prod$'
        $signatureSecure = $serverSignature -match '^(?i)Off$'
        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "ServerTokens: $serverTokens",
            "ServerSignature: $serverSignature"
        )

        if ($tokensSecure -and $signatureSecure) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache response header exposure is minimized with ServerTokens Prod and ServerSignature Off."
        }
        elseif ($tokensSecure) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache ServerTokens is set to Prod. ServerSignature Off is additionally recommended."
        }
        else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache may expose server header information. Set ServerTokens Prod and ServerSignature Off."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for ServerTokens and ServerSignature"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows header exposure configuration discovery"
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
