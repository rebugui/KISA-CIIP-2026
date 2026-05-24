# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-22
# @Category    : 웹서비스>3.보안설정
# @Platform    : Apache_Windows
# @Severity    : 하
# @Title       : 에러 페이지 관리
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-22"
$ITEM_NAME = "에러 페이지 관리"
$SEVERITY = "하"

$purpose = "에러 페이지에서 웹 서버 버전 및 종류, OS 정보 등 웹 서버와 관련된 불필요한 정보 및 에러 코드를 통한 기술적 취약점이 노출되는 것을 최소화하기 위함"
$threat = "에러 페이지에서 불필요한 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점 등을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함 필수 에러 코드에 대해 일원화된 에러 페이지로 관리하지 않는 경우 에러 코드를 통해 각종 정보 유추의 위험이 존재함"
$criteria_good = "웹 서비스 에러 페이지가 별도로 지정된 경우"
$criteria_bad = "웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
$remediation = "필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정"

try {
    $services = @(Get-ApacheWindowsServices)
    $configFiles = @(Get-ApacheWindowsConfigCandidates)

    if ($services.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service or known httpd.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache service exists, but configuration files were not found for ErrorDocument inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $errorDocs = @($config.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object {
            $_ -and $_ -notmatch '^#' -and $_ -match '^(?i)ErrorDocument\s+(400|401|403|404|500|502|503)\b'
        })
        $codes = @($errorDocs | ForEach-Object { if ($_ -match '^(?i)ErrorDocument\s+(\d{3})\b') { $Matches[1] } } | Sort-Object -Unique)
        $requiredCodes = @('400', '401', '403', '404', '500')
        $covered = @($requiredCodes | Where-Object { $codes -contains $_ })

        $commandExecuted = "Parse active ErrorDocument directives from Apache Windows configuration"
        $commandOutput = if ($errorDocs) { ($errorDocs -join "`n") } else { "No active ErrorDocument directives found." }

        if ($covered.Count -ge 4) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Custom ErrorDocument directives cover most required error codes: $($covered -join ', ')."
        }
        elseif ($errorDocs.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Some ErrorDocument directives exist, but coverage of required error codes is incomplete."
        }
        else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "No custom ErrorDocument directives were found; default error pages may expose server details."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows ErrorDocument configuration discovery"
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

exit 0
