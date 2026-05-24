# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-19
# @Category    : 웹서비스>3.보안설정
# @Platform    : Nginx_Windows
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
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-19"
$ITEM_NAME = "웹 서비스 SSI(Server Side Includes)사용 제한"
$SEVERITY = "중"

$purpose = "웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함"
$threat = "웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함"
$criteria_good = "웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
$criteria_bad = "웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
$remediation = "웹 서비스 내 불필요한 SSI 사용 제한 설정"

try {
    $state = Get-NginxWindowsState
    if (-not $state.Installed) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process, service, or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx exists, but configuration files were not found for SSI inspection."; $commandOutput = Get-NginxWindowsProcessEvidence -State $state; $commandExecuted = "Nginx Windows config discovery"
    }
    else {
        $ssiOn = @($state.ActiveLines | Where-Object { $_ -match '^(?i)ssi\s+on\s*;' })
        $ssi = @($state.ActiveLines | Where-Object { $_ -match '^(?i)ssi\s+' })
        $commandExecuted = "Parse active SSI directives from Nginx Windows configuration"
        $commandOutput = if ($ssi) { ($ssi -join "`n") } else { "No active SSI directives found." }
        if ($ssiOn.Count -gt 0) { $finalResult = "VULNERABLE"; $status = "취약"; $summary = "Nginx SSI is enabled." }
        else { $finalResult = "GOOD"; $status = "양호"; $summary = "No active SSI enabled directive was found." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows SSI configuration discovery"
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
