# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-10
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 불필요한 프 록 시 설정 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-10"
$ITEM_NAME = "불필요한 프 록 시 설정 제한"
$SEVERITY = "상"

$purpose = "불필요한 Proxy 설정을 제한하여 자원 낭비 예방 및 관리의 복잡성을 감소시키며, 중간자 공격 등의 해킹 공격으로부터 시스템 관련 정보가 노출되거나 악용되는 것을 방지하기 위함"
$threat = "불필요한 Proxy 설정을 제한하지 않는 경우 공격자가 Proxy 서버를 이용하여 원래 의도되지 않은 방식으로 시스템에 접근하거나 시스템 관련 정보가 유출될 위험이 존재함"
$criteria_good = "불필요한 Proxy 설정을 제한한 경우"
$criteria_bad = "불필요한 Proxy 설정을 제한하지 않은 경우"
$remediation = "불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"

try {
    $state = Get-NginxWindowsState
    if (-not $state.Installed) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process, service, or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx exists, but configuration files were not found for proxy inspection."; $commandOutput = Get-NginxWindowsProcessEvidence -State $state; $commandExecuted = "Nginx Windows config discovery"
    }
    else {
        $proxy = @($state.ActiveLines | Where-Object { $_ -match '^(?i)(proxy_pass|grpc_pass|uwsgi_pass|scgi_pass|fastcgi_pass)\s+' })
        $commandExecuted = "Parse active proxy/pass directives from Nginx Windows configuration"
        $commandOutput = if ($proxy) { ($proxy -join "`n") } else { "No proxy/pass directives found." }
        if ($proxy.Count -eq 0) { $finalResult = "GOOD"; $status = "양호"; $summary = "No proxy/pass directives were found." }
        else { $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Proxy/pass directives exist; confirm each upstream mapping is required and restricted." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows proxy configuration discovery"
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
