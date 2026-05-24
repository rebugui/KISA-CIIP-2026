# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-18
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 웹 서비스 WebDAV 비활성화
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-18"
$ITEM_NAME = "웹 서비스 WebDAV 비활성화"
$SEVERITY = "상"

$purpose = "WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
$threat = "WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
$criteria_good = "WebDAV 서비스를 비활성화하고 있는 경우"
$criteria_bad = "WebDAV 서비스를 활성화하고 있는 경우"
$remediation = "WebDAV 서비스 비활성화 설정"

try {
    $state = Get-NginxWindowsState
    if (-not $state.Installed) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process, service, or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx exists, but configuration files were not found for WebDAV inspection."; $commandOutput = Get-NginxWindowsProcessEvidence -State $state; $commandExecuted = "Nginx Windows config discovery"
    }
    else {
        $dav = @($state.ActiveLines | Where-Object { $_ -match '^(?i)dav_methods\s+' -or $_ -match '^(?i)create_full_put_path\s+on\s*;' })
        $commandExecuted = "Parse active WebDAV directives from Nginx Windows configuration"
        $commandOutput = if ($dav) { ($dav -join "`n") } else { "No active WebDAV directives found." }
        if ($dav.Count -gt 0) { $finalResult = "VULNERABLE"; $status = "취약"; $summary = "Nginx WebDAV directives were found." }
        else { $finalResult = "GOOD"; $status = "양호"; $summary = "No Nginx WebDAV directives were found." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows WebDAV configuration discovery"
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
