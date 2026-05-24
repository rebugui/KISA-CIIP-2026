# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-05
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-05"
$ITEM_NAME = "지정하지 않은 CGI/ISAPI 실행 제한"
$SEVERITY = "상"

$purpose = "CGI 스크립트를 정해진 디렉터리에서만 실행되도록하여 악의적인 파일의 업로드 및 실행을 방지하기 위함"
$threat = "게시판이나 자료실과 같이 업로드되는 파일이 저장되는 디렉터리에 CGI 스크립트가 실행 가능한 경우 악의적인 파일을 업로드하고 이를 실행하여 시스템의 중요 정보가 노출될 수 있으며 침해 사고의 경로로 이용될 위험이 존재함"
$criteria_good = "CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
$criteria_bad = "CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
$remediation = "CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"

try {
    $state = Get-NginxWindowsState
    if (-not $state.Installed) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process, service, or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx exists, but configuration files were not found for CGI/FastCGI inspection."; $commandOutput = Get-NginxWindowsProcessEvidence -State $state; $commandExecuted = "Nginx Windows config discovery"
    }
    else {
        $cgi = @($state.ActiveLines | Where-Object { $_ -match '^(?i)(fastcgi_pass|scgi_pass|uwsgi_pass|cgi_pass)\s+' })
        $unrestricted = @($cgi | Where-Object { $_ -match '(?i)127\.0\.0\.1|localhost|unix:|fastcgi|cgi' })
        $commandExecuted = "Parse active fastcgi/scgi/uwsgi/cgi pass directives from Nginx Windows configuration"
        $commandOutput = if ($cgi) { ($cgi -join "`n") } else { "No CGI/FastCGI pass directives found." }
        if ($cgi.Count -eq 0) { $finalResult = "GOOD"; $status = "양호"; $summary = "No CGI/FastCGI execution directives were found." }
        elseif ($unrestricted.Count -gt 0) { $finalResult = "MANUAL"; $status = "수동진단"; $summary = "CGI/FastCGI execution is configured; confirm it is restricted to approved locations and not upload paths." }
        else { $finalResult = "GOOD"; $status = "양호"; $summary = "No unrestricted CGI/FastCGI evidence was found." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows CGI/FastCGI configuration discovery"
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
