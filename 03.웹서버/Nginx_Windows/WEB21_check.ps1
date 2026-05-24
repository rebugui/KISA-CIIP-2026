# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-21
# @Category    : 웹서비스>3.보안설정
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-21"
$ITEM_NAME = "HTTP 리디렉션"
$SEVERITY = "중"

$purpose = "HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
$threat = "HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
$criteria_good = "HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
$criteria_bad = "HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
$remediation = "HTTP Redirection 활성화 설정"

try {
    $processes = @(Get-NginxWindowsProcesses)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    if ($processes.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx process exists, but configuration files were not found for HTTP redirect inspection."; $commandOutput = ($processes | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }) -join "`n"; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    else {
        $config = Get-NginxWindowsConfigText -ConfigFiles $configFiles
        $lines = Get-NginxActiveLines -ConfigText $config.Text
        $http = @($lines | Where-Object { $_ -match '^(?i)listen\s+.*\b80\b' -and $_ -notmatch '443|ssl' })
        $redirect = @($lines | Where-Object { $_ -match '^(?i)return\s+30[18]\s+https://' -or $_ -match '^(?i)rewrite\s+.+\s+https://' -or $_ -match '^(?i)add_header\s+Strict-Transport-Security\b' })
        $commandExecuted = "Parse Nginx Windows HTTP listen and HTTPS redirect directives"
        $commandOutput = (@($http + $redirect) -join "`n")
        if (-not $commandOutput) { $commandOutput = "No HTTP listener or HTTPS redirect evidence found." }
        if ($redirect.Count -gt 0) { $finalResult = "GOOD"; $status = "양호"; $summary = "HTTPS redirect or HSTS evidence was found." }
        elseif ($http.Count -gt 0) { $finalResult = "VULNERABLE"; $status = "취약"; $summary = "HTTP listener evidence was found without HTTPS redirection evidence." }
        else { $finalResult = "MANUAL"; $status = "수동진단"; $summary = "No port 80 listener was found in static configuration; confirm active server blocks and upstream redirect policy." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows HTTP redirect configuration discovery"
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
