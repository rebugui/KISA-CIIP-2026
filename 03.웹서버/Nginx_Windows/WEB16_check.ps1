# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-16
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
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
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-16"
$ITEM_NAME = "웹 서비스 헤더 정보 노출 제한"
$SEVERITY = "중"

$purpose = "HTTP 응답 헤더에서 웹 서버 버전 및 종류,OS 정보 등 웹 서버와 관련된 정보가 불필요하게 노출되는 것을 최소화하기 위함"
$threat = "웹 서버 및 OS 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함"
$criteria_good = "HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
$criteria_bad = "HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
$remediation = "응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"

try {
    $processes = @(Get-NginxWindowsProcesses)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    if ($processes.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx process exists, but configuration files were not found for server_tokens inspection."; $commandOutput = ($processes | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }) -join "`n"; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    else {
        $config = Get-NginxWindowsConfigText -ConfigFiles $configFiles
        $tokens = @(Get-NginxActiveLines -ConfigText $config.Text | Where-Object { $_ -match '^(?i)server_tokens\s+' })
        $off = @($tokens | Where-Object { $_ -match '^(?i)server_tokens\s+off\s*;' })
        $commandExecuted = "Parse active server_tokens directives from Nginx Windows configuration"
        $commandOutput = if ($tokens) { ($tokens -join "`n") } else { "No active server_tokens directives found." }
        if ($off.Count -gt 0) { $finalResult = "GOOD"; $status = "양호"; $summary = "server_tokens off is configured." }
        else { $finalResult = "VULNERABLE"; $status = "취약"; $summary = "server_tokens off was not found; Nginx version information may be exposed." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows server_tokens configuration discovery"
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
