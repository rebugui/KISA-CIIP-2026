# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-08
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 하
# @Title       : 웹 서비스 파일 업로드 및 다운로드 용량 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-08"
$ITEM_NAME = "웹 서비스 파일 업로드 및 다운로드 용량 제한"
$SEVERITY = "하"

$purpose = "기반 시설 시스템은 원칙적으로 파일 업로드 및 다운로드를 금지하지만 불가피하게 파일의 업로드 및 다운로드 기능이 필요한 경우, 파일의 용량 제한을 설정하여 불필요한 업로드 및 다운로드를 방지해 서버의 과부하를 예방하고, 웹 서버 자원을 효율적으로 관리하기 위함"
$threat = "웹 서비스의 파일 업로드 및 다운로드의 용량을 제한하지 않은 경우, 악의적인 목적을 가진 사용자가 반복 업로드 및 웹 쉘 공격 등으로 시스템 권한을 탈취하거나 대용량 파일의 업로드 및 다운로드로 서버 자원을 고갈시켜 서비스 장애를 발생시킬 위험이 존재함"
$criteria_good = "파일 업로드 및 다운로드 용량을 제한한 경우"
$criteria_bad = "파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
$remediation = "파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정"

try {
    $processes = @(Get-NginxWindowsProcesses)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    if ($processes.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx process exists, but configuration files were not found for upload/download size inspection."; $commandOutput = ($processes | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }) -join "`n"; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    else {
        $config = Get-NginxWindowsConfigText -ConfigFiles $configFiles
        $limits = @(Get-NginxActiveLines -ConfigText $config.Text | Where-Object { $_ -match '^(?i)client_max_body_size\s+(.+);' })
        $unlimited = @($limits | Where-Object { $_ -match '^(?i)client_max_body_size\s+0\s*;' })
        $commandExecuted = "Parse active client_max_body_size directives from Nginx Windows configuration"
        $commandOutput = if ($limits) { ($limits -join "`n") } else { "No active client_max_body_size directives found." }
        if ($limits.Count -eq 0 -or $unlimited.Count -gt 0) { $finalResult = "VULNERABLE"; $status = "취약"; $summary = "client_max_body_size is missing or unlimited." }
        else { $finalResult = "GOOD"; $status = "양호"; $summary = "client_max_body_size limit is configured." }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows client_max_body_size configuration discovery"
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
