# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-06
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-06"
$ITEM_NAME = "웹 서비스 상위 디렉터리 접근 제한 설정"
$SEVERITY = "상"

$purpose = "상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
$threat = "상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
$criteria_good = "상위 디렉터리 접근 기능을 제거한 경우"
$criteria_bad = "상위 디렉터리 접근 기능을 제거하지 않은 경우"
$remediation = "상위 디렉터리 접근 기능 제거 설정"

try {
    $state = Get-NginxWindowsState

    if (-not $state.Installed) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Nginx for Windows service/process/configuration was not found."
        $commandOutput = "No nginx.exe process, Nginx service, or known nginx.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known Nginx nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Nginx was found, but nginx.conf could not be located automatically."
        $commandOutput = Get-NginxWindowsProcessEvidence -State $state
        $commandExecuted = "Discover Nginx Windows process/service configuration paths"
    }
    else {
        $tryFiles = @($state.ActiveLines | Where-Object { $_ -match '^(?i)try_files\s+' })
        $unsafeRoots = @($state.ActiveLines | Where-Object { $_ -match '^(?i)(root|alias)\s+(?:[A-Za-z]:[/\\]?|/|.*\.\.).*;$' })

        $evidence = @(
            "Config files: $($state.Config.Files -join ', ')",
            "try_files directives: $($tryFiles.Count)",
            "root/alias directives requiring review: $($unsafeRoots.Count)"
        )
        if ($tryFiles.Count -gt 0) { $evidence += $tryFiles }
        if ($unsafeRoots.Count -gt 0) { $evidence += $unsafeRoots }

        $commandExecuted = "Parse active Nginx root/alias/try_files directives for parent-directory traversal controls"
        $commandOutput = $evidence -join "`n"

        if ($unsafeRoots.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx root/alias directives use broad or parent-relative paths. Verify that '..' traversal and unintended parent-directory access are blocked."
        }
        elseif ($tryFiles.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Nginx configuration contains try_files routing controls and no broad parent-relative root/alias directive was detected."
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx configuration was found, but parent-directory traversal protection cannot be proven from static config alone."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows parent-directory access control discovery"
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
