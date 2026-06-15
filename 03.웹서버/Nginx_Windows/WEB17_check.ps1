# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-17
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : 웹 서비스 가상 디렉터리 삭제
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-17"
$ITEM_NAME = "웹 서비스 가상 디렉터리 삭제"
$SEVERITY = "중"

$purpose = "불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
$threat = "불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
$criteria_good = "불필요한 가상 디렉터리가 존재하지 않는 경우"
$criteria_bad = "불필요한 가상 디렉터리가 존재하는 경우"
$remediation = "불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"

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
        $aliases = @(Get-NginxAliasPaths -State $state)
        $unnecessaryAliases = @($aliases | Where-Object {
            $_.Directive -match '(?i)[\\/](manual|docs?|examples?|samples?|test|tmp|backup|old)([\\/;]|\s|$)' -or
            $_.Path -match '(?i)\\(manual|docs?|examples?|samples?|test|tmp|backup|old)(\\|$)'
        })

        $commandExecuted = "Parse Nginx alias directives for unnecessary virtual-directory mappings"
        $commandOutput = if ($aliases.Count -gt 0) {
            ($aliases | ForEach-Object { "$($_.Directive) => $($_.Path)" }) -join "`n"
        }
        else {
            "No active Nginx alias directives found."
        }

        if ($unnecessaryAliases.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Nginx alias directives appear to expose unnecessary virtual directories such as docs, samples, tests, or backups."
        }
        elseif ($aliases.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx alias directives were found. Confirm each virtual directory is required."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No active Nginx alias-based virtual directory mappings were found."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows virtual directory discovery"
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
