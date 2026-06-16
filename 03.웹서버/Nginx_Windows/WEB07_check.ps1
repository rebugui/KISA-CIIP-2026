# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-07
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-07"
$ITEM_NAME = "웹 서비스 경로 내 불필요한 파일 제거"
$SEVERITY = "중"

$purpose = "웹 서비스 설치 시 기본으로 생성되는 샘플, 매뉴얼 파일 등 서비스에 불필요한 파일을 제거하여 불필요한 공격 대상으로 이용되는 것을 방지하기 위함"
$threat = "웹 서비스 설치 시 기본으로 생성되는 파일 및 디렉터리나 백 업, 테스트 파일 등을 제거하지 않은 경우, 비인가자에게 시스템 관련 정보 및 웹 서버 정보가 노출되거나 해킹에 악용될 수 있음"
$criteria_good = "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
$criteria_bad = "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
$remediation = "불필요한 파일 및 디렉터리를 제거하도록 설정"

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
        $summary = "Nginx was found, but web root paths could not be determined automatically."
        $commandOutput = Get-NginxWindowsProcessEvidence -State $state
        $commandExecuted = "Discover Nginx Windows process/service configuration paths"
    }
    else {
        $roots = @((Get-NginxRootPaths -State $state) + (Get-NginxDefaultRootCandidates) | Select-Object -Unique)
        $patterns = @(
            '*sample*', '*example*', '*manual*', '*docs*', '*doc*', '*test*', '*tmp*',
            '*backup*', '*.bak', '*.old', '*.orig', '*readme*', '*install*'
        )
        $findings = [System.Collections.Generic.List[string]]::new()

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                continue
            }
            foreach ($pattern in $patterns) {
                foreach ($item in @(Get-ChildItem -Path (Join-Path $root '*') -Recurse -Force -ErrorAction SilentlyContinue -Include $pattern | Select-Object -First 20)) {
                    $findings.Add($item.FullName) | Out-Null
                }
            }
        }

        $commandExecuted = "Inspect configured Nginx root paths for sample/manual/test/backup files"
        $commandOutput = if ($findings.Count -gt 0) {
            "Root paths:`n$($roots -join "`n")`n`nUnnecessary file candidates:`n$($findings -join "`n")"
        }
        else {
            "Root paths:`n$($roots -join "`n")`n`nNo sample/manual/test/backup file candidates found."
        }

        if ($roots.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx configuration was found, but no web root path was resolved for unnecessary-file inspection."
        }
        elseif ($findings.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Unnecessary sample, manual, test, temporary, or backup file candidates were found under Nginx web roots."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No unnecessary sample, manual, test, temporary, or backup file candidates were found under resolved Nginx web roots."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows unnecessary web file discovery"
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
