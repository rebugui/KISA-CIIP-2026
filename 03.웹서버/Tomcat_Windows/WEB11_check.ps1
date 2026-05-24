# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-11
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Tomcat_Windows
# @Severity    : 중
# @Title       : 웹 서비스 경로 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\tomcat_windows_lib.ps1"

$ITEM_ID = "WEB-11"
$ITEM_NAME = "웹 서비스 경로 설정"
$SEVERITY = "중"

$purpose = "웹 서비스 영역 내 불필요한 경로를 분리해 웹 서비스의 침해가 시스템 영역으로 확장될 가능성을 최소화하기 위함"
$threat = "웹 서비스 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나, 불필요한 경로가 존재할 경우 외부에서 시스템 중요 파일이나 기능에 비인가 접근이 발생할 위험이 존재함"
$criteria_good = "웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
$criteria_bad = "웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
$remediation = "웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"

try {
    $diagnostic = Invoke-TomcatWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
    $finalResult = $diagnostic.FinalResult
    $status = $diagnostic.Status
    $summary = $diagnostic.Summary
    $commandOutput = $diagnostic.CommandOutput
    $commandExecuted = $diagnostic.CommandExecuted
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: " + $_.Exception.Message
    $commandExecuted = "Tomcat Windows diagnostic discovery"
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
