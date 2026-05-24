# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-06
# @Category    : DBMS>1.계정관리
# @Platform    : mysql_Windows
# @Severity    : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\mysql_windows_lib.ps1"

$ITEM_ID = "D-06"
$ITEM_NAME = "DB 사용자 계정을 개별적으로 부여하여 사용"
$SEVERITY = "중"

$purpose = "사용자별 별도 DBMS 계정을 사용하여 DB에 접근하는지 점검하여 DB 계정 공유 사용으로 발생할 수 있는 로그 감사 추적 문제를 대비하고자함"
$threat = "DB 계정을 공유하여 사용할 경우 비인가자의 DB 접근 발생 시 계정 공유 사용으로 인해 로그 감사 추적의 어려움이 발생할 위험이 존재함"
$criteria_good = "사용자별 계정을 사용하고 있는 경우"
$criteria_bad = "공용 계정을 사용하고 있는 경우"
$remediation = "사용자별 계정 생성 및 권한 부여"

try {
    $diagnostic = Invoke-MySqlWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
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
    $commandExecuted = "MySQL Windows diagnostic discovery"
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
