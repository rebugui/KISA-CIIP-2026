# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-04
# @Category    : DBMS>1.계정관리
# @Platform    : MSSQL_Windows
# @Severity    : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\mssql_windows_lib.ps1"

$ITEM_ID = "D-04"
$ITEM_NAME = "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
$SEVERITY = "상"

$purpose = "관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함"
$threat = "관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함"
$criteria_good = "관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
$criteria_bad = "관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우"
$remediation = "관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"

try {
    $diagnostic = Invoke-MsSqlWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
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
    $commandExecuted = "SQL Server Windows diagnostic discovery"
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
