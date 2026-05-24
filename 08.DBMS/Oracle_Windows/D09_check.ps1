# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-09
# @Category    : DBMS>1.계정관리
# @Platform    : Oracle_Windows
# @Severity    : 중
# @Title       : 일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\oracle_windows_lib.ps1"

$ITEM_ID = "D-09"
$ITEM_NAME = "일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정"
$SEVERITY = "중"

$purpose = "일정 횟수의 로그인 실패 시 계정 잠금 정책을 설정하여 비인가자의 자동화된 무차별 대입 공격, 사전 대입 공격 등을 통한 사용자 계정 비밀번호 유출을 방지하기 위함"
$threat = "일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함"
$criteria_good = "로그인 시도 횟수를 제한하는 값을 설정한 경우"
$criteria_bad = "로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우"
$remediation = "로그인 시도 횟수 제한 값 설정"
try {
    $diagnostic = Invoke-OracleWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
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
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Invoke-OracleWindowsCheck"
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
