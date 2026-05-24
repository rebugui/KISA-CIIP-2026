#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-09"
$ITEM_NAME = "일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정"
$SEVERITY = "중"

$purpose = "일정 횟수의 로그인 실패 시 계정 잠금 정책을 설정하여 비인가자의 자동화된 무차별 대입 공격, 사전 대입 공격 등을 통한 사용자 계정 비밀번호 유출을 방지하기 위함"
$threat = "일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함"
$criteria_good = "로그인 시도 횟수를 제한하는 값을 설정한 경우"
$criteria_bad = "로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우"
$remediation = "로그인 시도 횟수 제한 값 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "mysql_Windows is not a target platform for D-09 according to docs/guideline_metadata.json."
$commandOutput = "D-09 target: Oracle DB, Altibase, Tibero 등"
$commandExecuted = "guideline_metadata.json D-09 target platform review"

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
