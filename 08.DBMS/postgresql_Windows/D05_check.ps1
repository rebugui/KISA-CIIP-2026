#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-05"
$ITEM_NAME = "비밀번호 재사용에 대한 제약 설정"
$SEVERITY = "중"

$purpose = "비밀번호 재사용 제약 설정 적용 여부를 점검하여 비밀번호 변경 시 이전 비밀번호 재사용을 제약하여 형식적인 비밀번호 변경을 원천적으로 차단하기 위함"
$threat = "비밀번호 재사용 제약 설정이 적용되어 있지 않을 경우 비밀번호 변경 전 사용했던 비밀번호를 재사용함으로써 비인가자의 계정 비밀번호 추측 공격에 대한 시간을 더 많이 허용하여 비밀번호 유출 위험이 증가함"
$criteria_good = "비밀번호 재사용 제한 설정을 적용한 경우"
$criteria_bad = "비밀번호 재사용 제한 설정을 적용하지 않은 경우"
$remediation = "PASSWORD _REUSE _TIME, PASSWORD _REUSE _MAX 파라미터 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "postgresql_Windows is not a target platform for D-05 according to docs/guideline_metadata.json."
$commandOutput = "D-05 target: Oracle DB, Altibase, Tibero 등"
$commandExecuted = "guideline_metadata.json D-05 target platform review"

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
