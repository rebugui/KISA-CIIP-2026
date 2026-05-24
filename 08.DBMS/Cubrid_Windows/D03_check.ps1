#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-03"
$ITEM_NAME = "비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
$SEVERITY = "상"

$purpose = "비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
$threat = "비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
$criteria_good = "기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
$criteria_bad = "기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
$remediation = "기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "Cubrid_Windows is not a target platform for D-03 according to docs/guideline_metadata.json."
$commandOutput = "D-03 target: Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL 등"
$commandExecuted = "guideline_metadata.json D-03 target platform review"

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
