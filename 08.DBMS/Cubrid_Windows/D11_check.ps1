#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-11"
$ITEM_NAME = "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
$SEVERITY = "상"

$purpose = "시스템 테이블의 일반 사용자 계정 접근 제한 설정 적용 여부를 점검하여 일반 사용자 계정 유출 시 발생할 수 있는 비인가자의 시스템 테이블 접근 위험을 차단하기 위함"
$threat = "시스템 테이블의 일반 사용자 계정 접근 제한 설정이 되어 있지 않을 경우 Object, 사용자, 테이블 및 뷰, 작업 내역 등의 시스템 테이블에 저장된 정보가 누출될 수 있음"
$criteria_good = "시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
$criteria_bad = "시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우"
$remediation = "시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "Cubrid_Windows is not a target platform for D-11 according to docs/guideline_metadata.json."
$commandOutput = "D-11 target: Oracle DB, MSSQL, MySQL, Altibase, Tibero, PostgreSQL 등"
$commandExecuted = "guideline_metadata.json D-11 target platform review"

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
