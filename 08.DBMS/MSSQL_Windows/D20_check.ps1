#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-20"
$ITEM_NAME = "인가되지 않은 Object Owner의 제한"
$SEVERITY = "하"

$purpose = "Object Owner가 비인가자에게 존재하고 있는 경우 중요 데이터에 대한 무단 접근이 가능하여 데이터의 일관성 및 무결성을 해치는 위험이 발생할 수 있으므로 비인가된 계정의 Object Owner를 제한하여 내부 및 외부의 보안 위협을 최소화하기 위함"
$threat = "Object Owner는 SYS, SYSTEM과 같은 데이터베이스 관리자 계정과 응용 프로그램의 관리자 계정에만 존재하여야 하며, 일반 계정이 존재할 경우 공격자가 이를 이용하여 Object의 수정, 삭제가 가능하므로 중요 정보의 유출 및 변경의 위험이 존재함"
$criteria_good = "ObjectOwner가 SYS,SYSTEM, 관리자 계정 등으로 제한된 경우"
$criteria_bad = "ObjectOwner가 일반 사용자에게도 존재하는 경우"
$remediation = "Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "MSSQL_Windows is not a target platform for D-20 according to docs/guideline_metadata.json."
$commandOutput = "D-20 target: Oracle DB, Altibase, Tibero, PostgreSQL 등"
$commandExecuted = "guideline_metadata.json D-20 target platform review"

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
