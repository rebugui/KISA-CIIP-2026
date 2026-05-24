#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-18"
$ITEM_NAME = "응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
$SEVERITY = "상"

$purpose = "응용 프로그램 또는 DBA 계정의 Role을 점검하여 일반 계정으로 응용 프로그램 테이블이나 DBA 테이블의 접근을 차단하기 위함"
$threat = "응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정된 경우 일반 계정에서도 응용 프로그램 테이블 및 DBA 테이블로 접근할 수 있으므로 중요 정보 유출의 위험이 존재함"
$criteria_good = "DBA 계정의 Role이 Public으로 설정되지 않은 경우"
$criteria_bad = "DBA 계정의 Role이 Public으로 설정된 경우"
$remediation = "DBA 계정의 Role 설정에서 Public 그룹 권한 취소"

$finalResult = "N/A"
$status = "N/A"
$summary = "mysql_Windows is not a target platform for D-18 according to docs/guideline_metadata.json."
$commandOutput = "D-18 target: Oracle DB, Altibase, Tibero, Cubrid 등"
$commandExecuted = "guideline_metadata.json D-18 target platform review"

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
