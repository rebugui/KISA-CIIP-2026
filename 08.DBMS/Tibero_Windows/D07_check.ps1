#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-07"
$ITEM_NAME = "root 권한으로 서비스 구동 제한"
$SEVERITY = "중"

$purpose = "root 권한을 제한적으로 사용함으로써 시스템의 손상, 데이터의 유출 및 변조 등을 차단하여 보안 위협을 방지하기 위함"
$threat = "root 권한으로 서비스를 구동할 경우 시스템 손상, 데이터 유출 및 변조, 감사 및 추적의 어려움 등으로 인해 서비스 공격의 표적이 될 위험이 존재함"
$criteria_good = "DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
$criteria_bad = "DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우"
$remediation = "DBMS 구동 계정 변경"

$finalResult = "N/A"
$status = "N/A"
$summary = "Tibero_Windows is not a target platform for D-07 according to docs/guideline_metadata.json."
$commandOutput = "D-07 target: Oracle DB, MySQL, Altibase, Cubrid 등"
$commandExecuted = "guideline_metadata.json D-07 target platform review"

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
