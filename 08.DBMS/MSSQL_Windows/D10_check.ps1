#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-10"
$ITEM_NAME = "원격에서 DB 서버로의 접속 제한"
$SEVERITY = "상"

$purpose = "지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검하여 비인가자의 DB 서버 접근을 원천적으로 차단하고자함"
$threat = "DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부 망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함"
$criteria_good = "DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우"
$criteria_bad = "DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우"
$remediation = "DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "MSSQL_Windows is not a target platform for D-10 according to docs/guideline_metadata.json."
$commandOutput = "D-10 target: Windows OS, Oracle DB, MySQL, Altibase, Tibero, PostgreSQL 등"
$commandExecuted = "guideline_metadata.json D-10 target platform review"

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
