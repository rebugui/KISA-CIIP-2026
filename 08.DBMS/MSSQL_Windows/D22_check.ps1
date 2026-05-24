#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-22"
$ITEM_NAME = "데이터베이스의 자원 제한 기능을 TRUE로 설정"
$SEVERITY = "하"

$purpose = "RESOURCE _LIMIT 값을 TRUE로 설정하여 자원의 과도한 사용을 방지하여 데이터베이스의 안정성을 보장하고, 효율적인 자원 관리를 수행하기 위함"
$threat = "자원 제한 기능을 TRUE로 설정하지 않을 경우, 특정 사용자가 과도하게 많은 자원을 소비할 수 있으며 이로 인해 시스템에 과부하가 발생할 위험이 존재함"
$criteria_good = "RESOURCE _LIMIT 설정이 TRUE로 되어 있는 경우"
$criteria_bad = "RESOURCE _LIMIT 설정이 FALSE로 되어 있는 경우"
$remediation = "RESOURCE _LIMIT 설정을 TRUE로 설정 변경"

$finalResult = "N/A"
$status = "N/A"
$summary = "MSSQL_Windows is not a target platform for D-22 according to docs/guideline_metadata.json."
$commandOutput = "D-22 target: Oracle DB"
$commandExecuted = "guideline_metadata.json D-22 target platform review"

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
