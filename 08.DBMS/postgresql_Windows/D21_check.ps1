#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-21"
$ITEM_NAME = "인가되지 않은 GRANTOPTION 사용 제한"
$SEVERITY = "중"

$purpose = "GRANTOPTION을 ROLE에 의해 설정하여 권한의 남용을 방지하고, 안정성을 확보하기 위함"
$threat = "일반 사용자에게 GRANT OPTION이 부여된 경우, 일반 사용자가 Object 소유자인 것과 같이 다른 일반 사용자에게 권한을 부여할 수 있어 권한의 무분별한 확산으로 인한 중요 정보의 유출 등의 위험이 존재함"
$criteria_good = "WITH _GRANT _OPTION이 ROLE에 의하여 설정된 경우"
$criteria_bad = "WITH _GRANT _OPTION이 ROLE에 의하여 설정되지 않은 경우"
$remediation = "WITH _GRANT _OPTION이 ROLE에 의하여 설정되도록 변경"

$finalResult = "N/A"
$status = "N/A"
$summary = "postgresql_Windows is not a target platform for D-21 according to docs/guideline_metadata.json."
$commandOutput = "D-21 target: Oracle DB, MySQL, Altibase, Tibero 등"
$commandExecuted = "guideline_metadata.json D-21 target platform review"

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
