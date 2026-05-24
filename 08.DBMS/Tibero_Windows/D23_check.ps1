#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-23"
$ITEM_NAME = "xp_cmdshell 사용 제한"
$SEVERITY = "상"

$purpose = "불필요하게 활성화되어 있는 xp_cmdshell를 제한하여 공격자의 무단 접근 및 악성 코드의 실행 위험을 감소시키기 위함"
$threat = "해킹 툴에서 자주 이용되고 있으며, 권한 상승이나 데이터 유출 등의 위험이 존재함"
$criteria_good = "xp_cmdshell이 비활성화되어 있거나, 활성화되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute)권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
$criteria_bad = "xp_cmdshell이 활성화되어 있고, 양호의 조건을 만족하지 않는 경우"
$remediation = "xp_cmdshell 설정 값을 0 또는 False로 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "Tibero_Windows is not a target platform for D-23 according to docs/guideline_metadata.json."
$commandOutput = "D-23 target: MSSQL"
$commandExecuted = "guideline_metadata.json D-23 target platform review"

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
