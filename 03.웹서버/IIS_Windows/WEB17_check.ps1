#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-17"
$ITEM_NAME = "웹 서비스 가상 디렉터리 삭제"
$SEVERITY = "중"

$purpose = "불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
$threat = "불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
$criteria_good = "불필요한 가상 디렉터리가 존재하지 않는 경우"
$criteria_bad = "불필요한 가상 디렉터리가 존재하는 경우"
$remediation = "불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "IIS_Windows is not a target platform for WEB-17 according to docs/guideline_metadata.json."
$commandOutput = "WEB-17 target: Apache, Tomcat, Nginx, WebtoB"
$commandExecuted = "guideline_metadata.json WEB-17 target platform review"

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
