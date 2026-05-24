#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-06"
$ITEM_NAME = "웹 서비스 상위 디렉터리 접근 제한 설정"
$SEVERITY = "상"

$purpose = "상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
$threat = "상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
$criteria_good = "상위 디렉터리 접근 기능을 제거한 경우"
$criteria_bad = "상위 디렉터리 접근 기능을 제거하지 않은 경우"
$remediation = "상위 디렉터리 접근 기능 제거 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "JEUS_Windows is not a target platform for WEB-06 according to docs/guideline_metadata.json."
$commandOutput = "WEB-06 target: Apache, Tomcat, Nginx, IIS, WebtoB"
$commandExecuted = "guideline_metadata.json WEB-06 target platform review"

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
