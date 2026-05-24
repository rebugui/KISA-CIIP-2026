#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-12"
$ITEM_NAME = "안전한 리스너 비밀번호 설정 및 사용"
$SEVERITY = "상"

$purpose = "Listener의 Owner는 DBA가 아니더라도 Listener를 shutdown시키거나 DB 서버에 임의의 파일을 생성할 수 있으며, 원격에서 LSNRCTL 유틸리티를 사용하여 listener.ora 파일에 대한 변경이 가능하므로 Listener에 비밀번호를 설정하여 비인가자가 이를 수정하지 못하도록하기 위함"
$threat = "Listener에 비밀번호가 설정되지 않았을 경우 DoS, 정보 획득, Listener 프로세스를 중지시킬 수 있는 위험이 존재함"
$criteria_good = "Listener의 비밀번호가 설정된 경우"
$criteria_bad = "Listener의 비밀번호가 설정되어 있지 않은 경우"
$remediation = "Listener 비밀번호 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "Tibero_Windows is not a target platform for D-12 according to docs/guideline_metadata.json."
$commandOutput = "D-12 target: Oracle DB"
$commandExecuted = "guideline_metadata.json D-12 target platform review"

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
