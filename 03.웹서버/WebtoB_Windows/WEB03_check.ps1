#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-03"
$ITEM_NAME = "비밀번호 파일 권한 관리"
$SEVERITY = "상"

$purpose = "비밀번호 파일의 접근 권한을 적절하게 설정하여 비인가자가 비밀번호 파일에 무단 접근 및 유출 등을 방지하기 위함"
$threat = "비밀번호 파일의 권한을 적절하게 설정하지 않은 경우, 비인가자에게 비밀번호 정보가 노출될 수 있고 웹 서버에 접속하는 등의 침해 사고가 발생할 위험이 존재함"
$criteria_good = "비밀번호 파일에 권한이 600 이하로 설정된 경우"
$criteria_bad = "비밀번호 파일에 권한이 600 초과로 설정된 경우"
$remediation = "비밀번호 파일 권한 600 이하로 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "WebtoB_Windows is not a target platform for WEB-03 according to docs/guideline_metadata.json."
$commandOutput = "WEB-03 target: Tomcat, IIS, JEUS"
$commandExecuted = "guideline_metadata.json WEB-03 target platform review"

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
