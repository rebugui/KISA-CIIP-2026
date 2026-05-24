#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-19"
$ITEM_NAME = "웹 서비스 SSI(Server Side Includes)사용 제한"
$SEVERITY = "중"

$purpose = "웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함"
$threat = "웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함"
$criteria_good = "웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
$criteria_bad = "웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
$remediation = "웹 서비스 내 불필요한 SSI 사용 제한 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "JEUS_Windows is not a target platform for WEB-19 according to docs/guideline_metadata.json."
$commandOutput = "WEB-19 target: Apache, Tomcat, Nginx, IIS, WebtoB"
$commandExecuted = "guideline_metadata.json WEB-19 target platform review"

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
