#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-18"
$ITEM_NAME = "웹 서비스 WebDAV 비활성화"
$SEVERITY = "상"

$purpose = "WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
$threat = "WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
$criteria_good = "WebDAV 서비스를 비활성화하고 있는 경우"
$criteria_bad = "WebDAV 서비스를 활성화하고 있는 경우"
$remediation = "WebDAV 서비스 비활성화 설정"

$finalResult = "N/A"
$status = "N/A"
$summary = "Tomcat_Windows is not a target platform for WEB-18 according to docs/guideline_metadata.json."
$commandOutput = "WEB-18 target: Apache, Nginx, IIS, WebtoB"
$commandExecuted = "guideline_metadata.json WEB-18 target platform review"

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
