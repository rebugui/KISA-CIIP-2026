#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-08"
$ITEM_NAME = "안전한 암호화 알고리즘 사용"
$SEVERITY = "상"

$purpose = "안전한 해시 알고리즘 사용으로 데이터의 기밀성 및 무결성을 보장하고, 사용자 인증을 강화하기 위함"
$threat = "SHA-1이나 MD5와 같은 오래된 알고리즘 사용 시 공격자의 무차별 대입 공격 등으로 비밀번호 유추가 가능하며, 데이터 변조 및 유출의 위험이 존재함"
$criteria_good = "해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
$criteria_bad = "해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우"
$remediation = "SHA-256 이상의 암호화 알고리즘 적용"

$finalResult = "N/A"
$status = "N/A"
$summary = "Cubrid_Windows is not a target platform for D-08 according to docs/guideline_metadata.json."
$commandOutput = "D-08 target: Oracle DB, MSSQL, MySQL, Tibero, PostgreSQL 등"
$commandExecuted = "guideline_metadata.json D-08 target platform review"

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
