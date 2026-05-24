#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "D-17"
$ITEM_NAME = "AuditTable은 데이터베이스 관리자 계정으로 접근하도록 제한"
$SEVERITY = "하"

$purpose = "Audit Table 접근 권한을 관리자 계정으로 제한함으로써 비인가자가 감사 데이터의 수정, 삭제하는 것을 방지하고, 감사 기록 의무 결성과 신뢰성을 보장하기 위함"
$threat = "Audit Table이 데이터베이스 관리자 계정에 속하지 않을 경우, 비인가자가 감사 데이터의 수정, 삭제 등을 수행할 수 있으므로 보안 사고 발생 시 원인 분석이 불가능하게 되며, 이로 인해 재발 방지를 위한 조치를 할 수 없으므로 동일 유형의 공격이 반복되거나 시스템 취약점의 악용이 반복될 위험이 존재함"
$criteria_good = "AuditTable 접근 권한이 관리자 계정으로 설정한 경우"
$criteria_bad = "AuditTable 접근 권한이 일반 계정으로 설정한 경우"
$remediation = "AuditTable 접근 권한을 관리자 계정으로 제한"

$finalResult = "N/A"
$status = "N/A"
$summary = "mysql_Windows is not a target platform for D-17 according to docs/guideline_metadata.json."
$commandOutput = "D-17 target: Oracle DB, Altibase, Tibero 등"
$commandExecuted = "guideline_metadata.json D-17 target platform review"

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
