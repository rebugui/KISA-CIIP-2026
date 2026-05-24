# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-26
# @Category    : 웹서비스>4.패치및로그관리
# @Platform    : Tomcat_Windows
# @Severity    : 중
# @Title       : 로그 디렉터리 및 파일 권한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\tomcat_windows_lib.ps1"

$ITEM_ID = "WEB-26"
$ITEM_NAME = "로그 디렉터리 및 파일 권한 설정"
$SEVERITY = "중"

$purpose = "로그 파일에 공격자에게 유용한 정보가 들어 있을 수 있으므로 권한 관리를 통해 비인가자에 의한 정보 유출, 로그 파일의 훼손 및 변조를 방지하기 위함"
$threat = "로그 디렉터리 및 파일에 적절한 권한이 설정되어 있지 않은 경우, 비인가자가 로그 파일에 접근할 수 있으므로 사용자 및 시스템 정보 유출, 로그 파일 조작 등의 공격 위험이 존재함"
$criteria_good = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
$criteria_bad = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"
$remediation = "로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"

try {
    $diagnostic = Invoke-TomcatWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
    $finalResult = $diagnostic.FinalResult
    $status = $diagnostic.Status
    $summary = $diagnostic.Summary
    $commandOutput = $diagnostic.CommandOutput
    $commandExecuted = $diagnostic.CommandExecuted
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: " + $_.Exception.Message
    $commandExecuted = "Tomcat Windows diagnostic discovery"
}
$resultParams = @{
    ItemId = $ITEM_ID
    ItemName = $ITEM_NAME
    Status = $status
    FinalResult = $finalResult
    InspectionSummary = $summary
    CommandResult = $commandOutput
    CommandExecuted = $commandExecuted
    GuidelinePurpose = $purpose
    GuidelineThreat = $threat
    GuidelineCriteriaGood = $criteria_good
    GuidelineCriteriaBad = $criteria_bad
    GuidelineRemediation = $remediation
    ScriptDir = $SCRIPT_DIR
}

Save-DualResult @resultParams

exit 0
