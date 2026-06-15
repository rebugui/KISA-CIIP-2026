# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-15
# @Category    : 웹서비스>2.서비스관리 웹서비스의불필요한스크립트매핑제거
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 웹 서비스의 불필요한 스크립트 매핑 제거
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-15"
$ITEM_NAME = "웹 서비스의 불필요한 스크립트 매핑 제거"
$SEVERITY = "상"

$purpose = "웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함"
$threat = "웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting) 등의 공격 위험이 존재함"
$criteria_good = "불필요한 스크립트 매핑이 존재하지 않는 경우"
$criteria_bad = "불필요한 스크립트 매핑이 존재하는 경우"
$remediation = "불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"

try {
    $finalResult = "N/A"
    $status = "N/A"
    $summary = "Apache for Windows is not a target platform for WEB-15 according to docs/04_웹서비스.md and docs/guideline_metadata.json."
    $commandOutput = "WEB-15 targets Tomcat, IIS, and JEUS. Existing Apache_Linux logic is not migrated because the docs baseline excludes Apache for this item."
    $commandExecuted = "docs/04_웹서비스.md and guideline_metadata.json WEB-15 target platform review"
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "N/A"
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
