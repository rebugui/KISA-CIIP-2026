# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-01
# @Category    : 웹서비스>1.계정관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : Default 관리자 계정 명 변경
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-01"
$ITEM_NAME = "Default 관리자 계정 명 변경"
$SEVERITY = "상"

$purpose = "기본 관리자 계정 명과 같은 알려진 계정 명을 유추하기 어려운 계정 명으로 변경 후 사용하여 공격자에 의한 추측 공격 및 무단 접근 등을 방지하고 보안을 강화하기 위함"
$threat = "기본 관리자 계정 명을 변경하지 않고 사용할 경우, 공격자에 의한 계정 및 비밀번호 추측 공격이 가능하고, 이를 통해 불법적인 접근, 데이터 유출, 시스템 장애 등의 보안 사고가 발생할 수 있는 위험이 존재함"
$criteria_good = "관리자 페이지를 사용하지 않거나, 계정 명이 기본 계정 명으로 설정되어 있지 않은 경우"
$criteria_bad = "계정 명이 기본 계정 명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정 명을 사용하는 경우"
$remediation = "기본 관리자 계정 명을 추측하기 어려운 계정 명으로 설정"

try {
    $finalResult = "N/A"
    $status = "N/A"
    $summary = "Apache for Windows is not a target platform for WEB-01 according to docs/guideline_metadata.json."
    $commandOutput = "WEB-01 targets Tomcat and JEUS default administrator console accounts. Apache does not provide a built-in default web administrator account for this guideline item."
    $commandExecuted = "guideline_metadata.json WEB-01 target platform review"
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
