# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-01
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : Default 관리자 계정 명 변경
# @Description : 웹서비스 설치 시 기본적으로 설정된 관리자 계정의 변경 후 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-01"
$ITEM_NAME = "Default 관리자 계정 명 변경"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS는 이 항목이 해당하지 않음 (Tomcat, JEUS 대상)
    $finalResult = "N/A"
    $summary = "이 진단 항목은 Tomcat, JEUS에 적용됩니다. IIS의 경우 Windows 서버 관리자 계정 정책(W-01)을 참고하세요."
    $status = "N/A"
    $commandExecuted = "N/A"
    $commandOutput = "N/A"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "N/A"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '기본 관리자 계정 명과 같은 알려진 계정 명을 유추하기 어려운 계정 명으로 변경 후 사용하여 공격자에 의한 추측 공격 및 무단 접근 등을 방지하고 보안을 강화하기 위함'
$threat = '기본 관리자 계정 명을 변경하지 않고 사용할 경우, 공격자에 의한 계정 및 비밀번호 추측 공격이 가능하고, 이를 통해 불법적인 접근, 데이터 유출, 시스템 장애 등의 보안 사고가 발생할 수 있는 위험이 존재함'
$criteria_good = '관리자 페이지를 사용하지 않거나, 계정 명이 기본 계정 명으로 설정되어 있지 않은 경우'
$criteria_bad = '계정 명이 기본 계정 명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정 명을 사용하는 경우'
$remediation = '기본 관리자 계정 명을 추측하기 어려운 계정 명으로 설정'

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

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
