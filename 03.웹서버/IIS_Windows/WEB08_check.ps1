# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-08
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 하
# @Title       : 웹 서비스 파일 업로드 및 다운로드 용량 제한
# @Description : Apache 웹 서버의 .htaccess 파일 오버라이드 기능을 제한하여 설정 파일 무결성을 보장합니다. IIS는 Apache의 .htaccess를 사용하지 않으며 web.config를 사용하므로 이 항목은 IIS에 해당하지 않습니다(N/A).
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-08"
$ITEM_NAME = "웹 서비스 파일 업로드 및 다운로드 용량 제한"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS는 Apache .htaccess 사용하지 않음
    $finalResult = "N/A"
    $summary = "이 진단 항목은 Apache 대상이며 IIS는 해당하지 않습니다. IIS에서는 URL Rewrite 및 web.config 사용."
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
$purpose = '기반 시설 시스템은 원칙적으로 파일 업로드 및 다운로드를 금지하지만 불가피하게 파일의 업로드 및 다운로드 기능이 필요한 경우, 파일의 용량 제한을 설정하여 불필요한 업로드 및 다운로드를 방지해 서버의 과부하를 예방하고, 웹 서버 자원을 효율적으로 관리하기 위함'
$threat = '웹 서비스의 파일 업로드 및 다운로드의 용량을 제한하지 않은 경우, 악의적인 목적을 가진 사용자가 반복 업로드 및 웹 쉘 공격 등으로 시스템 권한을 탈취하거나 대용량 파일의 업로드 및 다운로드로 서버 자원을 고갈시켜 서비스 장애를 발생시킬 위험이 존재함'
$criteria_good = '파일 업로드 및 다운로드 용량을 제한한 경우'
$criteria_bad = '파일 업로드 및 다운로드 용량을 제한하지 않은 경우'
$remediation = '파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정'

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
