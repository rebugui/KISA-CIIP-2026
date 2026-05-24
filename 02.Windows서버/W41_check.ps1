# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-41
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 및 시각 동기화 설정으로 시스템간 시간 동기화 및 감사 정확성 확보
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-41"
$ITEM_NAME = "NTP 및 시각 동기화 설정"
$SEVERITY = "중"
$CATEGORY = "4.로그관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check if NTP is configured
try {
    $ntpConfigOutput = w32tm /query /configuration 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0 -and $ntpConfigOutput -match 'NtpServer') {
        $finalResult = "GOOD"
        $summary = "NTP 및 시각 동기화가 설정됨"
        $status = "양호"
        $commandOutput = $ntpConfigOutput
    } elseif ($exitCode -eq 0) {
        $finalResult = "VULNERABLE"
        $summary = "NTP 및 시각 동기화가 설정되지 않음"
        $status = "취약"
        $commandOutput = $ntpConfigOutput
    } else {
        $finalResult = "MANUAL"
        $summary = "진단 실패: 수동으로 NTP 설정 확인 필요"
        $status = "수동진단"
        $commandOutput = "진단 실패: $($ntpConfigOutput)"
    }

    $commandExecuted = "w32tm /query /configuration"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "w32tm /query /configuration"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "안전하고 승인된 Windows 시간 서비스 또는 자체 구축한 NTP 서버와 동기화하여 인증 및 감사하기 위함"
$threat = "시스템 간 시각 동기화 미흡으로 보안 사고 및 장애 발생 시 초기 대응이 불가한 위험이 존재함"
$criteria_good = "NTP 및 시각 동기화를 설정한 경우"
$criteria_bad = "NTP 및 시각 동기화를 설정하지 않은 경우"
$remediation = "NTP 및 시각 동기화 설정"

# Save results using lib
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
