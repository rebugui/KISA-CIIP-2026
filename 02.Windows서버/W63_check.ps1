# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-63
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 도메인 컨트롤러-사용자의 시간 동기화
# @Description : Kerberos 시간 동기화 설정으로 재전송 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-63"
$ITEM_NAME = "도메인 컨트롤러-사용자의 시간 동기화"
$SEVERITY = "중"
$CATEGORY = "5.보안관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check Kerberos MaxClockSkew setting
try {
    $kerberosPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew' -ErrorAction SilentlyContinue

    if ($kerberosPolicy -and $kerberosPolicy.MaxClockSkew -le 5) {
        $finalResult = "GOOD"
        $summary = "컴퓨터 시계 동기화 최대 허용 오차가 5분 이하로 설정됨"
        $status = "양호"
    } elseif ($kerberosPolicy -and $kerberosPolicy.MaxClockSkew -gt 5) {
        $finalResult = "VULNERABLE"
        $summary = "컴퓨터 시계 동기화 최대 허용 오차가 5분 초과로 설정됨"
        $status = "취약"
    } else {
        $finalResult = "MANUAL"
        $summary = "도메인 컨트롤러가 아니거나 설정 확인 불가능 (수동 진단 필요)"
        $status = "수동진단"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew'"
    $commandOutput = if ($kerberosPolicy) { "MaxClockSkew: $($kerberosPolicy.MaxClockSkew) minutes" } else { "레지스트리 키 없음" }

} catch {
    $finalResult = "MANUAL"
    $summary = "도메인 컨트롤러가 아니거나 설정 확인 불가능 (수동 진단 필요)"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'MaxClockSkew'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "이 설정은 Kerberos가 클라이언트 시계의 시간과 서버 시계의 시간 사이에서 허용되는 최대 시간 차이(분)를 결정하는 동시에 두 시계의 동기를 고려하여, 재전송 공격을 방지하기 위함"
$threat = "Replay Attack 이란 프로토콜 상 메시지를 복사한 후 재전송함으로써 승인된 사용자로 오인하게 만들어 내부 침입 및 정보 유출 위험이 존재함"
$criteria_good = "컴퓨터 시계 동기화 최대 허용 오차 값이 5분 이하인 경우"
$criteria_bad = "컴퓨터 시계 동기화 최대 허용 오차 값이 5분 초과인 경우"
$remediation = "Kerberos 사용 시 컴퓨터 시계 동기화 최대 허용 오차 값 5분 이하로 설정"

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
    -GuidelineRemediation $remediation

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
