# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-60
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 보안 채널 데이터 디지털 암호화 또는 서명
# @Description : 보안 채널 데이터 암호화 및 서명으로 인증 트래픽 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-60"
$ITEM_NAME = "보안 채널 데이터 디지털 암호화 또는 서명"
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

# 1. Check secure channel data encryption or signing
try {
    $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $requireSignOrSeal = if ($lsa) { $lsa.RequireSignOrSeal } else { 0 }
    $requireSignOrSeal2 = if ($lsa) { $lsa.RequireSignOrSeal2 } else { 0 }
    $sealSecureChannel = if ($lsa) { $lsa.SealSecureChannel } else { 0 }
    $allSet = ($requireSignOrSeal -eq 1) -and ($requireSignOrSeal2 -ge 1) -and ($sealSecureChannel -ge 1)

    if ($allSet) {
        $finalResult = "GOOD"
        $summary = "보안 채널 데이터 디지털 암호화 및 서명이 활성화됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "보안 채널 데이터 디지털 암호화 또는 서명이 비활성화됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' (RequireSignOrSeal, RequireSignOrSeal2, SealSecureChannel)"
    $commandOutput = "RequireSignOrSeal: $requireSignOrSeal, RequireSignOrSeal2: $requireSignOrSeal2, SealSecureChannel: $sealSecureChannel"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' (RequireSignOrSeal, RequireSignOrSeal2, SealSecureChannel)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "해당 정책을 활성화하여 보안 채널의 서명 또는 암호화를 협상하지 않는 한 보안 채널을 확립하지 않기 위함"
$threat = "보안 채널이 암호화되지 않으면 인증 트래픽 끼어들기 공격, 반복 공격 및 기타 유형의 네트워크 공격 등의 위험이 존재함"
$criteria_good = "아래 3가지 정책 모두'사용`"으로 되어 있는 경우 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우) 도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)"
$criteria_bad = "아래 3가지 정책 중 일부가`"사용 안 함`"으로 되어 있는 경우 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우) 도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)"
$remediation = "보안 채널 데이터를 디지털 암호화· 서명 관련 3개 정책 →사용"

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
