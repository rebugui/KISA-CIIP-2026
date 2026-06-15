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
    # 본 3개 정책은 '도메인 구성원(Domain member)' 보안 정책이다:
    #   도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상) -> RequireSignOrSeal
    #   도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우)      -> SealSecureChannel
    #   도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우)          -> SignSecureChannel
    # 도메인에 가입되지 않은(standalone) 서버는 보안 채널(Netlogon secure channel) 자체가 없어
    # 위 레지스트리 값이 부재(all-null)하며, 이를 VULNERABLE로 판정하면 오탐이다.
    # 따라서 도메인 가입 여부를 먼저 게이트한다: 비도메인 -> N/A(점검 대상 아님).
    $partOfDomain = $false
    try {
        $partOfDomain = [bool](Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
    } catch {
        # WMI 조회 실패 시 도메인 미가입으로 단정하지 않고, 아래에서 정책 평가로 진행
        $partOfDomain = $true
    }

    if (-not $partOfDomain) {
        $finalResult = "N/A"
        $summary = "도메인에 가입되지 않은(standalone) 서버로, 도메인 구성원 보안 채널 정책은 점검 대상이 아님"
        $status = "N/A"
        $commandExecuted = "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"
        $commandOutput = "PartOfDomain: False (비도메인 구성원 - 보안 채널 정책 미적용 대상)"
    } else {
        # Hive: HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters (1 = enabled).
        $netlogonPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        $params = Get-ItemProperty -Path $netlogonPath -ErrorAction SilentlyContinue
        $requireSignOrSeal = if ($params) { $params.RequireSignOrSeal } else { $null }
        $sealSecureChannel = if ($params) { $params.SealSecureChannel } else { $null }
        $signSecureChannel = if ($params) { $params.SignSecureChannel } else { $null }

        $allSet = ($requireSignOrSeal -eq 1) -and ($sealSecureChannel -eq 1) -and ($signSecureChannel -eq 1)

        if ($allSet) {
            $finalResult = "GOOD"
            $summary = "보안 채널 데이터 디지털 암호화 및 서명 관련 3개 정책이 모두 활성화됨"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "보안 채널 데이터 디지털 암호화 또는 서명 관련 정책 중 일부가 비활성화됨"
            $status = "취약"
        }

        $commandExecuted = "(Get-WmiObject Win32_ComputerSystem).PartOfDomain; Get-ItemProperty '$netlogonPath' (RequireSignOrSeal, SealSecureChannel, SignSecureChannel)"
        $commandOutput = "PartOfDomain: True | RequireSignOrSeal: $requireSignOrSeal, SealSecureChannel: $sealSecureChannel, SignSecureChannel: $signSecureChannel"
    }

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
