# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-28
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 터미널 서비스 암호화 수준 설정
# @Description : 터미널 서비스 암호화 수준 설정 여부 점검으로 통신 데이터 보호
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-28"
$ITEM_NAME = "터미널 서비스 암호화 수준 설정"
$SEVERITY = "중"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    # First check if RDP is actually in use
    $rdpEnabled = $false
    $tsEnabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($tsEnabled -eq 0) {
        $rdpEnabled = $true
    }

    if (-not $rdpEnabled) {
        $finalResult = "GOOD"
        $summary = "원격 데스크톱 서비스를 사용하지 않아 양호"
        $status = "양호"
        $commandOutput = "RDP disabled (fDenyTSConnections != 0)"
        $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'"
    } else {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $encryptionLevel = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).MinEncryptionLevel

        if ($encryptionLevel) {
            $commandOutput = "MinEncryptionLevel: $encryptionLevel"

            # 암호화 수준: 1=Low(56bit), 2=Medium(128bit), 3=High(256bit), 4=FIPS 140-1
            if ($encryptionLevel -ge 2) {
                $finalResult = "GOOD"
                $summary = "RDP 암호화 수준이 Medium(Level 2) 이상으로 설정됨"
                $status = "양호"
            } else {
                $finalResult = "VULNERABLE"
                $encryptionLevelText = if ($encryptionLevel -eq 1) { "Low (56비트)" } elseif ($encryptionLevel -eq 2) { "Medium (128비트)" } else { "Level $encryptionLevel" }
                $summary = "RDP 암호화 수준이 $encryptionLevelText 으로 설정되어 보안 취약"
                $status = "취약"
            }
        } else {
            $finalResult = "MANUAL"
            $summary = "암호화 수준 레지스트리 값 부재 - 유효 정책 수동 확인 필요 (Windows 기본값은 '클라이언트와 호환 가능(중간)'일 수 있음)"
            $status = "수동진단"
            $commandOutput = "레지스트리 값 없음 (MinEncryptionLevel) - RDP 활성화 상태, 유효 암호화 정책 수동 확인 필요"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' (fDenyTSConnections); Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' (MinEncryptionLevel)"

# 2. lib를 통한 결과 저장
$purpose = "원격 데스크톱 서비스 암호화 설정으로 데이터를 암호화하여 클라이언트와 서버 간의 통신에서 전송되는 데이터를 보호하기 위함"
$threat = "서버 접속 시에 낮은 암호화 수준을 적용할 경우 악의적인 사용자에 의해 서버와 클라이언트 간 주고받는 정보가 노출될 위험이 존재함"
$criteria_good = "원격 데스크톱 서비스를 사용하지 않거나 사용 시 암호화 수준을'클라이언트와 호환 가능(중간)' 이상으로 설정한 경우"
$criteria_bad = "원격 데스크톱 서비스를 사용하고 암호화 수준이'낮음'으로 설정한 경우"
$remediation = "원격 데스크톱 서비스의 가동을 '중지' 및 '사용 안 함' 설정을 하거나, 부득이하게 사용할 경우 암호화 수준 설정 적용"

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
