# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-36
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 원격 터미널 접속 타임 아웃 설정
# @Description : 원격 터미널 접속 Timeout 설정으로 비인가자의 불필요한 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-36"
$ITEM_NAME = "원격 터미널 접속 타임 아웃 설정"
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
Write-Host ""

# 1. Run diagnostic
try {
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $userPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    $maxIdleTime = $null
    $minutes = 0
    $out = ""

    # Check policy path first
    $policyProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($policyProps -and $policyProps.MaxIdleTime) {
        $maxIdleTime = $policyProps.MaxIdleTime
        $minutes = $maxIdleTime / 60000
        $out = "Policy MaxIdleTime: $maxIdleTime ($minutes minutes)"
    }

    # If not found in policy, check user path
    if (-not $maxIdleTime) {
        $userProps = Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue
        if ($userProps -and $userProps.UserTimeout) {
            $maxIdleTime = $userProps.UserTimeout
            $minutes = $maxIdleTime / 60000
            $out = "UserTimeout: $maxIdleTime ($minutes minutes)"
        }
    }

    # Evaluate result
    if ($minutes -gt 0 -and $minutes -le 30) {
        $finalResult = "GOOD"
        $summary = "원격 터미널 접속 Timeout이 30분 이하로 설정됨"
        $status = "양호"
    } elseif ($minutes -gt 30) {
        $finalResult = "VULNERABLE"
        $summary = "원격 터미널 접속 Timeout이 30분 초과로 설정됨"
        $status = "취약"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "원격 터미널 접속 Timeout이 설정되지 않음"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $out = $_.Exception.Message
}

# Define guideline variables
$purpose = "조직에서 부득이 원격 터미널 접속을 허용해야할 경우, 원격 터미널 접속 후 일정 시간 동안 이벤트가 발생하지 않은 호스트의 접속을 차단하여 비인가자의 불필요한 접근을 차단하고 정보의 노출을 방지하기 위함"
$threat = "접속 Timeout 값이 설정되지 않으면 유휴 시간 내 비인가자의 시스템 접근으로 인해 불필요한 내부 정보의 노출 위험이 존재함"
$criteria_good = "원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우"
$criteria_bad = "원격 제어 시 Timeout 제어 설정을 적용하지 않거나 30분 초과로 설정한 경우"
$remediation = "Timeout 제어 설정 적용"

# Save results using lib
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $out `
    -CommandExecuted "Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'" `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
