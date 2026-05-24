

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-05-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-03
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 복구 콘솔에서 자동 로그 온을 금지하도록 설정
# @Description : 시스템 복구 시 자동 로그온을 금지하여 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-03"
$ITEM_NAME = "복구 콘솔에서 자동 로그 온을 금지하도록 설정"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v SecurityLevel'
$commandOutput = ""
try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    $regName = 'SecurityLevel'
    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    if ($null -eq $value -or $value.PSObject.Properties.Name -notcontains $regName) {
        $finalResult = "GOOD"
        $summary = "복구 콘솔 자동 관리자 로그온 허용 설정값 없음 (기본값: 자동 로그온 금지)"
        $status = "양호"
        $commandOutput = "SecurityLevel : Not set (default: automatic administrative logon disabled)"
    } else {
        $securityLevel = [int]$value.SecurityLevel
        $commandOutput = "SecurityLevel : $securityLevel"

        if ($securityLevel -eq 0) {
            $finalResult = "GOOD"
            $summary = "복구 콘솔 자동 관리자 로그온 금지 설정됨 (SecurityLevel = 0)"
            $status = "양호"
        } elseif ($securityLevel -eq 1) {
            $finalResult = "VULNERABLE"
            $summary = "복구 콘솔 자동 관리자 로그온 허용됨 (SecurityLevel = 1)"
            $status = "취약"
        } else {
            $finalResult = "MANUAL"
            $summary = "복구 콘솔 SecurityLevel 값이 예상 범위를 벗어남 ($securityLevel): 수동 확인 필요"
            $status = "수동진단"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "복구 콘솔 자동 관리자 로그온 설정 조회 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '복구 콘솔 자동 로그온 허용을''사용 안 함''으로 설정함으로써 비인가자의 복구 콘솔을 통한 관리자 권한 탈취 등의 위험을 방지하기 위함'
$threat = 'Windows 복구 콘솔(Recovery Console) 자동 로그온 설정은 시스템 액세스 허가 전 Administrator 계정의 비밀번호 제공 여부를 결정하는 것으로 이 옵션을 사용하면 비인가자도 복구 콘솔을 이용해 관리자 권한으로 시스템에 자동으로 로그온할 수 있는 위험이 존재함'
$criteria_good = '복구 콘솔 자동 로그온 허용이''사용 안 함''으로 설정된 경우'
$criteria_bad = '복구 콘솔 자동 로그 온 허용이''사용''으로 설정된 경우'
$remediation = '복구 콘솔 자동 로그온 허용''사용 안 함''으로 설정'

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
