# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-52
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : Autologon 기능 제어
# @Description : 자동 로그온 기능 비활성화로 시스템 계정 정보 노출 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-52"
$ITEM_NAME = "Autologon 기능 제어"
$SEVERITY = "상"
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

# 1. Check AutoAdminLogon registry value
try {
    $autoAdminLogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue

    if (-not $autoAdminLogon -or $autoAdminLogon.AutoAdminLogon -eq '0' -or $autoAdminLogon.AutoAdminLogon -eq '') {
        $finalResult = "GOOD"
        $summary = "AutoAdminLogon 값이 없거나 0으로 설정됨 (자동 로그온 비활성화)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "AutoAdminLogon 값이 1로 설정됨 (자동 로그온 활성화 위험)"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'"
    $autoAdminLogonValue = if ($autoAdminLogon) { $autoAdminLogon.AutoAdminLogon } else { "없음" }
    $commandOutput = "AutoAdminLogon=$autoAdminLogonValue"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "Autologon 기능을 사용하지 않도록 설정하여 시스템 계정 정보 노출을 차단하기 위함"
$threat = "Autologon 기능을 사용하면 침입자가 해킹 도구를 이용하여 레지스트리에 저장된 로그인 계정 및 비밀번호 정보 유출 위험이 존재함"
$criteria_good = "AutoAdminLogon 값이 없거나 0 으로 설정된 경우"
$criteria_bad = "AutoAdminLogon 값이 1로 설정된 경우"
$remediation = "해당 레지스트리 값이 존재하는 경우 0 으로 설정"

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
