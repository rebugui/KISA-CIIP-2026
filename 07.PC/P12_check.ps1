

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-12
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : Windows 자동 로그인 점검
# @Description : Windows 자동 로그인 기능이 비활성화되어 있는지 점검하여 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-12"
$ITEM_NAME = "Windows 자동 로그인 점검"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$command = 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AutoAdminLogon'
$commandResult = cmd /c "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v AutoAdminLogon 2>&1" | Out-String

try {
    $value = Get-ItemProperty -Path $regPath -Name AutoAdminLogon -ErrorAction Stop

    if ($value.AutoAdminLogon -eq 0 -or $value.AutoAdminLogon -eq "") {
        $finalResult = "GOOD"
        $summary = "자동 로그인 설정 안 됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "자동 로그인 설정됨"
        $status = "취약"
    }
} catch {
    # If registry key doesn't exist, it's actually good (no autologon)
    $finalResult = "GOOD"
    $summary = "자동 로그인 설정 안 됨"
    $status = "양호"
}

# 2. Define guideline variables
$purpose = 'Windows 자동 로그인이 비활성화되어 있는지 점검하여 비인가자의 로그인을 방지하고자하기 위함'
$threat = 'Windows 자동 로그인이 활성화되어 있을 때 비인가자가 별도의 로그인 과정을 거치지 않고 계정에 자동으로 로그인할 수 있는 위험이 존재함'
$criteria_good = 'Windows 자동 로그인이 비활성화된 경우'
$criteria_bad = 'Windows 자동 로그인이 활성화된 경우'
$remediation = 'Windows 자동 로그인 비활성화 설정'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandResult.Trim() `
    -CommandExecuted $command `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
