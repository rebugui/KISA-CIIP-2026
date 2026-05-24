

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-02
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : Guest 계정 비활성화
# @Description : Guest 계정 비활성화로 무단 로그인 접근 방지 및 시스템 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-02"
$ITEM_NAME = "Guest 계정 비활성화"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check Guest account status
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

    if ($guest) {
        if ($guest.Enabled) {
            $finalResult = "VULNERABLE"
            $summary = "Guest 계정이 활성화됨 (보안 위험)"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "Guest 계정이 비활성화됨"
            $status = "양호"
        }
        $commandOutput = "Guest Account Enabled: $($guest.Enabled)"
    } else {
        $finalResult = "GOOD"
        $summary = "Guest 계정이 존재하지 않음"
        $status = "양호"
        $commandOutput = "Guest account not found"
    }

    $commandExecuted = "Get-LocalUser -Name 'Guest'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser -Name 'Guest'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "Guest 계정을 비활성화하여 불특정 다수의 임시적인 시스템 접근을 차단하기 위함"
$threat = "Guest 계정은 시스템에 임시로 액세스해야 하는 사용자용 계정으로, 해당 계정을 사용하여 권한 없는 사용자가 시스템에 익명으로 액세스할 수 있으므로 비인가자 접근, 정보 유출 등 보안 위험이 존재함"
$criteria_good = "Guest 계정이 비활성화되어 있는 경우"
$criteria_bad = "Guest 계정이 활성화되어 있는 경우"
$remediation = "Guest 계정 비활성화"

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
