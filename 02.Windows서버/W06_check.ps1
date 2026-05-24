

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-06
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 관리자 그룹에 최소한의 사용자 포함
# @Description : 관리자 그룹에 최소한의 사용자 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-06"
$ITEM_NAME = "관리자 그룹에 최소한의 사용자 포함"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check Administrators group members
try {
    $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $count = ($members | Measure-Object).Count
    $names = ($members | ForEach-Object { $_.Name }) -join ', '

    if ($count -le 1) {
        $finalResult = "GOOD"
        $summary = "Administrators 그룹 구성원이 최소한으로 유지됨 (1명 이하)"
        $status = "양호"
        $commandOutput = "Administrators Group Members ($count): $names"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "Administrators 그룹에 $count명의 구성원 존재: $names (불필요한 관리자 권한 제거 필요)"
        $status = "취약"
        $commandOutput = "Administrators Group Members ($count): $names"
    }

    $commandExecuted = "Get-LocalGroupMember -Group 'Administrators'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalGroupMember -Group 'Administrators'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "관리자 그룹 구성원에 불필요한 사용자의 포함 여부를 점검하여, 관리 권한 사용자를 최소화하고자함"
$threat = "Administrators와 같은 관리자 그룹에 속한 구성원은 컴퓨터 시스템에 대한 완전하고 제한 없는 액세스 권한을 가지므로, 사용자를 관리자 그룹에 포함하면 비인가 사용자에 대한 과도한 관리 권한이 부여되어 내부 정보 유출 위험이 존재함"
$criteria_good = "Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않는 경우"
$criteria_bad = "Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우"
$remediation = "Administrators 그룹에 포함된 불필요한 계정 제거"

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
