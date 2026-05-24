

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-01
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : Administrator 계정 이름 변경 등 보안성 강화
# @Description : 기본 Administrator 계정 이름을 변경하여 무단 접근 위험 방지 및 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-01"
$ITEM_NAME = "Administrator 계정 이름 변경 등 보안성 강화"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check if Administrator account name is changed
try {
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like "*-500" }

    if ($admin.Name -eq "Administrator") {
        $finalResult = "VULNERABLE"
        $summary = "기본 Administrator 계정 이름 사용 중 (보안 위험)"
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "Administrator 계정 이름이 변경됨"
        $status = "양호"
    }

    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "Admin Name: $($admin.Name)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' }"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "윈도우 기본 관리자 계정인 Administrator의 이름을 변경 또는 보안을 고려한, 잘 알려진 계정을 통한 악의적인 패스워드 추측 공격을 차단하기 위함"
$threat = "일반적으로 관리자 계정으로 잘 알려진 Administrator를 변경하지 않는 경우 악의적인 사용자의 패스워드 추측 공격을 통해 사용 권한 상승의 위험이 있으며, 관리자를 유인하여 침입자의 액세스를 허용하는 악성 코드를 실행할 위험이 존재함 윈도우 최상위 관리자 계정인 Administrator는 기본적으로 삭제하거나 잠글 수 없어 악의적인 사용자의 목표가 될 위험이 존재함"
$criteria_good = "Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우"
$criteria_bad = "Administrator 기본 계정 이름을 변경하지 않거나 단순 비밀번호를 적용한 경우"
$remediation = "Administrator 기본 계정 이름 변경 및 보안성이 있는 비밀번호 설정"

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
