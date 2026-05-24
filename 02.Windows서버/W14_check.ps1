

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-14
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : (중) 원격 터미널 접속 가능한 사용자 그룹 제한 개요
# @Description : 원격 터미널 접속 가능 사용자 그룹 제한 여부 점검으로 관리자 계정 분리
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-14"
$ITEM_NAME = "(중) 원격 터미널 접속 가능한 사용자 그룹 제한 개요"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check Remote Desktop Users group members
try {
    $group = Get-LocalGroup -Name "Remote Desktop Users" -ErrorAction Stop
    $members = Get-LocalGroupMember -Group $group -ErrorAction Stop

    $adminCount = 0
    $nonAdminCount = 0
    $memberNames = @()

    foreach ($member in $members) {
        $memberNames += $member.Name
        if ($member.Name -like '*Administrator*') {
            $adminCount++
        } else {
            $nonAdminCount++
        }
    }

    if ($nonAdminCount -gt 0 -or $members.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "원격 터미널 접속 가능한 별도의 계정이 존재하거나 구성된 계정이 없음 (관리자 계정과 분리)"
        $status = "양호"
        $commandOutput = "Remote Desktop Users: $($memberNames -join ', ')"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "원격 터미널 접속 가능한 별도의 계정이 존재하지 않음 (관리자 계정 외 원격 접속 계정 필요)"
        $status = "취약"
        $commandOutput = "Remote Desktop Users: $($memberNames -join ', ') (Only Administrators)"
    }

    $commandExecuted = "Get-LocalGroupMember -Group 'Remote Desktop Users'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalGroupMember -Group 'Remote Desktop Users'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "비인가자의 원격 터미널 접속을 제한하기 위함"
$threat = "원격 터미널의 그룹이나 계정을 제한하지 않으면 임의의 사용자가 원격으로 접속하여 해당 서버에 정보를 변경하거나 정보가 유출될 위험이 존재함"
$criteria_good = "(관리자 계정을 제외한)원격 접속이 가능한 계정을 생성하여 타 사용자의 원격 접속을 제한하고, 원격 접속 사용자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
$criteria_bad = "(관리자 계정을 제외한)원격 접속이 가능한 별도의 계정이 존재하지 않는 경우"
$remediation = "관리자 계정과 이외의 계정을 생성, 권한을 제한 사용 설정"

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
