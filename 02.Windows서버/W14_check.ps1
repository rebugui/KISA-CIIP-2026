

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
    # 원격 데스크톱(RDP) 노출 여부를 먼저 판별한다.
    # RDP가 비활성화된 서버는 원격 접속 표면 자체가 없으므로 'Remote Desktop Users' 그룹이 비어 있어도
    # criteria_bad(원격 접속 전용 계정 부재)에 해당하지 않는다. 이 경우 빈 그룹을 VULNERABLE로 판정하면 오탐이다.
    # 판별 기준:
    #   - fDenyTSConnections (HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server) = 1 -> RDP 연결 거부(비활성)
    #   - TermService(원격 데스크톱 서비스)가 Stopped 이고 StartType 이 Disabled -> RDP 비활성
    $rdpDenied = $false
    try {
        $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $tsProp = Get-ItemProperty -Path $tsPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        if ($null -ne $tsProp -and [int]$tsProp.fDenyTSConnections -eq 1) {
            $rdpDenied = $true
        }
    } catch {
        # 레지스트리 조회 실패는 RDP 상태 미상으로 취급(서비스 상태로 보강 판단)
    }

    $termService = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
    $rdpServiceDisabled = $false
    if ($null -ne $termService) {
        if ($termService.Status -ne 'Running' -and $termService.StartType -eq 'Disabled') {
            $rdpServiceDisabled = $true
        }
    }
    $rdpDisabled = $rdpDenied -or $rdpServiceDisabled
    $rdpStateText = "fDenyTSConnections=$(if ($rdpDenied) { '1' } else { '0/absent' }); TermService=$(if ($null -ne $termService) { "$($termService.Status)/$($termService.StartType)" } else { 'NotInstalled' })"

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

    # 양호: 관리자 계정을 제외한 원격 접속 전용 계정이 1개 이상 존재해야 함.
    # 빈 그룹(members.Count -eq 0)은 관리자 외 별도 원격 접속 계정이 없는 상태이므로 criteria_bad에 해당(취약).
    # 단, RDP가 비활성화된 서버는 원격 접속 표면이 없어 criteria_bad에 해당하지 않으므로 빈 그룹이라도 VULNERABLE로 보지 않는다.
    # 따라서 빈 그룹을 무조건 GOOD으로 처리하던 false-good('-or $members.Count -eq 0')은 복원하지 않는다.
    if ($nonAdminCount -gt 0) {
        $finalResult = "GOOD"
        $summary = "관리자 계정을 제외한 원격 접속 가능한 별도의 계정이 존재함 (관리자 계정과 분리)"
        $status = "양호"
        $commandOutput = "Remote Desktop Users: $($memberNames -join ', ') | RDP 상태: $rdpStateText"
    } elseif ($rdpDisabled) {
        # RDP 비활성: 원격 접속 표면 없음 -> 취약 아님(양호). 빈 그룹은 정상 상태.
        $finalResult = "GOOD"
        $summary = "원격 데스크톱(RDP)이 비활성화되어 원격 접속 표면이 없음 (Remote Desktop Users 그룹이 비어 있어도 취약 아님)"
        $status = "양호"
        $commandOutput = "Remote Desktop Users: $($memberNames -join ', ') (empty) | RDP 비활성: $rdpStateText"
    } else {
        # RDP가 활성화되어 있고 관리자 외 원격 접속 전용 계정이 없음 -> 원래 criteria_bad(취약).
        $finalResult = "VULNERABLE"
        $summary = "원격 데스크톱(RDP)이 활성화되어 있으나 관리자 계정을 제외한 원격 접속 전용 계정이 존재하지 않음"
        $status = "취약"
        $commandOutput = "Remote Desktop Users: $($memberNames -join ', ') (no non-admin account) | RDP 활성: $rdpStateText"
    }

    $commandExecuted = "Get-LocalGroupMember -Group 'Remote Desktop Users'; Get-Service TermService; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections"

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
