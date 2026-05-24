

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-11
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 로컬 로그 온 허용
# @Description : 불필요한 계정의 로컬 로그온 허용 여부 점검으로 비인가자의 불법적 시스템 로컬 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-11"
$ITEM_NAME = "로컬 로그 온 허용"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check local logon allowed users
try {
    $right = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp"
    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    $allowedSIDs = @()
    $content | Where-Object { $_ -match 'SeInteractiveLogonRight\s*=\s*(.+)' } | ForEach-Object {
        $values = $Matches[1].Trim()
        $allowedSIDs += $values -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    }

    # Criteria expects only Administrators (S-1-5-32-544) and IUSR/Local Service (S-1-5-19)
    $builtinAllowed = @('*S-1-5-32-544', '*S-1-5-19')
    $extraSIDs = $allowedSIDs | Where-Object { $_ -notin $builtinAllowed -and $_ -notmatch '^\*S-1-5-21' }

    if ($extraSIDs.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "로컬 로그온 허용 정책에 Administrators, IUSR만 존재"
        $status = "양호"
        $commandOutput = "SeInteractiveLogonRight: Built-in groups only ($($allowedSIDs -join ', '))"
    } else {
        $finalResult = "VULNERABLE"
        $extraUsersList = $extraSIDs -join ', '
        $summary = "로컬 로그온 허용 정책에 추가 계정 존재: $extraUsersList"
        $status = "취약"
        $commandOutput = "SeInteractiveLogonRight: $extraUsersList"
    }

    $commandExecuted = "secedit /export (SeInteractiveLogonRight 확인)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "불필요한 계정에 로컬 로그온이 허용될 경우를 찾아 비인가자의 불법적인 시스템 로컬 접근을 차단하고자함"
$threat = "불필요한 사용자에게 로컬 로그온이 허용될 경우 비인가자를 통한 권한 상승을 위한 악성 코드 실행 위험이 존재함"
$criteria_good = "로컬 로그온 허용 정책에 Administrators,IUSR _만 존재하는 경우"
$criteria_bad = "로컬 로그 온 허용 정책에 Administrators,IUSR _외 다른 계정 및 그룹이 존재하는 경우"
$remediation = "Administrators,IUSR _외 다른 계정 및 그룹의 로컬 로그온 제한"

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
