# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-49
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 원격 시스템에서 강제로 시스템 종료
# @Description : 원격 시스템 강제 종료 권한 제한으로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-49"
$ITEM_NAME = "원격 시스템에서 강제로 시스템 종료"
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

# 1. Check remote shutdown privilege
try {
    $tempFile = Join-Path $env:TEMP "secedit_w49.tmp"

    # Export security policy to temp file
    $null = secedit /export /cfg $tempFile 2>&1

    # NOTE: Get-Content returns a string[] array. Using the -match operator on an
    # array FILTERS the array and does NOT populate $matches, so a scalar must be
    # used to capture the privilege value. Join to a single string before matching.
    $contentText = (Get-Content $tempFile -ErrorAction Stop) -join "`n"
    $remoteShutdown = 0
    $privilege = $null

    # Parse SeRemoteShutdownPrivilege (scalar -match populates $matches)
    if ($contentText -match 'SeRemoteShutdownPrivilege\s*=\s*(.*)') {
        $privilege = $matches[1].Trim()

        # Check if only Administrators (S-1-5-32-544) have this privilege
        # Format can be: *S-1-5-32-544 or S-1-5-32-544
        if ($privilege -eq '*S-1-5-32-544' -or $privilege -eq 'S-1-5-32-544') {
            $remoteShutdown = 1
        }
    }

    # Clean up temp file
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    if ($null -eq $privilege) {
        # SeRemoteShutdownPrivilege line not present in secedit export -> cannot
        # judge statically; route to manual diagnosis rather than VULNERABLE.
        $output = "SeRemoteShutdownPrivilege: (정책 항목 없음)"
        $finalResult = "MANUAL"
        $summary = "SeRemoteShutdownPrivilege 항목을 확인할 수 없어 수동 확인 필요"
        $status = "수동진단"
    } elseif ($remoteShutdown -eq 1) {
        $output = "SeRemoteShutdownPrivilege: $privilege"
        $finalResult = "GOOD"
        $summary = "'원격시스템에서강제로시스템종료' 정책에 'Administrators'만 존재함"
        $status = "양호"
    } else {
        $output = "SeRemoteShutdownPrivilege: $privilege"
        $finalResult = "VULNERABLE"
        $summary = "'원격시스템에서강제로시스템종료' 정책에 'Administrators' 외 다른 계정 및 그룹이 존재함"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 SeRemoteShutdownPrivilege 값 확인"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 SeRemoteShutdownPrivilege 값 확인"
    $commandOutput = "진단 실패: $_"

    # Clean up temp file if it exists
    $tempFile = Join-Path $env:TEMP "secedit_w49.tmp"
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

# 2. lib를 통한 결과 저장
$purpose = "원격에서 네트워크를 통하여 운영 체제를 종료할 수 있는 사용자나 그룹을 설정하여 특정 사용자만 시스템 종료를 허용하기 위함"
$threat = "원격 시스템 강제 종료 설정이 부적절한 경우 서비스 거부 공격 등에 악용될 위험이 존재함"
$criteria_good = '''원격 시스템에서 강제로 시스템 종료''정책에''Administrators''만 존재하는 경우'
$criteria_bad = '''원격 시스템에서 강제로 시스템 종료''정책에''Administrators''외 다른 계정 및 그룹이 존재하는 경우'
$remediation = '''원격 시스템에서 강제로 시스템 종료''정책에''Administrators''외 다른 계정 및 그룹 제거'

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
