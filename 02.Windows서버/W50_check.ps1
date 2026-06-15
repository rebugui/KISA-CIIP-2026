# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-50
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료
# @Description : 보안 감사 실패 시 시스템 종료 비활성화로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-50"
$ITEM_NAME = "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료"
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

# 1. Check CrashOnAuditFail setting
try {
    $tempFile = Join-Path $env:TEMP "secedit_w50.tmp"

    # Export security policy to temp file
    $null = secedit /export /cfg $tempFile 2>&1

    # NOTE: Get-Content returns a string[] array. Using the -match operator on an
    # array FILTERS the array and does NOT populate $matches, so a scalar must be
    # used to capture the numeric value. Join to a single string before matching.
    $contentText = (Get-Content $tempFile -ErrorAction Stop) -join "`n"
    $crashOnAuditFail = $null

    # Parse CrashOnAuditFail (scalar -match populates $matches)
    if ($contentText -match 'CrashOnAuditFail\s*=\s*(\d+)') {
        $crashOnAuditFail = [int]$matches[1]
    }

    # Clean up temp file
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    if ($null -eq $crashOnAuditFail) {
        # Value not present in policy export -> cannot determine -> MANUAL
        $finalResult = "MANUAL"
        $summary = "CrashOnAuditFail 값을 확인할 수 없음: 수동으로 '보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 정책 확인 필요"
        $status = "수동진단"
        $commandOutput = "CrashOnAuditFail: (정책 항목 없음)"
    } elseif ($crashOnAuditFail -eq 0) {
        # 0 = Disabled (GOOD)
        $finalResult = "GOOD"
        $summary = "'보안감사를로그할수없는경우즉시시스템종료' 정책이 '사용안함'으로 설정됨"
        $status = "양호"
        $commandOutput = "CrashOnAuditFail: $crashOnAuditFail"
    } else {
        # 1 or 2 = Enabled (VULNERABLE)
        $finalResult = "VULNERABLE"
        $summary = "'보안감사를로그할수없는경우즉시시스템종료' 정책이 '사용'으로 설정됨 (CrashOnAuditFail=$crashOnAuditFail)"
        $status = "취약"
        $commandOutput = "CrashOnAuditFail: $crashOnAuditFail"
    }

    $commandExecuted = "secedit /export 및 CrashOnAuditFail 값 확인"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 CrashOnAuditFail 값 확인"
    $commandOutput = "진단 실패: $_"

    # Clean up temp file if it exists
    $tempFile = Join-Path $env:TEMP "secedit_w50.tmp"
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

# 2. lib를 통한 결과 저장
$purpose = "해당 정책을 비활성화함으로써 로그 용량 초과 등의 이유로 이벤트를 기록할 수 없는 경우, 해당 정책으로 인해 시스템이 비정상적으로 종료되는 것을 방지하기 위함"
$threat = "해당 정책이 활성화되어 있는 경우 악의적인 목적으로 시스템 종료를 유발하여 서비스 거부 공격에 악용될 수 있으며, 비정상적인 시스템 종료로 인해 시스템 및 데이터에 손상을 입힐 위험이 존재함"
$criteria_good = '''보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료''정책이''사용 안 함''으로 되어 있는 경우'
$criteria_bad = '''보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료''정책이''사용''으로 되어 있는 경우'
$remediation = '''보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료''정책을''사용 안 함''으로 설정'

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
