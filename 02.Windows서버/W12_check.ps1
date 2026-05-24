

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-12
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 익명 SID/ 이름 변환 허용 해제
# @Description : 익명 SID/이름 변환 정책 적용 여부 점검으로 Administrator 이름 찾기 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-12"
$ITEM_NAME = "익명 SID/ 이름 변환 허용 해제"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check AllowAnonymousLookup policy
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).AllowAnonymousLookup

    if ($null -eq $value -or $value -eq 0) {
        $finalResult = "GOOD"
        $summary = "'익명 SID/이름 변환 허용' 정책이 '사용 안 함'으로 설정됨"
        $status = "양호"
        $commandOutput = "AllowAnonymousLookup = 0 (Disabled)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'익명 SID/이름 변환 허용' 정책이 '사용'으로 설정됨 (보안 위협)"
        $status = "취약"
        $commandOutput = "AllowAnonymousLookup = $value (Enabled)"
    }

    $commandExecuted = "Get-ItemProperty -Path '$path'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty -Path '$path'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "익명 SID/ 이름 변환 정책을 '사용 안 함'으로 설정하여, SID(보안 식별자)를 사용하여 관리자 이름을 찾을 수 없도록하기 위함"
$threat = '해당 정책이 ''사용함''으로 설정될 경우 로컬 접근 권한이 있는 사용자가 잘 알려진 Administrator SID를 사용하여 Administrator 계정의 실제 이름을 알아낼 수 있으며 암호 추측 공격 위험이 존재함'
$criteria_good = '''익명 SID/ 이름 변환 허용''정책이''사용 안 함''으로 설정된 경우'
$criteria_bad = '''익명 SID/ 이름 변환 허용''정책이''사용''으로 설정된 경우'
$remediation = '''네트워크 액세스: 익명 SID/ 이름 변환 허용''정책''사용 안 함''설정'

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
