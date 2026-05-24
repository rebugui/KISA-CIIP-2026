

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-05
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 해독 가능한 암호화를 사용하여 암호 저장 해제
# @Description : 해독 가능한 암호화 사용 여부 점검으로 비밀번호 평문 저장 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-05"
$ITEM_NAME = "해독 가능한 암호화를 사용하여 암호 저장 해제"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check reversible encryption password storage
try {
    $tempFile = "$env:TEMP\secedit.tmp"
    secedit /export /cfg $tempFile 2>&1 | Out-Null
    $content = Get-Content $tempFile -ErrorAction SilentlyContinue
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    $value = 0
    $found = $false

    # Try to find ClearTextPassword setting
    foreach ($line in $content) {
        if ($line -match 'ClearTextPassword\s*=\s*(\d+)') {
            $value = [int]$matches[1]
            $found = $true
            break
        }
    }

    if ($found -and $value -eq 0) {
        $finalResult = "GOOD"
        $summary = "해독 가능한 암호화를 사용하여 암호 저장 정책이 '사용 안 함'으로 설정됨"
        $status = "양호"
        $commandOutput = "ClearTextPassword = 0 (Disabled)"
    } elseif ($found -and $value -eq 1) {
        $finalResult = "VULNERABLE"
        $summary = "해독 가능한 암호화를 사용하여 암호 저장 정책이 '사용'으로 설정됨 (보안 심각 위협)"
        $status = "취약"
        $commandOutput = "ClearTextPassword = 1 (Enabled)"
    } else {
        $finalResult = "GOOD"
        $summary = "정책을 찾을 수 없음 (기본값 '사용 안 함'으로 간주)"
        $status = "양호"
        $commandOutput = "ClearTextPassword not found (assumed disabled)"
    }

    $commandExecuted = "secedit /export (ClearTextPassword 정책 확인)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '''해독 가능한 암호화를 사용하여 암호 저장'' 정책이 설정되어 사용자 계정 비밀번호가 해독 가능한 텍스트 형태로 저장되는 것을 차단하기 위함'
$threat = "위 정책이 설정된 경우 운영 체제에서 사용자 계정, 비밀번호를 입력받아 인증을 진행하는 응용 프로그램 프로토콜 지원 시 운영 체제는 사용자의 비밀번호를 해독 가능한 방식으로 저장하기 때문에, 노출된 계정에 대해 공격자가 비밀번호 복호화 공격으로 비밀번호를 획득하여 네트워크 리소스에 접근할 위험이 존재함"
$criteria_good = '''해독 가능한 암호화를 사용하여 암호 저장''정책이''사용 안 함''으로 설정된 경우'
$criteria_bad = '''해독 가능한 암호화를 사용하여 암호 저장''정책이''사용''으로 설정된 경우'
$remediation = '''해독 가능한 암호화를 사용하여 암호 저장''을''사용 안 함''으로 설정'

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
