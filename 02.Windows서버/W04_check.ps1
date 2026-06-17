

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-04
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : 계정 잠금 임계값 설정 여부 점검으로 공격자의 자유로운 자동화 암호 유추 공격 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-04"
$ITEM_NAME = "계정 잠금 임계값 설정"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check account lockout threshold
try {
    $output = net accounts 2>&1 | Out-String
    $threshold = 0
    $found = $false

    # Try Korean pattern
    if ($output -match '잠금 임계값\s*:\s*(\d+)') {
        $threshold = [int]$matches[1]
        $found = $true
    }
    # Try English pattern
    elseif ($output -match 'Lockout threshold\s*:\s*(\d+)') {
        $threshold = [int]$matches[1]
        $found = $true
    }

    if ($found) {
        if ($threshold -gt 0 -and $threshold -le 5) {
            $finalResult = "GOOD"
            $summary = "계정 잠금 임계값이 5회 이하로 적절히 설정됨 (비밀번호 추측 공격 방지)"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "계정 잠금 임계값이 설정되지 않았거나 5회 초과 (보안 취약, 비밀번호 추측 공격 가능성 높음)"
            $status = "취약"
        }
        $commandOutput = "Lockout Threshold: $threshold"
    } else {
        $finalResult = "MANUAL"
        $summary = "계정 잠금 임계값을 확인할 수 없음 (net accounts 출력에서 Lockout threshold 필드를 파싱하지 못함). 수동 검토 필요."
        $status = "수동진단"
        $commandOutput = "Lockout threshold not found in output"
    }

    $commandExecuted = "net accounts"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "net accounts"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "계정 잠금 임계값을 설정하여 공격자의 자유로운 자동화 암호 유추 공격을 차단하기 위함"
$threat = "공격자는 시스템의 계정 잠금 임계값이 설정되지 않는 경우, 자동화된 방법을 이용하여 모든 사용자 계정에 대해 암호 조합 공격을 자유롭게 시도할 수 있으므로 사용자 계정 정보의 노출 위험이 존재함"
$criteria_good = "계정 잠금 임계값이 5 이하의 값으로 설정된 경우"
$criteria_bad = "계정 잠금 임계값이 5 초과의 값으로 설정된 경우"
$remediation = "계정 잠금 임계값을 5 이하의 값으로 설정"

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
