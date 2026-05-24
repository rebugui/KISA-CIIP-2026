

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-02
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호의 최소 길이를 8자 이상으로 설정하고 암호 복잡성 정책을 적용하여 비밀번호 추측 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-02"
$ITEM_NAME = "비밀번호 관리 정책 설정"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = "net accounts; reg query `"HKLM\SYSTEM\CurrentControlSet\Control\Lsa`" /v PasswordComplexity"
$commandOutput = ""
try {
    # Check minimum password length
    $out = net accounts 2>&1 | Out-String
    $commandOutput = $out
    $minLength = 0
    $found = $false
    $issues = @()

    if ($out -match 'Minimum password length') {
        if ($out -match 'Minimum password length\s*:\s*(\d+)') {
            $minLength = [int]$matches[1]
            $found = $true
        }
    } elseif ($out -match '최소 암호 길이') {
        if ($out -match '최소 암호 길이\s*:\s*(\d+)') {
            $minLength = [int]$matches[1]
            $found = $true
        }
    }

    if ($minLength -lt 8) {
        $issues += "최소 암호 길이가 8자 미만임 (현재: ${minLength}자)"
    }

    # Check password complexity policy
    $complexityCheck = $false
    try {
        $complexityOutput = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity 2>&1 | Out-String
        $commandOutput += "`n`n" + $complexityOutput

        if ($complexityOutput -match 'PasswordComplexity\s+REG_DWORD\s+0x1') {
            $complexityCheck = $true
        } elseif ($complexityOutput -match 'PasswordComplexity\s+REG_DWORD\s+0x0') {
            $issues += "암호 복잡성 정책 비활성화됨"
        } else {
            $issues += "암호 복잡성 정책 설정 확인 불가 (레지스트리 값 없음)"
        }
    } catch {
        $issues += "암호 복잡성 정책 확인 실패: $_"
    }

    # Final judgment
    if ($issues.Count -eq 0 -and $minLength -ge 8 -and $complexityCheck) {
        $finalResult = "GOOD"
        $summary = "최소 암호 길이 8자 이상 및 암호 복잡성 정책 활성화됨"
        $status = "양호"
    } elseif ($issues.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "암호 정책 미준수: " + ($issues -join ", ")
        $status = "취약"
    } else {
        $finalResult = "MANUAL"
        $summary = "일부 정책 확인 불가: 수동 확인 필요"
        $status = "수동진단"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '안전한 비밀번호 (*비밀번호 설정 기준 참고)를 사용함으로써 무차별 대입 공격, 사전 공격 등 비밀번호 탈취 목적의 공격에 대해 대비하기 위함'
$threat = '주기적으로 보안 패치를 적용하지 않을 경우, 버전 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고가 발생할 수 있는 위험이 존재함'
$criteria_good = '복잡성을 만족하는 비밀번호 정책이 설정된 경우'
$criteria_bad = '비밀번호를 사용하지 않거나, 추측하기 쉬운 문자 조합으로 이루어진 짧은 자릿수의 비밀번호를 설정된 경우'
$remediation = '비밀번호 정책을 해당 기관의 보안 정책에 적합하게 설정'

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
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
