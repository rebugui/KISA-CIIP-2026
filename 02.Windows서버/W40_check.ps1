# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-40
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 정책에 따른 시스템로깅 설정
# @Description : 감사 정책 설정으로 유사시 책임 추적을 위한 로그 확보
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-40"
$ITEM_NAME = "정책에 따른 시스템로깅 설정"
$SEVERITY = "중"
$CATEGORY = "4.로그관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}
Write-Host ""

# 1. Run diagnostic
try {
    # Get audit policy using auditpol command
    $auditOutput = auditpol /get /category:* /r 2>&1
    $out = $auditOutput | Out-String

    # auditpol /r emits a native CSV header:
    #   Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    # Using a custom -Header would replace these native headers and misalign every
    # column (machine name read as Subcategory). Let ConvertFrom-Csv use the native
    # header row instead, and read the documented 'Inclusion Setting' column.
    $auditPolicy = $auditOutput | ConvertFrom-Csv -Delimiter ','
    $out += "`n총 $($auditPolicy.Count)개의 감사 정책 확인됨`n"

    if ($auditPolicy) {
        # Critical audit categories to check (Korean and English)
        $criticalAudits = @(
            '로그온',
            'Logon',
            '계정 관리',
            'Account Management',
            '정책 변경',
            'Policy Change',
            '권한 사용',
            'Privilege Use'
        )

        $allConfigured = $true
        $unconfiguredItems = @()

        # Check each critical audit. The audit state lives in the native
        # 'Inclusion Setting' column ('없음'/'No Auditing' means not configured).
        foreach ($auditKeyword in $criticalAudits) {
            $found = $auditPolicy | Where-Object {
                $_.Subcategory -like "*$auditKeyword*" -and $_.'Inclusion Setting' -ne '없음' -and $_.'Inclusion Setting' -ne 'No Auditing'
            }

            if (-not $found) {
                $allConfigured = $false
                $unconfiguredItems += $auditKeyword
            }
        }

        # Add detailed status to output
        $out += "주요 감사 정책 상태:`n"
        foreach ($auditKeyword in $criticalAudits) {
            $matching = $auditPolicy | Where-Object { $_.Subcategory -like "*$auditKeyword*" }
            if ($matching) {
                foreach ($match in $matching) {
                    $out += "  - $($match.Subcategory): $($match.'Inclusion Setting')`n"
                }
            }
        }

        if ($allConfigured) {
            $finalResult = "GOOD"
            $summary = "감사 정책 권고 기준에 따라 감사 설정이 됨"
            $status = "양호"
        } else {
            $missing = $unconfiguredItems -join ', '
            $finalResult = "VULNERABLE"
            $summary = "감사 정책 권고 기준에 따라 감사 설정이 되어 있지 않음 (미설정 항목: $missing)"
            $status = "취약"
        }
    } else {
        $out = "감사 정책을 확인할 수 없음"
        $finalResult = "MANUAL"
        $summary = "진단 실패: 수동으로 감사 정책 확인 필요"
        $status = "수동진단"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $out = $_.Exception.Message
}

# Define guideline variables
$purpose = "적절한 로깅 설정으로 유사 시 책임 추적을 위한 로그를 확보하기 위함"
$threat = "감사 설정이 구성되어 있지 않거나 감사 설정 수준이 너무 낮은 경우 보안 관련 문제 발생 시 원인을 파악하기 어려우며 법적 대응을 위한 충분한 증거 확보가 어려운 위험이 존재함"
$criteria_good = "감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우"
$criteria_bad = "감사 정책 권고 기준에 따라 감사 설정이 되어 있지 않은 경우"
$remediation = "이벤트에 대한 감사 설정"

# Save results using lib
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $out `
    -CommandExecuted 'auditpol /get /category:*' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
