# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-51
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : SAM 계정과 공유의 익명 열거 허용 안 함
# @Description : SAM 계정 익명 열거 금지로 악의적인 계정 정보 탈취 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-51"
$ITEM_NAME = "SAM 계정과 공유의 익명 열거 허용 안 함"
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

# 1. Check both network access policies as per KISA guideline:
# 1. "네트워크 액세스: SAM 계정과 공유의 익명 열거 허용 안함" (RestrictAnonymous)
# 2. "네트워크 액세스: SAM 계정의 익명 열거 허용 안함" (RestrictAnonymousSAM)
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    $content = Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue
    $restrictAnonymous = 0
    $restrictAnonymousSAM = 0

    if ($content -match 'RestrictAnonymous\s*=\s*(\d+)') {
        $restrictAnonymous = [int]$matches[1]
    }

    if ($content -match 'RestrictAnonymousSAM\s*=\s*(\d+)') {
        $restrictAnonymousSAM = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    if ($restrictAnonymous -eq 1 -and $restrictAnonymousSAM -eq 1) {
        $finalResult = "GOOD"
        $summary = "'SAM계정과공유의익명열거허용안함' 정책이 '사용'으로 설정됨 (RestrictAnonymous=1, RestrictAnonymousSAM=1)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'SAM계정과공유의익명열거허용안함' 정책이 '사용안함'으로 설정됨 (RestrictAnonymous 또는 RestrictAnonymousSAM이 1이 아님)"
        $status = "취약"
    }

    $commandExecuted = "secedit /export 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous, RestrictAnonymousSAM 확인"
    $commandOutput = "RestrictAnonymous=$restrictAnonymous, RestrictAnonymousSAM=$restrictAnonymousSAM"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous, RestrictAnonymousSAM 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "익명 사용자에 의한 악의적인 계정 정보 탈취를 방지하기 위함"
$threat = "Windows에서는 익명의 사용자가 도메인 계정(사용자, 컴퓨터 및 그룹)과 네트워크 공유 이름의 열거 작업을 수행할 수 있으므로 SAM(보안 계정 관리자) 계정과 공유의 익명 열거가 허용될 경우 악의적인 사용자가 계정 이름 목록을 확인하고 이 정보를 사용하여 암호를 추측하거나 사회 공학적 공격 기법을 수행할 위험이 존재함"
$criteria_good = '''SAM 계정과 공유의 익명 열거 허용 안 함''이''사용''으로 설정된 경우'
$criteria_bad = '''SAM 계정과 공유의 익명 열거 허용 안 함''이''사용 안 함''으로 설정된 경우'
$remediation = "레지스트리 값 또는 로컬 보안 정책 설정"

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
