# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-55
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 사용자가 프린터 드라이버를 설치할 수 없게 함
# @Description : 프린터 드라이버 설치 제한으로 의도하지 않은 시스템 손상 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-55"
$ITEM_NAME = "사용자가 프린터 드라이버를 설치할 수 없게 함"
$SEVERITY = "중"
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

# 1. Check printer driver installation restriction policy
try {
    $secedit = secedit /export /cfg "$env:TEMP\secedit.tmp" 2>&1
    # NOTE: Get-Content returns a string[] array. Using -match on an array FILTERS
    # the array and does NOT populate $matches. Join to a scalar string first so the
    # captured value in $matches[1] is valid.
    $contentText = (Get-Content "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue) -join "`n"
    $disableAddPrinter = $null

    if ($contentText -match 'DisableAddPrinter\s*=\s*(\d+)') {
        $disableAddPrinter = [int]$matches[1]
    }

    Remove-Item "$env:TEMP\secedit.tmp" -ErrorAction SilentlyContinue

    # DisableAddPrinter: 1 = 사용 (GOOD); 0/기타 = 사용 안 함 (VULNERABLE); 항목 없음 = MANUAL
    if ($null -eq $disableAddPrinter) {
        $finalResult = "MANUAL"
        $summary = "DisableAddPrinter 값을 확인할 수 없음: 수동으로 '사용자가 프린터 드라이버를 설치할 수 없게 함' 정책 확인 필요"
        $status = "수동진단"
        $policyStatus = "정책 항목 없음"
    } elseif ($disableAddPrinter -eq 1) {
        $finalResult = "GOOD"
        $summary = "'사용자가프린터드라이버를설치할수없게함' 정책이 '사용'으로 설정됨"
        $status = "양호"
        $policyStatus = "사용 (Administrators만 설치 가능)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'사용자가프린터드라이버를설치할수없게함' 정책이 '사용안함'으로 설정됨"
        $status = "취약"
        $policyStatus = switch ($disableAddPrinter) {
            0 { "사용안함 (모든 사용자 설치 가능)" }
            default { "알 수 없음 ($disableAddPrinter)" }
        }
    }

    $commandExecuted = "secedit /export 및 DisableAddPrinter 값 확인"
    $commandOutput = "DisableAddPrinter=$disableAddPrinter ($policyStatus)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export 및 DisableAddPrinter 값 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "일반 사용자를 통한 프린터 드라이버 설치를 차단하여 의도하지 않은 시스템 손상을 방지하기 위함"
$threat = "서버에 프린터 드라이버를 설치하는 경우 악의적인 사용자가 고의로 잘못된 프린터 드라이버를 설치하여 컴퓨터를 손상할 수 있으며, 프린터 드라이버로 위장한 악성 코드를 설치할 위험이 존재함"
$criteria_good = '''사용자가 프린터 드라이버를 설치할 수 없게함''정책이''사용''인 경우'
$criteria_bad = '''사용자가 프린터 드라이버를 설치할 수 없게함''정책이''사용 안 함''인 경우'
$remediation = '''사용자가 프린터 드라이버를 설치할 수 없게함''정책을''사용''으로 설정'

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
