

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

# 1. Check '익명 SID/이름 변환 허용' policy
# 해당 정책은 레지스트리에 기록되지 않고 LSA 보안 정책 DB의 [System Access] 토큰
# LSAAnonymousNameLookup 에만 저장되므로 secedit /export 로 확인한다.
try {
    $tempFile = "$env:TEMP\secedit.tmp"
    secedit /export /cfg $tempFile 2>&1 | Out-Null
    $content = Get-Content $tempFile -ErrorAction SilentlyContinue
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    $value = 0
    $found = $false

    # secedit 내보내기 결과를 얻지 못한 경우(서비스 미동작/권한 부족 등) 정책 판단 불가 -> 수동진단
    # null/빈 내용을 GOOD으로 처리하면 정책 미설정을 '사용 안 함'으로 잘못 단정하는 false-good 발생
    if ($null -eq $content -or @($content).Count -eq 0) {
        $finalResult = "MANUAL"
        $summary = "secedit 정책 내보내기 결과를 얻지 못해 'LSAAnonymousNameLookup' 정책을 확인할 수 없음. 로컬 보안 정책에서 '네트워크 액세스: 익명 SID/이름 변환 허용' 설정을 수동으로 확인 필요"
        $status = "수동진단"
        $commandOutput = "secedit export returned no content (policy undeterminable)"
        $commandExecuted = "secedit /export (LSAAnonymousNameLookup 정책 확인)"
    } else {
        # Try to find LSAAnonymousNameLookup setting
        foreach ($line in $content) {
            if ($line -match 'LSAAnonymousNameLookup\s*=\s*(\d+)') {
                $value = [int]$matches[1]
                $found = $true
                break
            }
        }

        if ($found -and $value -eq 0) {
            $finalResult = "GOOD"
            $summary = "'익명 SID/이름 변환 허용' 정책이 '사용 안 함'으로 설정됨"
            $status = "양호"
            $commandOutput = "LSAAnonymousNameLookup = 0 (Disabled)"
        } elseif ($found -and $value -eq 1) {
            $finalResult = "VULNERABLE"
            $summary = "'익명 SID/이름 변환 허용' 정책이 '사용'으로 설정됨 (보안 위협)"
            $status = "취약"
            $commandOutput = "LSAAnonymousNameLookup = 1 (Enabled)"
        } else {
            # 정책 항목 자체가 export 결과에 없는 경우: 기본값은 '사용 안 함'이나 자동 단정 불가 -> 수동진단
            $finalResult = "MANUAL"
            $summary = "'LSAAnonymousNameLookup' 정책 항목이 secedit 결과에 존재하지 않음. 기본값은 '사용 안 함'이나 정책 적용 여부를 수동으로 확인 필요"
            $status = "수동진단"
            $commandOutput = "LSAAnonymousNameLookup not found in secedit export (verify manually)"
        }

        $commandExecuted = "secedit /export (LSAAnonymousNameLookup 정책 확인)"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "secedit /export"
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
