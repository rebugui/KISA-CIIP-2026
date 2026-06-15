# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-38
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 주기적 보안패치 및 벤더 권고사항 적용으로 시스템 취약성 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-38"
$ITEM_NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"
$SEVERITY = "상"
$CATEGORY = "3.패치관리"

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
# NOTE: The criterion is the establishment of a patch PROCEDURE ("패치 절차를 수립하여
# 주기적으로 패치를 확인 및 설치"). Hotfix recency is not a valid proxy: WSUS/SCCM-managed
# hosts can show stale Get-HotFix entries while fully patched, and recent hotfixes do not
# prove a formal procedure exists. This emits MANUAL with a hotfix inventory as evidence.
try {
    $hotFixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
    $out = ""

    if ($hotFixes) {
        $lastUpdate = $hotFixes[0].InstalledOn
        if ($lastUpdate -is [DateTime]) {
            $lastUpdateStr = $lastUpdate.ToString("yyyy-MM-dd")
        } else {
            $lastUpdateStr = "Unknown"
        }

        $out = "총 $($hotFixes.Count)개의 핫픽스 확인됨`n"
        $out += "최근 패치 날짜: $lastUpdateStr`n"
        $out += "최근 핫픽스 10개:`n"
        for ($i = 0; $i -lt [Math]::Min(10, $hotFixes.Count); $i++) {
            $hf = $hotFixes[$i]
            $out += "  - $($hf.HotFixID) 설치일: $($hf.InstalledOn)`n"
        }
        $summary = "핫픽스 $($hotFixes.Count)개 확인됨 (최근: $lastUpdateStr). 패치 절차 수립 및 주기적 적용 여부는 수동 확인 필요"
    } else {
        $out = "핫픽스 정보를 찾을 수 없음 (WSUS/SCCM 관리 환경일 수 있음)"
        $summary = "핫픽스 정보 확인 불가: 패치 절차 수립 및 주기적 적용 여부 수동 확인 필요"
    }

    $finalResult = "MANUAL"
    $status = "수동진단"
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $out = $_.Exception.Message
}

# Define guideline variables
$purpose = "최신 보안 패치를 설치하여 시스템 및 응용 프로그램의 취약성을 제거하기 위함"
$threat = "최신 보안 패치가 즉시 적용되지 않으면 알려진 취약성으로 인한 시스템 공격 위험이 존재함"
$criteria_good = "패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우"
$criteria_bad = "패치 절차가 수립되어 있지 않거나 주기적으로 패치를 설치하지 않는 경우"
$remediation = "주기적인 보안 패치 확인 및 설치 적용"

# Save results using lib
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $out `
    -CommandExecuted 'Get-HotFix | Sort-Object InstalledOn -Descending' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
