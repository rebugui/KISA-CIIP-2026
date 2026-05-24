# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-39
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 백신 프로그램 업데이트
# @Description : 백신 프로그램 최신 업데이트 유지로 신종 바이러스 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-39"
$ITEM_NAME = "백신 프로그램 업데이트"
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
try {
    $avProducts = Get-WmiObject -Namespace 'root/SecurityCenter2' -Class 'AntiVirusProduct' -ErrorAction SilentlyContinue
    $out = ""

    if ($avProducts) {
        $recentUpdate = $false
        $avInfo = @()

        foreach ($av in $avProducts) {
            $path = $av.pathToSignedProductExe
            if ($path) {
                $file = Get-Item $path -ErrorAction SilentlyContinue
                if ($file) {
                    $days = (New-TimeSpan -Start $file.LastWriteTime).Days
                    $avInfo += "백신: $($av.displayName), 경로: $path, 최근 수정: $($file.LastWriteTime), 경과 일수: ${days}일"

                    if ($days -le 7) {
                        $recentUpdate = $true
                    }
                }
            }
        }

        $out = $avInfo -join "`n"

        if ($recentUpdate) {
            $finalResult = "GOOD"
            $summary = "백신 프로그램의 최신 엔진 업데이트가 설치되어 있음 (최근 7일 이내 업데이트 확인됨)"
            $status = "양호"
        } else {
            $finalResult = "MANUAL"
            $summary = "백신 프로그램 상태를 수동으로 확인 필요 (망 격리 환경의 경우 업데이트 절차 및 적용 방법 수립 여부 확인)"
            $status = "수동진단"
        }
    } else {
        $out = "백신 프로그램 정보를 찾을 수 없음 (SecurityCenter2 WMI 접근 불가 또는 백신 미설치)"
        $finalResult = "MANUAL"
        $summary = "백신 프로그램 상태를 수동으로 확인 필요 (망 격리 환경의 경우 업데이트 절차 및 적용 방법 수립 여부 확인)"
        $status = "수동진단"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $out = $_.Exception.Message
}

# Define guideline variables
$purpose = "백신 프로그램의 최신 업데이트 상태를 유지하기 위함"
$threat = "백신 프로그램이 지속적, 주기적으로 업데이트되지 않으면 계속되는 신종 바이러스의 출현으로 인한 시스템 공격 위험이 존재함"
$criteria_good = "바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우"
$criteria_bad = "바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우"
$remediation = "백신 프로그램 환경 설정 메뉴를 통해 DB 및 엔진의 최신 업데이트를 하도록 설정"

# Save results using lib
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $out `
    -CommandExecuted "Get-WmiObject -Namespace 'root/SecurityCenter2' -Class 'AntiVirusProduct'" `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
