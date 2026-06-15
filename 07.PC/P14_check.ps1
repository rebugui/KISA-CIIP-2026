

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-14
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화
# @Description : 바이러스 백신 프로그램의 실시간 감시 기능 활성화 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-14"
$ITEM_NAME = "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    # Windows Defender 실시간 감시 확인
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

    $realTimeEnabled = $false
    if ($defender -ne $null -and $defender.RealTimeProtectionEnabled -eq $true) {
        $realTimeEnabled = $true
    }

    # 제3자 백신 실시간 감시 확인
    $thirdParty = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue
    $thirdPartyRealTime = $false
    $thirdPartyDetails = ""

    if ($null -ne $thirdParty) {
        foreach ($av in $thirdParty) {
            $avName = $av.displayName
            # productState 비트 플래그 확인
            # SecurityCenter2 productState에서 실시간 보호(ON) 상태는 비트 12-15 (마스크 0x1000)로 표현됨
            # (0x10은 잘못된 마스크였음 — 실제 실시간 보호 활성화 nibble과 무관)
            $stateVal = $av.productState
            if ($null -ne $stateVal) {
                $realTimeBit = ($stateVal -band 0x1000) -ne 0
                if ($realTimeBit) {
                    $thirdPartyRealTime = $true
                    $thirdPartyDetails = "$avName 실시간 감시 활성화 (productState=0x{0:X})" -f [int]$stateVal
                }
            }
        }
    }

    if ($realTimeEnabled) {
        $finalResult = "GOOD"
        $summary = "Windows Defender 백신 실시간 감시 기능 활성화됨"
        $status = "양호"
    } elseif ($thirdPartyRealTime) {
        $finalResult = "GOOD"
        $summary = "제3자 백신 실시간 감시 기능 활성화됨: $thirdPartyDetails"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        if ($null -ne $thirdParty -and !$thirdPartyRealTime) {
            $summary = "제3자 백신 설치되었으나 실시간 감시 비활성화됨"
        } else {
            $summary = "백신 실시간 감시 기능 비활성화됨"
        }
        $status = "취약"
    }

    $commandOutput = $defender | ConvertTo-Json -Compress -ErrorAction SilentlyContinue
    if ($null -eq $commandOutput) {
        $commandOutput = "진단 실패 또는 백신 미설치"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $($_.Exception.Message)"
}

# 2. Define guideline variables
$purpose = '사용자가 인터넷(이동식 저장 매체 포함)을 통해 파일을 다운로드하거나 다운로드 받은 파일을 실행할 경우 백신 프로그램이 악성 코드 감염을 실시간으로 점검하고 있는지 확인하기 위함'
$threat = '백신 프로그램의 실시간 감시 기능이 적용되어 있지 않을 경우, 악성 코드에 대해 실시간 감지가 이루어지지 않아 시스템 사용자가 인터넷(이동식 저장 매체 포함)을 통한 파일 다운로드나 실행 시 악성 코드가 감염될 위험이 존재함'
$criteria_good = '설치된 백신의 실시간 감시 기능이 활성화된 경우'
$criteria_bad = '백신이 설치되어 있지 않거나 실시간 감시 기능이 비활성화된 경우'
$remediation = '바이러스 백신 실시간 감시 기능 설정'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted 'Get-MpComputerStatus' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
