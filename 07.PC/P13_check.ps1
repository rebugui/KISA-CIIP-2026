

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-13
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 바이러스 백신 프로그램 설치 및 주기적 업데이트
# @Description : 바이러스 백신 프로그램 설치 및 주기적 업데이트 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-13"
$ITEM_NAME = "바이러스 백신 프로그램 설치 및 주기적 업데이트"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $thirdParty = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue

    $hasDefender = $false
    $defenderUpToDate = $false
    $defenderUpdateUnknown = $false

    if ($defender -ne $null) {
        $hasDefender = $true
        if ($defender.AntivirusSignatureLastUpdated -ne $null) {
            $now = Get-Date
            $daysSinceUpdate = ($now - $defender.AntivirusSignatureLastUpdated).Days
            # 가이드라인 기준: KISA PC-13은 "최신 업데이트가 적용된 경우"를 양호로 판정
            # 7일 기준은 일반적인 백신 업데이트 주기(주간 업데이트)를 고려한 보안 권고사항
            # Microsoft, Symantec 등 주요 백신 벤더들은 주간 또는 일일 업데이트 권장
            if ($daysSinceUpdate -le 7) {
                $defenderUpToDate = $true
            }
        } else {
            # 서명 업데이트 시점을 알 수 없음 → 최신성 증명 불가
            $defenderUpdateUnknown = $true
        }
    }

    # PC-13 점검 범위: 백신 "설치" 여부 + "최신 업데이트" 적용 여부
    # (실시간 감시 활성화 여부는 PC-14의 점검 범위이므로 여기서는 판정에 사용하지 않음)
    $hasThirdParty = $false
    if ($thirdParty -ne $null) {
        $hasThirdParty = $true
    }

    if ($hasDefender -and $defenderUpToDate) {
        $finalResult = "GOOD"
        $summary = "Windows Defender 백신 설치 및 업데이트 정상"
        $status = "양호"
    } elseif ($hasThirdParty) {
        # 제3자 백신: 설치는 확인됨. 업데이트 최신 여부를 SecurityCenter2 timestamp로 판정.
        # timestamp가 없으면 업데이트 적용 시점을 증명할 수 없으므로 GOOD이 아니라 MANUAL.
        $thirdPartyUpToDate = $false
        $thirdPartyUnknown = $false
        $thirdPartyDetails = @()
        foreach ($av in $thirdParty) {
            $avName = $av.displayName
            $avTimestamp = $av.timestamp

            if ($null -ne $avTimestamp -and $avTimestamp -ne "") {
                try {
                    $updateDate = [Management.ManagementDateTimeConverter]::ToDateTime($avTimestamp)
                    $daysSince = ((Get-Date) - $updateDate).Days
                    if ($daysSince -le 7) {
                        $thirdPartyUpToDate = $true
                    }
                    $thirdPartyDetails += "$avName (업데이트: $($updateDate.ToString('yyyy-MM-dd')), ${daysSince}일 전)"
                } catch {
                    $thirdPartyUnknown = $true
                    $thirdPartyDetails += "$avName (업데이트 날짜 파싱 불가)"
                }
            } else {
                # timestamp 미제공 → 업데이트 최신성 증명 불가 → 수동진단 (양호로 단정 금지)
                $thirdPartyUnknown = $true
                $thirdPartyDetails += "$avName (업데이트 timestamp 미제공: 최신성 확인 불가)"
            }
        }

        if ($thirdPartyUpToDate) {
            $finalResult = "GOOD"
            $summary = "제3자 백신 설치 및 최신 업데이트 적용됨: $($thirdPartyDetails -join ', ')"
            $status = "양호"
        } elseif ($thirdPartyUnknown) {
            $finalResult = "MANUAL"
            $summary = "제3자 백신 설치 확인됨. 업데이트 최신 여부를 자동 확인 불가하여 수동 확인 필요: $($thirdPartyDetails -join ', ')"
            $status = "수동진단"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "제3자 백신 설치되었으나 업데이트가 오래됨: $($thirdPartyDetails -join ', ')"
            $status = "취약"
        }
    } elseif ($hasDefender -and $defenderUpdateUnknown) {
        # Defender 설치되어 있으나 서명 업데이트 시점 확인 불가 → 수동진단
        $finalResult = "MANUAL"
        $summary = "Windows Defender 설치 확인됨. 서명 업데이트 시점 확인 불가하여 수동 확인 필요"
        $status = "수동진단"
    } elseif ($hasDefender) {
        # Defender 설치되어 있고 서명 업데이트 시점은 확인되나 7일 초과 → 취약
        $finalResult = "VULNERABLE"
        $summary = "Windows Defender 설치되었으나 최신 업데이트 미적용 (마지막 서명 업데이트 ${daysSinceUpdate}일 전)"
        $status = "취약"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "백신 프로그램 미설치"
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
$purpose = '시스템의 백신 설치 여부와 설치된 백신이 주기적으로 업데이트가 되는지 점검하여 악성 코드(바이러스, 웜, 랜섬웨어, 스파이웨어 등)감염에 대해 대비를 하고 있는지 확인하기 위함'
$threat = '백신이 설치되지 않았거나, 백신이 설치되었어도 주기적으로 최신 업데이트가 이루어지지 않았을 경우 악성 코드(바이러스, 웜, 랜섬웨어, 스파이웨어 등)의 감염이 발생하여 시스템의 중요한 파일이나 폴더의 유출 및 삭제가 발생할 위험이 존재함'
$criteria_good = '백신이 설치되어 있고, 최신 업데이트가 적용된 경우'
$criteria_bad = '백신이 설치되어 있지 않거나, 최신 업데이트가 적용되지 않은 경우'
$remediation = '바이러스 백신 설치 및 최신 업데이트 적용'

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
