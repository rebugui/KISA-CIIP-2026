

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-15
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : OS에서 제공하는 침입 차단 기능 활성화
# @Description : OS에서 제공하는 침입 차단 기능이 활성화되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-15"
$ITEM_NAME = "OS에서 제공하는 침입 차단 기능 활성화"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    # Windows 방화벽 확인
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

    $windowsFirewallEnabled = $false
    if ($null -ne $profiles) {
        $allEnabled = $true
        foreach ($profile in $profiles) {
            if ($profile.Enabled -eq $false) {
                $allEnabled = $false
                break
            }
        }
        if ($allEnabled) {
            $windowsFirewallEnabled = $true
        }
    }

    # 제3자 방화벽 확인
    $thirdPartyFirewall = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "FirewallProduct" -ErrorAction SilentlyContinue
    $thirdPartyFirewallActive = $false
    $thirdPartyDetails = ""

    if ($null -ne $thirdPartyFirewall) {
        foreach ($fw in $thirdPartyFirewall) {
            $fwName = $fw.displayName
            $stateVal = $fw.productState
            if ($null -ne $stateVal -and ($stateVal -band 0x10) -ne 0) {
                $thirdPartyFirewallActive = $true
                $thirdPartyDetails = "$fwName 활성화"
            } elseif ($null -ne $fwName) {
                # productState 체크가 불확실하면 설치 여부만 확인
                $thirdPartyFirewallActive = $true
                $thirdPartyDetails = "$fwName 설치됨"
            }
        }
    }

    if ($windowsFirewallEnabled) {
        $finalResult = "GOOD"
        $summary = "Windows 방화벽 활성화됨 (모든 프로필)"
        $status = "양호"
    } elseif ($thirdPartyFirewallActive) {
        $finalResult = "GOOD"
        $summary = "제3자 방화벽 활성화됨: $thirdPartyDetails"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        if ($null -ne $thirdPartyFirewall) {
            $summary = "제3자 방화벽 설치되었으나 활성화 상태 불명확"
        } else {
            $summary = "방화벽이 비활성화됨 (Windows 및 제3자 방화벽 모두)"
        }
        $status = "취약"
    }

    $commandOutput = $profiles | ConvertTo-Json -Compress -ErrorAction SilentlyContinue
    if ($null -eq $commandOutput) {
        $commandOutput = "진단 실패"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $($_.Exception.Message)"
}

# 2. Define guideline variables
$purpose = '방화벽 기능 활성화 여부를 점검하여 시스템에서 외부 망의 비인가 접근 및 외부 망으로 통신을 시도하는 프로그램에 대해 통제하고 있는지 확인하기 위함'
$threat = '방화벽 기능이 비활성화되어 있으면, 외부 및 내부의 접근 통제가 되지 않아 유해 정보가 유입되거나 시스템 사용자의 파일이나 폴더가 외부로 유출될 위험이 존재함'
$criteria_good = 'Windows 방화벽''사용''으로 설정된 경우 또는 유· 무료 기타 방화벽을 사용한 경우'
$criteria_bad = 'Windows 방화벽''사용 안 함''으로 설정된 경우 또는 유· 무료 기타 방화벽을 사용하지 않은 경우'
$remediation = 'Windows 방화벽''사용''으로 설정 또는 유· 무료 기타 방화벽을 사용'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted 'Get-NetFirewallProfile' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
