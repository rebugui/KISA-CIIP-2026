

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
        # NetFirewallProfile.Enabled는 tri-state(True / False / NotConfigured)임.
        # 'NotConfigured -eq $false'는 $false이므로 -eq $false 검사는 NotConfigured 프로필을
        # 조용히 통과시켜 false-good을 유발함. 명시적으로 True(사용)가 아닌 모든 상태를
        # 비활성으로 간주한다(W-64 수정 미러링).
        $allEnabled = $true
        foreach ($profile in $profiles) {
            if ($profile.Enabled -ne $true) {
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

    $thirdPartyFirewallInstalledOnly = $false
    if ($null -ne $thirdPartyFirewall) {
        foreach ($fw in $thirdPartyFirewall) {
            $fwName = $fw.displayName
            $stateVal = $fw.productState
            # SecurityCenter2 productState: 활성화(ON) 상태는 비트 12-15 (마스크 0x1000)로 표현됨
            # displayName 존재만으로는 "설치됨"일 뿐 "사용 중(활성)"을 증명하지 못하므로
            # 반드시 productState 활성화 비트를 확인해야 함 (설치-but-비활성 방화벽 false-good 방지)
            if ($null -ne $stateVal -and ($stateVal -band 0x1000) -ne 0) {
                $thirdPartyFirewallActive = $true
                $thirdPartyDetails = "$fwName 활성화 (productState=0x{0:X})" -f [int]$stateVal
            } elseif ($null -ne $fwName) {
                $thirdPartyFirewallInstalledOnly = $true
                $thirdPartyDetails = "$fwName 설치됨 (productState=0x{0:X}, 활성화 비트 미확인)" -f [int]$stateVal
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
    } elseif ($thirdPartyFirewallInstalledOnly) {
        # 제3자 방화벽이 등록되어 있으나 productState 활성화 비트가 확인되지 않음
        # → 설치되었으나 비활성(사용 안 함)일 가능성이 높음. 양호로 판정하지 않음.
        $finalResult = "VULNERABLE"
        $summary = "제3자 방화벽 설치되었으나 활성화(사용) 상태 미확인: $thirdPartyDetails (Windows 방화벽도 비활성)"
        $status = "취약"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "방화벽이 비활성화됨 (Windows 및 제3자 방화벽 모두)"
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
