# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-64
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 윈도우 방화벽 설정
# @Description : Windows 방화벽 활성화로 비인가 접근 및 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-64"
$ITEM_NAME = "윈도우 방화벽 설정"
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

# 1. Detect OS version to determine if Get-NetFirewallProfile is available
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $version = [version]$os.Version
        $major = $version.Major
        $minor = $version.Minor
        $osVersion = "$major.$minor"

        # Windows Server 2012 R2 = 6.3, Windows Server 2016 = 10.0
        # Get-NetFirewallProfile requires 6.3 (2012 R2) or higher
        if ($major -lt 6 -or ($major -eq 6 -and $minor -lt 3)) {
            $finalResult = "MANUAL"
            $summary = "Windows Server 2012 R2 이전 버전 (Get-NetFirewallProfile 미지원): 수동 확인 필요 (OS 버전: $osVersion)"
            $status = "수동진단"
            $commandExecuted = "OS 버전 확인: $osVersion (2012 R2 이전에서는 수동진단 필요)"
            $commandOutput = "OS Version: $osVersion (Get-NetFirewallProfile 미지원)"
        } else {
            # OS is 2012 R2 or later, use Get-NetFirewallProfile
            $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

            if ($firewallProfiles) {
                $allEnabled = $true
                foreach ($profile in $firewallProfiles) {
                    if ($profile.Enabled -eq $false) {
                        $allEnabled = $false
                        break
                    }
                }

                if ($allEnabled) {
                    $finalResult = "GOOD"
                    $summary = "Windows 방화벽이 모든 프로필에서 활성화됨"
                    $status = "양호"
                } else {
                    $finalResult = "VULNERABLE"
                    $summary = "Windows 방화벽이 하나 이상의 프로필에서 비활성화됨"
                    $status = "취약"
                }

                $commandExecuted = "Get-NetFirewallProfile (Domain, Private, Public 프로필 확인)"
                $profileStatus = ($firewallProfiles | ForEach-Object { "$($_.Name): $($_.Enabled)" }) -join ', '
                $commandOutput = $profileStatus
            } else {
                $finalResult = "MANUAL"
                $summary = "진단 실패: 수동 확인 필요"
                $status = "수동진단"
                $commandExecuted = "Get-NetFirewallProfile (방화벽 상태 확인 실패)"
                $commandOutput = "방화벽 프로필 정보를 가져올 수 없음"
            }
        }
    } else {
        $finalResult = "MANUAL"
        $summary = "OS 버전 확인 실패: 수동 확인 필요"
        $status = "수동진단"
        $commandExecuted = "Get-WmiObject Win32_OperatingSystem (OS 버전 확인)"
        $commandOutput = "OS 정보를 가져올 수 없음"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-NetFirewallProfile 또는 OS 버전 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "방화벽 기능 활성화 여부를 점검하여 시스템에서 외부 망의 비인가 접근 및 외부 망으로 통신을 시도하는 프로그램에 대해 통제하고 있는지 확인하기 위함"
$threat = "방화벽 기능이 비활성화되어 있으면, 외부 및 내부의 접근 통제가 되지 않아 유해 정보가 유입되거나 시스템 사용자의 파일이나 폴더가 외부로 유출될 위험이 존재함"
$criteria_good = "Windows 방화벽'사용'으로 설정된 경우"
$criteria_bad = "Windows 방화벽'사용 안 함'으로 설정된 경우"
$remediation = "Windows 방화벽'사용'으로 설정"

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
