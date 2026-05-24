# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-31
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : SNMP Access Control 설정
# @Description : SNMP 트래픽에 대한 Access Control 설정으로 내부 네트워크 공격 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-31"
$ITEM_NAME = "SNMP Access Control 설정"
$SEVERITY = "중"
$CATEGORY = "2.서비스관리"

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

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $service = Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue

    if (-not $service) {
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "SNMP 서비스가 비활성화되거나 특정 호스트로부터의 SNMP 패킷만 수락하도록 설정됨"
        $commandExecuted = "Get-Service -Name 'SNMP'"
        $commandOutput = "SNMP service not found"
    } else {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\TrapConfiguration'
        $permittedPath = 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers'
        $validHosts = @('127.0.0.1', 'localhost')
        $hasValidConfig = $false

        if (Test-Path $regPath) {
            $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
            if ($subKeys.Count -gt 0) {
                $hasValidConfig = $true
            }
        }

        # PermittedManagers 확인 (SNMP 접근 제어의 핵심 설정)
        $hasPermittedManagers = $false
        if (Test-Path $permittedPath) {
            $permitted = (Get-ItemProperty -Path $permittedPath -Name 'PermittedManagers' -ErrorAction SilentlyContinue).PermittedManagers
            if ($permitted) {
                $hasPermittedManagers = $true
            }
        }

        $communityPath = 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities'
        $hasCommunityRestriction = $false

        if (Test-Path $communityPath) {
            $communities = Get-Item $communityPath -ErrorAction SilentlyContinue
            if ($communities) {
                $hasCommunityRestriction = $true
            }
        }

        if ($hasValidConfig -or $hasCommunityRestriction -or $hasPermittedManagers) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "SNMP 서비스가 비활성화되거나 특정 호스트로부터의 SNMP 패킷만 수락하도록 설정됨"
            $commandOutput = "SNMP service configured with access restrictions"
        } else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "SNMP 서비스가 활성화되어 있고 접근 제한 설정이 안 되어 있음"
            $commandOutput = "SNMP service running without access restrictions"
        }

        $commandExecuted = "Get-Service -Name 'SNMP'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters'"
    }

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-Service -Name 'SNMP'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "SNMP 트래픽에 대한 Access Control 설정을 적용하여 내부 네트워크로부터의 악의적인 공격을 차단하기 위함"
$threat = "SNMPAccessControl 설정을 적용하지 않아 인증되지 않은 내부 서버로부터의 SNMP 트래픽을 차단하지 않을 경우, 장치 구성 변경, 라우팅 테이블 조작, 악의적인 TFTP 서버 구동 등의 SNMP 공격에 노출될 위험이 존재함"
$criteria_good = "SNMP 서비스를 사용하지 않거나 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우"
$criteria_bad = "모든 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우"
$remediation = "불필요시 서비스 중지/ 사용 안 함, 사용 시 SNMP 패킷 수령 호스트 지정"

# Save results using lib
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
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
