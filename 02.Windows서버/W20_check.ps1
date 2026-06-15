# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-20
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : NetBIOS 바인 딩 서비스 구동 점검
# @Description : NetBIOS over TCP/IP 비활성화 여부 점검으로 NetBIOS 관련 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-20"
$ITEM_NAME = "NetBIOS 바인 딩 서비스 구동 점검"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check NetBIOS over TCP/IP settings
# TcpipNetbiosOptions: 0 = Use NetBIOS setting from DHCP, 1 = Enable NetBIOS over TCP/IP, 2 = Disable NetBIOS over TCP/IP
# 양호(GOOD)는 모든 IP-enabled 어댑터에서 NetBIOS가 비활성화(2)된 경우에만 성립한다.
try {
    $commandExecuted = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'"

    # 물리/활성 필터에 의존하지 않고 IP가 활성화된 모든 어댑터 구성을 직접 조회한다.
    $configs = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)

    if ($configs.Count -eq 0) {
        # 조회 가능한 어댑터가 없으면 바인딩 상태를 단정할 수 없으므로 수동 진단.
        $finalResult = "MANUAL"
        $summary = "IP가 활성화된 네트워크 어댑터를 찾을 수 없어 NetBIOS 바인딩 상태를 자동으로 판단할 수 없음 (수동 확인 필요)"
        $status = "수동진단"
        $commandOutput = "No IP-enabled adapters returned by Win32_NetworkAdapterConfiguration"
    } else {
        $netbiosEnabled = $false
        $adapterDetails = @()

        foreach ($config in $configs) {
            $opt = $config.TcpipNetbiosOptions
            $label = if ([string]::IsNullOrEmpty($config.Description)) { "Index $($config.Index)" } else { $config.Description }
            $statusText = switch ($opt) {
                0 { "NetBIOS via DHCP (enabled)" }
                1 { "NetBIOS enabled" }
                2 { "NetBIOS disabled" }
                default { "Unknown ($opt)" }
            }
            $adapterDetails += "${label}: $statusText"
            # 2(비활성화)가 아닌 모든 값(0=DHCP 기본, 1=활성화)은 바인딩이 제거되지 않은 것으로 간주.
            if ($opt -ne 2) {
                $netbiosEnabled = $true
            }
        }

        if ($netbiosEnabled) {
            $finalResult = "VULNERABLE"
            $summary = "TCP/IP와 NetBIOS 간의 바인딩이 제거되지 않음: " + ($adapterDetails -join ', ')
            $status = "취약"
            $commandOutput = $adapterDetails -join '; '
        } else {
            $finalResult = "GOOD"
            $summary = "TCP/IP와 NetBIOS 간의 바인딩이 제거됨 (모든 어댑터에서 NetBIOS 비활성화)"
            $status = "양호"
            $commandOutput = $adapterDetails -join '; '
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "NetBIOS와 TCP/IP 바인 딩을 제거하여 TCP/IP를 거치게 되는 파일 공유 서비스를 제공하지 못하도록하고, 인터넷에서의 공유 자원에 대한 접근 시도를 방지하고자 함"
$threat = "인터넷에 직접 연결된 윈도우 시스템에서 NetBIOS TCP/IP 바인딩이 활성화되어 있으면 공격자가 네트워크 공유 자원을 사용할 위험이 존재함"
$criteria_good = "TCP/IP와 NetBIOS 간의 바인 딩이 제거되어 있는 경우"
$criteria_bad = "TCP/IP와 NetBIOS 간의 바인 딩이 제거되어 있지 않은 경우"
$remediation = "네트워크 제어 판을 이용하여 TCP/IP와 NetBIOS 간의 바인 딩(binding)제거"

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
