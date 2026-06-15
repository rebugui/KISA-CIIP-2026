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
        # SNMP 서비스 미설치/미사용 = 양호 (가이드라인 양호 기준 1).
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "SNMP 서비스를 사용하지 않음"
        $commandExecuted = "Get-Service -Name 'SNMP'"
        $commandOutput = "SNMP service not found"
    } else {
        # 가이드라인: 양호 = SNMP 미사용 또는 '특정 호스트로부터 SNMP 패킷 받아들이기'가 설정된 경우.
        #             취약 = 모든 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우.
        # PermittedManagers는 KEY이며 허용 호스트는 그 아래 번호값(1='host1', 2='host2')으로 저장된다.
        # 따라서 'PermittedManagers'라는 값(value)이 아니라 KEY의 항목(entries)을 열거해야 한다.
        $permittedPath = 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers'
        $communityPath = 'HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities'

        # --- PermittedManagers 호스트 제한 항목 열거 ---
        $permittedHosts = @()
        if (Test-Path $permittedPath) {
            $props = Get-ItemProperty -Path $permittedPath -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    # 레지스트리 메타데이터(PS*) 속성 제외, 숫자 이름의 호스트 항목만 수집.
                    if ($p.Name -match '^\d+$' -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
                        $permittedHosts += [string]$p.Value
                    }
                }
            }
        }
        $hasHostRestriction = ($permittedHosts.Count -gt 0)

        # --- ValidCommunities 커뮤니티 항목 열거 ---
        $communityNames = @()
        if (Test-Path $communityPath) {
            $cprops = Get-ItemProperty -Path $communityPath -ErrorAction SilentlyContinue
            if ($cprops) {
                foreach ($c in $cprops.PSObject.Properties) {
                    if ($c.Name -notmatch '^PS' -and $c.Name -ne 'PSPath' -and $c.Name -ne 'PSParentPath' -and $c.Name -ne 'PSChildName' -and $c.Name -ne 'PSDrive' -and $c.Name -ne 'PSProvider') {
                        $communityNames += $c.Name
                    }
                }
            }
        }
        $hasCommunity = ($communityNames.Count -gt 0)

        # 이 항목(W-31)의 핵심 판단 기준은 호스트 접근 제한(PermittedManagers) 여부이다.
        # 호스트 제한이 설정되어 있으면 양호. 설정되어 있지 않으면(= 모든 호스트 허용) 취약.
        $communityLabel = if ($hasCommunity) { ($communityNames -join ', ') } else { '(none)' }
        if ($hasHostRestriction) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "특정 호스트로부터만 SNMP 패킷을 받아들이도록 설정됨 (PermittedManagers 지정됨)"
            $commandOutput = "PermittedManagers: " + ($permittedHosts -join ', ') + "; Communities: " + $communityLabel
        } else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "SNMP 서비스가 활성화되어 있으나 SNMP 패킷 수령 호스트 제한(PermittedManagers)이 설정되지 않아 모든 호스트로부터 패킷을 수락함"
            $commandOutput = "No PermittedManagers host restriction. Communities: " + $communityLabel
        }

        $commandExecuted = "Get-Service -Name 'SNMP'; Get-ItemProperty 'HKLM:\...\SNMP\Parameters\PermittedManagers'; Get-ItemProperty 'HKLM:\...\SNMP\Parameters\ValidCommunities'"
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
