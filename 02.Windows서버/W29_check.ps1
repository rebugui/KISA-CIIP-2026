# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-29
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 불필요한 SNMP 서비스 구동 점검
# @Description : 불필요한 SNMP 서비스 구동 여부 점검으로 시스템 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-29"
$ITEM_NAME = "불필요한 SNMP 서비스 구동 점검"
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

# 1. Run diagnostic
try {
    $snmpServices = Get-Service -Name 'SNMP*' -ErrorAction SilentlyContinue

    if ($snmpServices) {
        # 가이드라인 양호 기준: SNMP 서비스 미사용 또는 Community String을 설정하여 사용하는 경우.
        # 취약 기준: '불필요하게' SNMP 서비스를 사용하는 경우(필요성 판단).
        # 'SNMP*'에는 SNMP 에이전트가 없어도 단독 구동될 수 있는 SNMPTRAP가 포함되므로,
        # 실제 SNMP 에이전트(서비스명 'SNMP')의 구동 여부만으로 사용 여부를 판단한다.
        $snmpAgent = $snmpServices | Where-Object { $_.Name -eq 'SNMP' }
        $runningSnmp = $snmpAgent | Where-Object { $_.Status -eq 'Running' }

        $serviceList = ($snmpServices | Format-Table -Property Name, Status, StartType -AutoSize | Out-String).Trim()
        $commandOutput = $serviceList

        if ($runningSnmp) {
            # SNMP 에이전트가 구동 중. 'Community String을 설정하여 사용하는 경우'는 양호이고,
            # '불필요하게 사용하는 경우'만 취약이다. 서비스의 업무상 필요성은 스크립트로
            # 정적 판단할 수 없으므로(또한 Community String 설정 시 비취약), 플랫하게 취약 처리하지 않고
            # ValidCommunities 설정 상태를 증거로 수집하여 수동진단으로 라우팅한다.
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
            $communities = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $communityNames = @()
            if ($communities) {
                foreach ($prop in $communities.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') {
                        $communityNames += $prop.Name
                    }
                }
            }
            $communityLabel = if ($communityNames.Count -gt 0) { ($communityNames -join ', ') } else { '(none)' }

            $finalResult = "MANUAL"
            $status = "수동진단"
            if ($communityNames.Count -gt 0) {
                $summary = "SNMP 서비스가 구동 중이며 Community String이 설정됨(Communities: $communityLabel). 업무상 필요(NMS 모니터링 등)에 의한 사용이면 양호, 불필요한 사용이면 취약 - 필요성 수동 확인 필요"
            } else {
                $summary = "SNMP 서비스가 구동 중이나 ValidCommunities Community String이 확인되지 않음(GPO/SNMPv3 설정 가능성). 업무상 필요성 및 Community String 설정 여부 수동 확인 필요"
            }
            $commandOutput = $serviceList + "`r`nValidCommunities: " + $communityLabel
        } else {
            $finalResult = "GOOD"
            $summary = "SNMP 서비스가 설치되어 있지만 구동되지 않음 (서비스 미사용)"
            $status = "양호"
        }
    } else {
        $finalResult = "GOOD"
        $summary = "SNMP 서비스가 설치되지 않음"
        $status = "양호"
        $commandOutput = "SNMP 서비스 없음"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-Service -Name 'SNMP*' (+ SNMP 에이전트 구동 시 Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities')"

# 2. lib를 통한 결과 저장
$purpose = "취약한 SNMP 서비스를 비활성화하여 시스템의 주요 정보 유출 및 불법 수정을 방지하기 위함"
$threat = "취약한 SNMP 서비스를 사용하는 경우 서비스 거부 공격(DoS, DDoS), 버퍼오버플로우, 비인가 접속 등의 공격 위험이 존재함"
$criteria_good = "SNMP 서비스를 사용하지 않는 경우 또는 Community String을 설정하여 SNMP 서비스를 사용하는 경우"
$criteria_bad = "불필요하게 SNMP 서비스를 사용하는 경우"
$remediation = "불필요시 서비스 중지/ 사용 안 함"

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
