# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-30
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정으로 무단 SNMP 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-30"
$ITEM_NAME = "SNMP Community String 복잡성 설정"
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
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    $communities = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    if ($communities) {
        $hasWeakCommunity = $false
        $weakCommunities = @()
        $allCommunities = @()

        foreach ($prop in $communities.PSObject.Properties) {
            # PSObject의 기본 속성(PSPath, PSParentPath 등) 제외
            if ($prop.Name -notmatch '^PS') {
                $allCommunities += "$($prop.Name) (권한: $($prop.Value))"

                # 기본 Community String 확인 (오라클 기준: public, private 정확 일치)
                if ($prop.Name -match '^(public|private)$' -and $prop.Value -gt 0) {
                    $hasWeakCommunity = $true
                    $weakCommunities += $prop.Name
                }
            }
        }

        $commandOutput = $allCommunities -join "`r`n"

        if ($hasWeakCommunity) {
            $finalResult = "VULNERABLE"
            $weakList = $weakCommunities -join ', '
            $summary = "SNMP Community String이 기본값($weakList)을 사용하여 보안 취약"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "SNMP Community String이 복잡하게 설정되어 기본값(public, private 등) 미사용"
            $status = "양호"
        }
    } else {
        # ValidCommunities 키가 없거나 읽을 수 없음.
        # SNMP 서비스가 실제로 구동 중이면 Community String을 GPO/SNMPv3 등으로
        # 설정했거나 키가 삭제되었을 수 있으므로 '안전'으로 단정할 수 없음 → 수동진단.
        # SNMP 서비스가 구동 중이 아니면 서비스 미사용으로 양호.
        $snmpServices = Get-Service -Name 'SNMP*' -ErrorAction SilentlyContinue
        $runningSnmp = $snmpServices | Where-Object { $_.Status -eq 'Running' }

        if ($runningSnmp) {
            $finalResult = "MANUAL"
            $summary = "SNMP 서비스가 구동 중이나 ValidCommunities 레지스트리 키가 없거나 읽을 수 없어 Community String 안전 여부를 확인할 수 없음 (GPO/SNMPv3 설정 가능성) - 수동 확인 필요"
            $status = "수동진단"
            $commandOutput = "ValidCommunities 레지스트리 키 없음 / SNMP 서비스 구동 중"
        } else {
            $finalResult = "GOOD"
            $summary = "SNMP Community String이 설정되지 않음 (서비스 미사용)"
            $status = "양호"
            $commandOutput = "레지스트리 키 없음 / SNMP 서비스 미구동"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' (+ ValidCommunities 부재 시 Get-Service 'SNMP*' 구동 여부 확인)"

# 2. lib를 통한 결과 저장
$purpose = "SNMP에서 일종의 비밀번호로 사용하는 Community String을 유추할 수 없는 복잡한 값으로 변경하여 불필요한 시스템 정보 노출을 차단하기 위함"
$threat = "Community String을 변경하지 않고 public, private 등 기본 설정 값으로 사용하는 경우, 기본 Com munityString 값을 통한 시스템의 주요 정보 및 설정 상태가 비인가자에게 노출될 수 있는 위험이 존재함"
$criteria_good = "SNMP 서비스를 사용하지 않거나 CommunityString이 public, private이 아닌 경우"
$criteria_bad = "SNMP 서비스를 사용하며,Community String이 public, private인 경우"
$remediation = "불필요시 서비스 중지/ 사용 안 함, 사용 시 기본 CommunityString 변경"

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
