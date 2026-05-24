# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-54
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : Dos 공격 방어 레지스트리 설정
# @Description : TCP/IP 스택 레지스트리 설정으로 DoS 공격 방어
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-54"
$ITEM_NAME = "Dos 공격 방어 레지스트리 설정"
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

# 1. Check DoS protection registry settings
try {
    $tcpipParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue

    $synAttackProtect = if ($tcpipParams) { $tcpipParams.SynAttackProtect } else { 0 }
    $enableDeadGWDetect = if ($tcpipParams) { $tcpipParams.EnableDeadGWDetect } else { 1 }
    $keepAliveTime = if ($tcpipParams) { $tcpipParams.KeepAliveTime } else { 7200000 }
    $noNameReleaseOnDemand = if ($tcpipParams) { $tcpipParams.NoNameReleaseOnDemand } else { 0 }

    # Check if all DoS protection settings are properly configured
    $allSet = ($synAttackProtect -ge 1) -and ($enableDeadGWDetect -eq 0) -and ($keepAliveTime -eq 300000) -and ($noNameReleaseOnDemand -eq 1)

    if ($allSet) {
        $finalResult = "GOOD"
        $summary = "DoS 방어 레지스트리 4가지 모두 정확히 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "DoS 방어 레지스트리가 일부 또는 전체 미설정됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' (SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)"
    $commandOutput = "SynAttackProtect=$synAttackProtect, EnableDeadGWDetect=$enableDeadGWDetect, KeepAliveTime=$keepAliveTime, NoNameReleaseOnDemand=$noNameReleaseOnDemand"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' (SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "TCP/ IP스택(Stack)을 강화하는 레지스트리 값 변경을 통하여 DoS 공격을 방어하기 위함"
$threat = "DoS 방어레지스 트리를 설정하지 않은 경우, DoS 공격에 의한 시스템 다운으로 서비스 제공이 중단될 위험이 존재함"
$criteria_good = "아래 4가지 DoS 방어레지스 트리를 설정한 경우 SynAttackProtect →1 이상 EnableDeadGWDetect →0 KeepAliveTime →300,000 NoNameReleaseOnDemand →1"
$criteria_bad = "DoS 방어 레지스트리 값이 설정되어 있지 않은 경우"
$remediation = "레지스트리 값을 추가 또는 수정"

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
