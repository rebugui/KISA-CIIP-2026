

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-17
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 하드 디스크 기본 공유 제거
# @Description : 하드디스크 기본 공유(C$, D$, ADMIN$) 제거 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-17"
$ITEM_NAME = "하드 디스크 기본 공유 제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check default administrative shares (C$, D$, ADMIN$)
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
    $autoShare = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).AutoShareServer

    $defaultShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^\w+\$' -and $_.Name -ne 'IPC$'
    }

    $shareNames = ($defaultShares | ForEach-Object { $_.Name }) -join ', '

    if ($autoShare -eq 0 -and ($defaultShares.Count -eq 0)) {
        $finalResult = "GOOD"
        $summary = "레지스트리 AutoShareServer가 0이며 기본 공유(C$, D$, ADMIN$ 등)가 존재하지 않음"
        $status = "양호"
        $commandOutput = "AutoShareServer = 0, No default shares found"
    } elseif ($autoShare -eq 1 -or ($defaultShares.Count -gt 0)) {
        $finalResult = "VULNERABLE"
        $summary = "레지스트리 AutoShareServer가 1이거나 기본 공유(C$, D$, ADMIN$ 등)가 존재함 (보안 위협)"
        $status = "취약"
        $commandOutput = "AutoShareServer = $autoShare, Default shares: $shareNames"
    } else {
        $finalResult = "MANUAL"
        $summary = "기본 공유 상태를 확인할 수 없음 (AutoShareServer 레지스트리 값이 없거나 예상치 못한 값이며 기본 공유는 발견되지 않음). 수동 검토 필요."
        $status = "수동진단"
        $commandOutput = "AutoShareServer = $autoShare, No default shares found (indeterminate)"
    }

    $commandExecuted = "reg query '$path' /v AutoShareServer"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "reg query '$path' /v AutoShareServer"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "하드 디스크 기본 공유를 제거하여 시스템 정보 노출을 차단하고자함"
$threat = "Windows는 프로그램 및 서비스를 네트워크나 컴퓨터 환경에서 관리하기 위해 시스템 기본 공유 항목을 자동으로 생성함. 이를 제거하지 않으면 비인가자가 모든 시스템 자원에 접근할 수 있는 위험한 상황이 발생할 수 있으며 이러한 공유 기능의 경로를 이용하여 바이러스가 침투 위험이 존재함"
$criteria_good = "레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 0이며 기본 공유가 존재하지 않는 경우"
$criteria_bad = "레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 1이거나 기본 공유가 존재하는 경우"
$remediation = "기본 공유 중지 후 레지스트리 값 설정(IPC `$, 일반 공유 제외)"

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
