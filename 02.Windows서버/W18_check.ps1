

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-18
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 불필요한 서비스 제거
# @Description : 불필요한 서비스 실행 여부 점검으로 시스템 자원 낭비 방지 및 공격 표면 감소
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-18"
$ITEM_NAME = "불필요한 서비스 제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check unnecessary services
try {
    $unnecessaryServices = @('Alerter', 'Clipbook', 'Messenger', 'Remote Registry', 'Simple TCP/IP Services')
    $runningServices = @()

    foreach ($svcName in $unnecessaryServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $runningServices += $svcName
            }
        } catch {
            # Service not found or error, skip
            continue
        }
    }

    if ($runningServices.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "불필요한 서비스가 모두 중지됨"
        $status = "양호"
        $commandOutput = "All unnecessary services are stopped or not installed"
    } else {
        $finalResult = "VULNERABLE"
        $runningList = $runningServices -join ', '
        $summary = "불필요한 서비스가 구동 중임: $runningList"
        $status = "취약"
        $commandOutput = "Running unnecessary services: $runningList"
    }

    $commandExecuted = "Get-Service -Name 'Alerter','Clipbook','Messenger','Remote Registry','Simple TCP/IP Services'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name '...'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "사용자 환경에 필요하지 않은 서비스 및 실행 파일을 제거하거나 비활성화 처리하여 이를 통한 악의적인 공격을 차단하기 위함"
$threat = "시스템에 기본적으로 설치되는 불필요한 취약 서비스들이 제거되지 않은 경우, 해당 서비스의 취약점으로 인한 공격이 가능하며, 네트워크 서비스의 경우 열린 Port를 통한 외부 침입 위험이 존재함"
$criteria_good = "일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우"
$criteria_bad = "일반적으로 불필요한 서비스(아래 목록 참조)가 구동 중인 경우"
$remediation = "서비스 중지 후'사용 안 함'설정"

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
