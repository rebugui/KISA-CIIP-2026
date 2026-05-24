# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-37
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : (중) 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검 개요
# @Description : 예약된 작업에 의심스러운 명령 등록 여부 확인으로 백도어 설치 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-37"
$ITEM_NAME = "(중) 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검 개요"
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

# 1. Run diagnostic
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $out = ""

    if ($tasks) {
        $suspiciousTasks = @()
        $suspiciousCount = 0

        foreach ($task in $tasks) {
            $action = $task.Actions.Execute
            if ($action) {
                # Check for suspicious command patterns
                if ($action -match 'cmd' -or $action -match 'powershell' -or $action -match 'wscript' -or $action -match 'cscript') {
                    $suspiciousCount++
                    $suspiciousTasks += "Task: $($task.TaskName), Action: $action"
                }
            }
        }

        if ($suspiciousCount -gt 0) {
            $out = $suspiciousTasks -join "`n"
            $finalResult = "MANUAL"
            $summary = "의심스러운 명령어를 포함한 예약 작업이 $suspiciousCount개 발견됨: 수동 확인 필요"
            $status = "수동진단"
        } else {
            $out = "총 $($tasks.Count)개의 예약 작업 확인됨, 의심스러운 작업 없음"
            $finalResult = "GOOD"
            $summary = "의심스러운 예약 작업이 발견되지 않음 (주기적 확인 필요)"
            $status = "양호"
        }
    } else {
        $out = "예약 작업 없음 또는 확인 실패"
        $finalResult = "GOOD"
        $summary = "의심스러운 예약 작업이 발견되지 않음 (주기적 확인 필요)"
        $status = "양호"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $out = $_.Exception.Message
}

# Define guideline variables
$purpose = "외부 무단 침입 시 설정될 수 있는 불필요한 예약 작업의 등록 여부를 확인하기 위함"
$threat = "일정 시간마다 미리 설정해 둔 프로그램을 실행할 수 있는 예약된 작업은 시작 프로그램과 더불어서 해킹과 트로이 목마, 백 도어를 설치하여 공격하기 좋은 경로로 사용될 위험이 존재함"
$criteria_good = "불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우"
$criteria_bad = "불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하지 않거나, 불 필 요한 작업을 제거하지 않은 경우"
$remediation = "예약 작업에 대한 주기적인 확인"

# Save results using lib
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $out `
    -CommandExecuted 'Get-ScheduledTask' `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

exit 0
