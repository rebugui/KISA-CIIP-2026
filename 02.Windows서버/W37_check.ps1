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
# @Title       : 예약된 작업에 의심스러운 명령 등록 여부 점검
# @Description : 예약된 작업에 의심스러운 명령 등록 여부 확인으로 백도어 설치 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-37"
$ITEM_NAME = "예약된 작업에 의심스러운 명령 등록 여부 점검"
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
# NOTE: The criterion is a periodic human-review PROCESS ("주기적으로 점검하고 제거한
# 경우"). Whether scheduled tasks are *regularly reviewed* cannot be auto-verified, and
# a pattern scan misses malicious tasks (mshta/rundll32/regsvr32) while flagging benign
# cmd/powershell tasks. This always emits MANUAL with a task inventory as evidence.
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $out = ""

    if ($tasks) {
        $taskInventory = @()
        foreach ($task in $tasks) {
            $action = $task.Actions.Execute -join '; '
            $taskInventory += "Task: $($task.TaskPath)$($task.TaskName) [$($task.State)], Action: $action"
        }
        $out = "총 $($tasks.Count)개의 예약 작업:`n" + ($taskInventory -join "`n")
        $summary = "예약 작업 $($tasks.Count)개 확인됨. 불필요/의심스러운 작업의 주기적 점검 여부는 수동 확인 필요"
    } else {
        $out = "예약 작업이 없거나 목록을 확인할 수 없음"
        $summary = "예약 작업 목록을 확인할 수 없음: 주기적 점검 여부 수동 확인 필요"
    }

    $finalResult = "MANUAL"
    $status = "수동진단"
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
