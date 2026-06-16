# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-42
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 하
# @Title       : 이벤트 로그 관리 설정
# @Description : 이벤트 로그 파일 크기 및 보관 기간 적절 유지로 중요 로그 누락 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-42"
$ITEM_NAME = "이벤트 로그 관리 설정"
$SEVERITY = "하"
$CATEGORY = "4.로그관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check event log maximum size settings
try {
    $logNames = @('Application', 'System', 'Security')
    $logDetails = @()
    $allConfigured = $true
    $accessFailed = $false

    foreach ($logName in $logNames) {
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($log) {
            $maxSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $logDetails += "$logName : $($log.MaximumSizeInBytes) bytes ($maxSizeMB MB)"

            # Check log retention (Action when log is full)
            $logAction = $log.LogMode
            $logDetails += "$logName : LogMode=$logAction"

            # Check retention policy - should not be "OverwriteAsNeeded" without size check
            # "90일 이후 이벤트 덮어씀" = retain events for at least 90 days
            if ($log.MaximumSizeInBytes -lt 10485760 -or $log.LogMode -eq 'Circular') {
                $allConfigured = $false
            }
        } else {
            # 설정값이 취약한 것이 아니라 로그를 열거할 수 없음(권한 부족 등).
            # 양호 여부를 입증할 수 없으므로 취약이 아닌 수동진단으로 분류
            $accessFailed = $true
            $logDetails += "$logName : 접근 불가"
        }
    }

    if ($accessFailed) {
        $finalResult = "MANUAL"
        $summary = "일부 이벤트 로그를 열거할 수 없어(권한 부족 등) 설정값을 확인할 수 없음. 수동 확인 필요"
        $status = "수동진단"
    } elseif ($allConfigured) {
        $finalResult = "GOOD"
        $summary = "최대 로그 크기가 10,240KB 이상으로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "최대 로그 크기가 10,240KB 미만으로 설정됨"
        $status = "취약"
    }

    $commandExecuted = "Get-WinEvent -ListLog Application, System, Security"
    $commandOutput = $logDetails -join "`n"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WinEvent -ListLog Application, System, Security"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "유사시 책임 추적을 위해 주요 이벤트가 누락되지 않도록 이벤트 로그 파일의 크기 및 보관 기간을 적절하게 유지하기 위함"
$threat = "이벤트 로그 파일의 크기가 충분하지 않으면 중요 로그가 저장되지 않을 위험이 있으며, 최대 보존 크기를 초과하는 경우 자동으로 덮어씀으로써 중요 로그의 손실 위험이 존재함"
$criteria_good = "최대 로그 크기'10,240KB 이상'으로 설정,'90일 이후 이벤트 덮어씀'을 설정한 경우"
$criteria_bad = "최대 로그 크기'10,240KB 미만'으로 설정, 이벤트 덮어 씀 기간이'90일 이하로 설정된 경우"
$remediation = "최대 로그 크기'10,204KB','90일 이후 이벤트 덮어씀'설정"

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
