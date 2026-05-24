# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : W-47
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 하
# @Title       : 화면 보호기 설정
# @Description : 화면보호기 설정으로 유휴 시간 내 불법적인 시스템 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-47"
$ITEM_NAME = "화면 보호기 설정"
$SEVERITY = "하"
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

# 1. Check screen saver settings
try {
    $screenSaver = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
    $scrnsaveexe = if ($screenSaver) { $screenSaver.SCRNSAVE.EXE } else { '' }
    $screenSaveTimeOut = if ($screenSaver) { $screenSaver.ScreenSaveTimeOut } else { 0 }
    $screenSaveIsSecure = if ($screenSaver) { $screenSaver.ScreenSaverIsSecure } else { 0 }

    $output = "SCRNSAVE.EXE: $scrnsaveexe`nScreenSaveTimeOut: $screenSaveTimeOut`nScreenSaverIsSecure: $screenSaveIsSecure"

    # Check if screen saver is configured:
    # - Screen saver executable is set and not empty
    # - Timeout is greater than 0 and less than or equal to 600 seconds (10 minutes)
    # - Password protection is enabled (ScreenSaverIsSecure = 1)
    $isConfigured = ($scrnsaveexe -and $scrnsaveexe.Length -gt 0) -and
                   ($screenSaveTimeOut -gt 0 -and $screenSaveTimeOut -le 600) -and
                   ($screenSaveIsSecure -eq 1)

    if ($isConfigured) {
        $finalResult = "GOOD"
        $summary = "화면보호기가 설정되고 대기시간이 10분(600초) 이하이며 암호 사용이 활성화됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "화면보호기가 설정되지 않았거나 대기시간이 10분 초과 또는 암호 사용이 비활성화됨"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKCU:\Control Panel\Desktop' (SCRNSAVE.EXE, ScreenSaveTimeOut, ScreenSaverIsSecure)"
    $commandOutput = $output

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKCU:\Control Panel\Desktop'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "사용자가 일정 시간 동안 아무런 작업을 수행하지 않으면 자동으로 로그오프 되거나 워크스테이션이 잠기도록 설정하여, 유휴 시간 내 불법적인 시스템 접근을 차단하기 위함"
$threat = "화면 보호기 설정을 하지 않으면 사용자가 자리를 비운 사이에 임의의 사용자가 해당 시스템에 접근하여 중요 정보를 유출하거나, 악의적인 행위를 통해 시스템 운영에 악영향을 미칠 위험이 존재함"
$criteria_good = "화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우"
$criteria_bad = ""
$remediation = "화면 보호기 사용, 대기 시간 10분 이하, 해제를 위한 암호 사용"

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
