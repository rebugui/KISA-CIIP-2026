

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-10
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 마지막 사용자 이름 표시 안 함
# @Description : 로그인 화면에 마지막 로그온 사용자 이름 표시 안 함 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-10"
$ITEM_NAME = "마지막 사용자 이름 표시 안 함"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check dontdisplaylastusername policy
try {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).dontdisplaylastusername

    if ($value -eq 1) {
        $finalResult = "GOOD"
        $summary = "'마지막 사용자 이름 표시 안 함' 정책이 '사용'으로 설정됨"
        $status = "양호"
        $commandOutput = "dontdisplaylastusername = 1 (Enabled)"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'마지막 사용자 이름 표시 안 함' 정책이 '사용 안 함'으로 설정됨 (보안 위협)"
        $status = "취약"
        $commandOutput = "dontdisplaylastusername = $value (Disabled or not set)"
    }

    $commandExecuted = "Get-ItemProperty -Path '$path'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty -Path '$path'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "Windows 로그인 화면에 마지막 로그온 한 사용자 이름이 표시되지 않도록하여 악의적인 사용자에게 계정 정보가 노출되는 것을 차단하고자함"
$threat = "마지막으로 로그온 한 사용자의 이름이 로그온 대화 상자에 표시될 경우 공격자는 이를 획득하여 비밀번호를 추측하거나 무작위 공격을 시도할 위험이 존재함"
$criteria_good = '''마지막 사용자 이름 표시 안 함''이''사용''으로 설정된 경우'
$criteria_bad = '''마지막 사용자 이름 표시 안 함''이''사용 안 함''으로 설정된 경우'
$remediation = "※ WindowsNT: 마지막으로 로그온 한 사용자 이름 표시 안 함 설정 ※ Windows2000: 로그온 스크린에 마지막 사용자 이름 표시 안 함 사용 설정 ※ Windows 2003, 2008, 2012, 2016, 2019, 2022: 대화형 로그온: 마지막 사용자 이름 표시 안 함 사용 설정"

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
