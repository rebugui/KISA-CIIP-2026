# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-44
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 원격으로 액세스할 수 있는 레지스트리 경로
# @Description : 원격 레지스트리 서비스 비활성화로 레지스트리 원격 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-44"
$ITEM_NAME = "원격으로 액세스할 수 있는 레지스트리 경로"
$SEVERITY = "상"
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

# 1. Check Remote Registry service status
try {
    $service = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue

    if ($service) {
        $serviceInfo = "Name: $($service.Name), Status: $($service.Status), StartType: $($service.StartType)"

        if ($service.Status -eq 'Running' -or $service.StartType -eq 'Automatic') {
            $finalResult = "VULNERABLE"
            $summary = "Remote Registry Service가 사용 중"
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "Remote Registry Service가 중지됨"
            $status = "양호"
        }

        $commandOutput = $serviceInfo
    } else {
        $finalResult = "GOOD"
        $summary = "Remote Registry Service가 설치되지 않음"
        $status = "양호"
        $commandOutput = "Remote Registry 서비스를 찾을 수 없음"
    }

    $commandExecuted = "Get-Service -Name 'RemoteRegistry'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name 'RemoteRegistry'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "원격레지스트리 서비스를 비활성화하여 레지스트리에 대한 원격 접근을 차단하기 위함"
$threat = "원격 레지스트리 서비스는 액세스에 대한 인증이 취약하여 관리자 계정 외 다른 계정들에도 원격 레지스트리 액세스를 허용할 우려가 있으며, 레지스트리에 대한 권한 설정이 잘못되어 있는 경우 원격에서 레지스트리를 통해 임의의 파일을 실행할 위험이 존재함 레지스트리 서비스의 장애는 전체 시스템에 영향을 줄 수 있어 서비스 거부 공격(DoS)공격에 이용될 위험이 존재함"
$criteria_good = "Remote Registry Service가 중지된 경우"
$criteria_bad = "Remote Registry Service가 사용 중인 경우"
$remediation = "불필요시 서비스 중지 및 사용 안 함으로 설정"

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
