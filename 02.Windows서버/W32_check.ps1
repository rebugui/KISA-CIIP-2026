# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-32
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : DNS 서비스 구동 점검
# @Description : DNS 서비스 동적 업데이트 비활성화로 신뢰할 수 없는 데이터 업데이트 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-32"
$ITEM_NAME = "DNS 서비스 구동 점검"
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

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $service = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue

    if (-not $service) {
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "DNS 서비스가 비활성화되거나 동적 업데이트가 비활성화됨"
        $commandExecuted = "Get-Service -Name 'DNS'"
        $commandOutput = "DNS service not found"
    } else {
        $dnsServer = Get-WmiObject -Class MicrosoftDNS_Server -Namespace 'Root\MicrosoftDNS' -ErrorAction SilentlyContinue

        if ($dnsServer) {
            $updateEnabled = $false
            foreach ($srv in $dnsServer) {
                if ($srv.AllowUpdate -eq $true) {
                    $updateEnabled = $true
                }
            }

            if ($updateEnabled) {
                $finalResult = "VULNERABLE"
                $status = "취약"
                $summary = "DNS 서비스가 활성화되어 있고 동적 업데이트가 설정됨"
                $commandOutput = "DNS service running with dynamic updates enabled"
            } else {
                $finalResult = "GOOD"
                $status = "양호"
                $summary = "DNS 서비스가 비활성화되거나 동적 업데이트가 비활성화됨"
                $commandOutput = "DNS service running with dynamic updates disabled"
            }
        } else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "진단 실패: 수동 확인 필요"
            $commandOutput = "Failed to query DNS server configuration"
        }

        $commandExecuted = "Get-Service -Name 'DNS'; Get-WmiObject -Class MicrosoftDNS_Server"
    }

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-Service -Name 'DNS'; Get-WmiObject -Class MicrosoftDNS_Server"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "DNS 동적 업데이트를 비활성화함으로 신뢰할 수 없는 원본으로부터 업데이트를 받아들이는 위험을 차단하기 위함"
$threat = "DNS 서버에서 동적 업데이트를 사용할 경우 악의적인 사용자에 의해 신뢰할 수 없는 데이터가 받아들여질 위험이 존재함"
$criteria_good = "DNS 서비스를 사용하지 않거나 동적 업데이트'없음(아니오)'으로 설정된 경우"
$criteria_bad = "서비스를 사용하며 동적 업데이트가 설정된 경우"
$remediation = "DNS 서비스의 동적 업데이트 비활성화 설정"

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
