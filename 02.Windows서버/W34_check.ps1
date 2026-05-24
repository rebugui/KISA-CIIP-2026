# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-34
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : Telnet 서비스 비활성화
# @Description : 취약 프로토콜인 Telnet 서비스 비활성화로 인증 정보 노출 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-34"
$ITEM_NAME = "Telnet 서비스 비활성화"
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
    Write-Host ""
}

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue

    if (-not $service) {
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "Telnet 서비스가 비활성화되거나 NTLM 인증만 사용 설정됨"
        $commandExecuted = "Get-Service -Name 'TlntSvr'"
        $commandOutput = "Telnet service not found"
    } else {
        # Check if Telnet is actually running
        if ($service.Status -ne 'Running') {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Telnet 서비스가 구동되어 있지 않음"
            $commandExecuted = "Get-Service -Name 'TlntSvr'"
            $commandOutput = "Telnet service status: $($service.Status) (not running)"
        } else {
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\services\TlntSvr'
            $authValue = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).AuthenticationType

            if ($authValue -eq 1) {
                $finalResult = "GOOD"
                $status = "양호"
                $summary = "Telnet 서비스가 NTLM 인증만 사용 설정됨"
                $commandOutput = "Telnet service running with NTLM authentication only"
            } else {
                $finalResult = "VULNERABLE"
                $status = "취약"
                $summary = "Telnet 서비스가 활성화되어 있고 NTLM 인증만 사용 설정이 아님"
                $commandOutput = "Telnet service running without NTLM-only authentication"
            }

            $commandExecuted = "Get-Service -Name 'TlntSvr'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\TlntSvr'"
        }
    }

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-Service -Name 'TlntSvr'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\TlntSvr'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "취약 프로토콜인 Telnet 서비스의 사용을 원칙적으로 금지하고, 부득이 이용할 경우 네트워크상으로 비밀번호를 전송하지 않는 NTLM 인증을 사용하도록하여 인증 정보의 노출을 차단하기 위함"
$threat = "Telnet 서비스는 평문으로 데이터를 송수신하기 때문에 비밀번호 방식으로 인증을 수행할 경우 ID 및 비밀번호가 외부로 노출될 위험이 존재함"
$criteria_good = "Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우"
$criteria_bad = "Telnet 서비스가 구동되어 있으며 인증 방법이 NTLM이 아닌 경우"
$remediation = "불필요시 서비스 중지/ 사용 안 함 설정, 사용 시 인증 방법으로 NTLM만 사용"

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
