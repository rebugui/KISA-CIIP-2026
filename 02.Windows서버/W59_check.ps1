# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-59
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : LAN Manager 인증 수준
# @Description : LAN Manager 인증 수준 설정으로 안전한 인증 프로토콜 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-59"
$ITEM_NAME = "LAN Manager 인증 수준"
$SEVERITY = "중"
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

# 1. Check LAN Manager authentication level
try {
    $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $lmCompatibilityLevel = if ($lsa) { $lsa.LmCompatibilityLevel } else { 0 }

    if ($lmCompatibilityLevel -ge 3) {
        $finalResult = "GOOD"
        $summary = "LAN Manager 인증 수준이 NTLMv2 응답만 보내기로 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "LAN Manager 인증 수준이 LM 또는 NTLM이 설정됨 (취약)"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'"
    $commandOutput = "LmCompatibilityLevel: $lmCompatibilityLevel"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "LAN Manager 인증 수준 설정을 통해 네트워크 로그온에 사용할 Challenge/ Response 인증 프로토콜을 결정하며, 안전한 인증 절차를 적용하기 위함"
$threat = "안전하지 않은 LAN Manager 인증 수준을 사용하는 경우 인증 트래픽을 가로채기를 통해 악의적인 계정 정보 노출 위험이 존재함"
$criteria_good = '"LAN Manager 인증 수준" 정책에"NTLMv2 응답만 보냄"이 설정되어 있는 경우'
$criteria_bad = '"LAN Manager 인증 수준" 정책에"LM"및"NTLM"인증이 설정되어 있는 경우'
$remediation = "- Windows 2000 : LANManager 인증 7 수준->NTLMv2 응답만 보내기 - Windows 2003, 2008, 2012, 2016, 2019 : 네트워크 보안:LANManager 인증 수준->NTMLv2 응답만 보내기"

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
