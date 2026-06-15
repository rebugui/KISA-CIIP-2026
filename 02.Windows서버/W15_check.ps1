

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-15
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 사용자 개인 키 사용 시 암호 입력
# @Description : 사용자 개인키(인증서) 사용 시 암호 입력 요구 정책 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-15"
$ITEM_NAME = "사용자 개인 키 사용 시 암호 입력"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. check ForceKeyProtection policy for private key password
# 정책 위치: HKLM:\SOFTWARE\Policies\Microsoft\Cryptography 값 ForceKeyProtection
#   2 = 키를 사용할 때마다 암호 입력 (양호)
#   1 = 키를 처음 사용할 때 프롬프트 (수동진단 - 매번 입력 아님)
#   0 또는 미설정 = 암호 입력 없음 (취약)
try {
    # 점검 대상 OS 게이트: 가이드 target = Windows 2016, 2019, 2022 (Build 14393 이상)
    $osBuild = [int]([System.Environment]::OSVersion.Version.Build)

    if ($osBuild -lt 14393) {
        $finalResult = "N/A"
        $summary = "본 점검 항목은 Windows Server 2016/2019/2022 대상이며, 현재 OS 빌드($osBuild)는 점검 대상이 아님"
        $status = "N/A"
        $commandOutput = "OS Build $osBuild is out of target scope (requires >= 14393)"
        $commandExecuted = "[System.Environment]::OSVersion.Version.Build"
    } else {
        $prop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -ErrorAction SilentlyContinue
        $fkp = if ($null -ne $prop) { $prop.ForceKeyProtection } else { $null }

        if ($fkp -eq 2) {
            $finalResult = "GOOD"
            $summary = "사용자 개인키 사용 시마다 암호 입력이 요구됨 (ForceKeyProtection = 2)"
            $status = "양호"
            $commandOutput = "ForceKeyProtection = 2 (Password required on every use)"
        } elseif ($fkp -eq 1) {
            $finalResult = "MANUAL"
            $summary = "개인키 최초 사용 시에만 암호 입력 프롬프트가 설정됨 (매번 입력 아님). 운영 정책상 매번 입력 요구 여부를 수동 확인 필요 (ForceKeyProtection = 1)"
            $status = "수동진단"
            $commandOutput = "ForceKeyProtection = 1 (Prompt on first use only)"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "사용자 개인키 사용 시 암호 입력이 요구되지 않음 (정책 미설정 또는 ForceKeyProtection = 0)"
            $status = "취약"
            $commandOutput = "ForceKeyProtection = $(if ($null -ne $fkp) { $fkp } else { 'Not set' }) (No password required)"
        }

        $commandExecuted = "reg query 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography' /v ForceKeyProtection"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 레지스트리 확인 필요"
    $status = "수동진단"
    $commandExecuted = "reg query 'HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\Protected' /v ProtectionPolicy"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "디지털 인증서 소유자와 발급 기관 모두 컴퓨터, 저장 장치 또는 개인 키를 보관 사용하는 보호해야 함"
$threat = "사용자 개인 키 암호 입력을 사용하지 않을 경우, 공격자는 해당 키를 사용하여 네트워크 인프라에 액세스해 데이터 유출 등의 위험이 존재함"
$criteria_good = "사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우"
$criteria_bad = "사용자 개인 키를 사용할 때마다 암호 입력을 받지 않는 경우"
$remediation = '''시스템 암호화: 컴퓨터에 저장된 사용자 키에 대해 강력한 키 보호 사용'' 정책을 ''키를 사용할 때마다 암호를 매번 입력해야함''으로 적용'

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
