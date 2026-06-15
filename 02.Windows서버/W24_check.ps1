# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-24
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : FTP 접근 제어 설정
# @Description : FTP 서비스의 IP 기반 접근 제어로 무단 접속 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-24"
$ITEM_NAME = "FTP 접근 제어 설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check FTP IP restriction settings
# 'FTP*' 이름 와일드카드는 'Default FTP Site' 등 비-FTP-접두 사이트를 놓친다.
# 모든 IIS 사이트를 열거하여 FTP 바인딩을 가진 사이트별로 ipSecurity를 점검한다.
# IP 제한이 없는 FTP 사이트가 하나라도 있으면 취약.
try {
    $commandExecuted = "Get-Website | (ftp binding) | Get-WebConfiguration system.ftpServer/security/ipSecurity -Location <site>"

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    if (-not (Get-Command Get-Website -ErrorAction SilentlyContinue)) {
        # IIS 구성 모듈이 없으면 자동 점검 불가.
        $finalResult = "MANUAL"
        $summary = "WebAdministration 모듈을 사용할 수 없어 FTP 접근 제어 설정을 자동으로 확인할 수 없음 (수동 확인 필요)"
        $status = "수동진단"
        $commandOutput = "WebAdministration module unavailable"
    } else {
        $ftpSites = @()
        foreach ($site in @(Get-Website -ErrorAction SilentlyContinue)) {
            $hasFtpBinding = $false
            foreach ($b in @($site.Bindings.Collection)) {
                if ($b.protocol -eq 'ftp') { $hasFtpBinding = $true }
            }
            if ($hasFtpBinding) { $ftpSites += $site }
        }

        if ($ftpSites.Count -eq 0) {
            $finalResult = "GOOD"
            $summary = "FTP 바인딩을 가진 IIS 사이트가 없음 (FTP 서비스 미사용)"
            $status = "양호"
            $commandOutput = "No IIS site with FTP binding"
        } else {
            $unrestricted = @()
            $restricted = @()

            foreach ($site in $ftpSites) {
                $ipSecurity = Get-WebConfiguration -Filter 'system.ftpServer/security/ipSecurity' -PSPath 'IIS:\' -Location $site.Name -ErrorAction SilentlyContinue
                # '특정 IP에서만 접속 허용'은 미등록 클라이언트 접근 거부(AllowUnlisted=false)가 전제이며
                # 허용할 IP에 대한 명시적 Allow 규칙이 하나 이상 있어야 한다(거부-우선 모델).
                # AllowUnlisted=true(IIS 기본값=전체 개방)이면 Allow 규칙이 있어도 미등록 클라이언트가 그대로 접속되므로 취약.
                $ruleCount = 0
                if ($ipSecurity -and $ipSecurity.Collection) { $ruleCount = @($ipSecurity.Collection).Count }
                $allowRuleCount = 0
                if ($ipSecurity -and $ipSecurity.Collection) {
                    $allowRuleCount = @($ipSecurity.Collection | Where-Object { $_.allowed -eq $true }).Count
                }
                $allowUnlisted = if ($ipSecurity) { $ipSecurity.allowUnlisted } else { $true }

                if ($ipSecurity -and ($allowUnlisted -eq $false) -and ($allowRuleCount -gt 0)) {
                    $restricted += "$($site.Name) (AllowUnlisted=$allowUnlisted, Rules=$ruleCount, AllowRules=$allowRuleCount)"
                } else {
                    $unrestricted += "$($site.Name) (AllowUnlisted=$allowUnlisted, Rules=$ruleCount, AllowRules=$allowRuleCount)"
                }
            }

            if ($unrestricted.Count -gt 0) {
                $finalResult = "VULNERABLE"
                $summary = "특정 IP 주소 기반 접근 제어가 설정되지 않은 FTP 사이트가 존재함"
                $status = "취약"
                $commandOutput = "Unrestricted FTP sites: " + ($unrestricted -join '; ')
            } else {
                $finalResult = "GOOD"
                $summary = "모든 FTP 사이트에 IP 주소 기반 접근 제어가 적용됨"
                $status = "양호"
                $commandOutput = "Restricted FTP sites: " + ($restricted -join '; ')
            }
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website | (ftp binding) | Get-WebConfiguration system.ftpServer/security/ipSecurity -Location <site>"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "FTP 접근 시 특정 IP 주소에 대해 콘텐츠 접근을 허용하여 서비스 보안성을 강화하기 위함"
$threat = "FTP 프로토콜은 로그온 시 지정된 자격 증명이나 데이터 자체가 암호화되지 않고 모든 자격 증명을 일반 텍스트로 네트워크를 통해 전송되는 특성상 서버 클라이언트 간 트래픽 스니 핑을 통해 인증 정보가 쉽게 노출될 위험이 존재함"
$criteria_good = "특정 IP 주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우"
$criteria_bad = "특정 IP 주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용하지 않는 경우 ※조치 시 마스터 속성과 모든 사이트에 적용함"
$remediation = "특정 IP 주소에서만 FTP 서버에 접속하도록 접근 제어 설정"

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
