# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-21
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 암호화되지 않는 FTP 서비스 비활성화
# @Description : FTP 서비스 비활성화로 평문 암호 전송 방지 및 데이터 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-21"
$ITEM_NAME = "암호화되지 않는 FTP 서비스 비활성화"
$SEVERITY = "상"
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

# 1. Check if FTP service is running
# 가이드라인: 'FTP Publishing Service(Windows 2012 이상: Microsoft FTP Service)'
# Windows 2012+ 의 IIS FTP 서비스명은 FTPSVC(Microsoft FTP Service)이며,
# 구버전 IIS FTP 서비스명은 MSFTPSVC(FTP Publishing Service)이므로 두 서비스를 모두 점검한다.
try {
    $commandExecuted = "Get-Service -Name 'MSFTPSVC','FTPSVC'"
    $ftpServices = @(Get-Service -Name 'MSFTPSVC', 'FTPSVC' -ErrorAction SilentlyContinue)

    $runningServices = @($ftpServices | Where-Object { $_.Status -eq 'Running' })

    if ($runningServices.Count -gt 0) {
        # 암호화되지 않는 OS 기본 FTP 서비스가 실제 구동 중 → 취약.
        $detail = ($runningServices | ForEach-Object { "$($_.Name): $($_.Status)" }) -join '; '
        $finalResult = "VULNERABLE"
        $summary = "암호화되지 않는 FTP 서비스가 실행 중 (평문 암호 전송으로 보안 위험): $detail"
        $status = "취약"
        $commandOutput = $detail
    } else {
        $finalResult = "GOOD"
        $summary = "FTP 서비스가 비활성화됨 (또는 중지됨)"
        $status = "양호"
        $commandOutput = if ($ftpServices.Count -gt 0) {
            ($ftpServices | ForEach-Object { "$($_.Name): $($_.Status)" }) -join '; '
        } else {
            "FTP Service not installed (MSFTPSVC/FTPSVC)"
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name 'MSFTPSVC','FTPSVC'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "인증 정보가 기본적으로 평문 전송되는 취약한 프로토콜인 FTP의 사용을 제한하기 위함"
$threat = "OS에서 제공하는 기본적인 FTP 서비스를 사용할 경우 계정과 패스워드가 암호화되지 않은 채로 전송되어 Sniffer에 의한 계정 정보의 노출 위험이 존재함"
$criteria_good = "FTP 서비스를 사용하지 않는 경우 또는 SecureFTP 서비스를 사용하는 경우"
$criteria_bad = "암호화되지 않는 FTP 서비스를 사용하는 경우"
$remediation = "FTP 서비스가 필요하지 않다면 서비스 중지 또는 SecureFTP 응용 프로그램 사용"

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
