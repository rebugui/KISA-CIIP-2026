# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-25
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 최신 보안 패치 적용 여부 및 패치 적용 정책 수립 여부를 점검합니다. IIS/Windows Server 버전(레지스트리 HKLM\SOFTWARE\Microsoft\InetStp VersionString)을 증거로 수집하되, 최신 패치 여부는 벤더 공지와의 대조 및 정책 확인이 필요한 항목으로 자동 판정할 수 없으므로 버전 증거와 함께 수동진단으로 보고합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-25"
$ITEM_NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS/Windows Server 버전 정보 수집 (증거용). 패치 최신성은 자동 판정 불가 -> 수동진단.
    $regPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
    $commandExecuted = "reg query 'HKLM\SOFTWARE\Microsoft\InetStp' /v VersionString"
    $evidence = @()

    if (Test-Path $regPath) {
        $inetStp = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($inetStp) {
            if ($inetStp.VersionString) { $evidence += "IIS VersionString: $($inetStp.VersionString)" }
            if ($inetStp.MajorVersion) { $evidence += "MajorVersion: $($inetStp.MajorVersion)" }
            if ($inetStp.MinorVersion) { $evidence += "MinorVersion: $($inetStp.MinorVersion)" }
        }
    } else {
        $evidence += "InetStp 레지스트리 키를 찾을 수 없음 (IIS 미설치 가능성)"
    }

    # Windows OS 버전 추가 증거
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $evidence += "OS: $($os.Caption), Version: $($os.Version), Build: $($os.BuildNumber)"
        }
    } catch {
        # OS 정보 수집 실패는 무시 (증거 보조용)
    }

    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "최신 보안 패치 적용 여부 및 패치 정책 수립 여부는 벤더 공지 대조와 정책 확인이 필요하여 자동 판정할 수 없습니다. 수집된 버전 정보를 기준으로 수동 확인하세요. (참고: https://www.iis.net/downloads/microsoft)"
    $commandOutput = ($evidence -join "`n")
    if (-not $commandOutput) {
        $commandOutput = "버전 정보를 수집하지 못했습니다. 수동 확인 필요."
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "reg query 'HKLM\SOFTWARE\Microsoft\InetStp' /v VersionString"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '주기적인 최신 보안 패치를 통해 보안성 및 시스템 안정성을 확보하기 위함'
$threat = '주기적으로 최신 보안 패치를 적용하지 않을 경우, 알려진 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고 발생 위험이 존재함'
$criteria_good = '최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우'
$criteria_bad = '최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지'
$remediation = '패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정'

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

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
