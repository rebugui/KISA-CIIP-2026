# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-19
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 웹 서비스 SSI(Server Side Includes)사용 제한
# @Description : IIS 처리기 매핑(Handler Mappings)에서 SSI 관련 확장자(.shtml, .shtm, .stm) 매핑 존재 여부를 점검합니다. 가이드라인에 따라 해당 확장자 매핑이 존재하면 SSI가 활성화된 것으로 보아 취약으로 판단합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-19"
$ITEM_NAME = "웹 서비스 SSI(Server Side Includes)사용 제한"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: 처리기 매핑에서 SSI 확장자(.shtml/.shtm/.stm) 매핑 존재 여부 점검
    $sites = Get-Website
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'"
    $ssiExtensions = @(".shtml", ".shtm", ".stm")
    $ssiMappings = @()
    $details = @()

    foreach ($site in $sites) {
        $siteName = $site.Name

        $handlers = Get-WebConfiguration -Filter "/system.webServer/handlers" -Location $siteName -ErrorAction SilentlyContinue
        if ($handlers) {
            foreach ($handler in $handlers.Collection) {
                $hPath = "$($handler.path)".ToLower()
                foreach ($ext in $ssiExtensions) {
                    if ($hPath -like "*$ext") {
                        $ssiMappings += "Site: $siteName, 매핑: $($handler.path) -> $($handler.name)"
                    }
                }
            }
        }
        $details += "Site: $siteName 처리기 매핑 점검 완료"
    }

    $commandOutput = $details -join "`n"

    if (-not $sites -or $sites.Count -eq 0) {
        # 사이트가 열거되지 않으면 사이트 범위에서는 매핑 점검 불가하며,
        # 서버(applicationHost.config) 범위의 SSI 핸들러(SSINC-shtml/SSINC-shtm/SSINC-stm)
        # 잔존 가능성을 정적 분석으로 단정할 수 없어 수동 확인이 필요함.
        $finalResult = "MANUAL"
        $summary = "점검할 웹 사이트가 없습니다. 서버 수준(applicationHost.config) SSI 핸들러 매핑(.shtml/.shtm/.stm) 잔존 여부에 대한 수동 확인이 필요합니다."
        $status = "수동진단"
        if ([string]::IsNullOrWhiteSpace($commandOutput)) { $commandOutput = "Get-Website 결과: 사이트 없음" }
    } elseif ($ssiMappings.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "SSI 확장자(.shtml/.shtm/.stm) 처리기 매핑이 존재합니다: " + ($ssiMappings -join "; ")
        $status = "취약"
        $commandOutput = ($ssiMappings -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "SSI 확장자(.shtml/.shtm/.stm) 처리기 매핑이 존재하지 않습니다. (보안 권고사항 준수)"
        $status = "양호"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함'
$threat = '웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함'
$criteria_good = '웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우'
$criteria_bad = '웹 서비스 SSI 사용 설정이 활성화되어 있는 경우'
$remediation = '웹 서비스 내 불필요한 SSI 사용 제한 설정'

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
