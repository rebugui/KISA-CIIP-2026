# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-15
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 웹 서비스의 불필요한 스크립트 매핑 제거
# @Description : 불필요한 스크립트 매핑(Handler Mappings), 특히 시스템 실행 파일(.exe, .dll, .bat, .cmd)에 대한 매핑을 제거하여 악의적인 스크립트 실행을 방지합니다. 불필요한 확장자 매핑은 공격자가 악성 스크립트를 업로드하여 실행할 수 있는 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-15"
$ITEM_NAME = "웹 서비스의 불필요한 스크립트 매핑 제거"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Handler Mappings 확인
    $sites = Get-Website
    $unnecessaryHandlers = @()
    $unnecessaryFound = $false

    $unwantedExtensions = @(
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".com",
        ".vbs",
        ".js",
        ".htaccess"
    )

    foreach ($site in $sites) {
        $siteName = $site.Name

        # Handler Mappings 확인
        $handlers = Get-WebConfiguration -Filter "/system.webServer/handlers" -Location $siteName
        if ($handlers) {
            foreach ($handler in $handlers.Collection) {
                $scriptProcessor = $handler.scriptProcessor
                $path = $handler.path

                # 불필요한 확장자 매핑 확인
                foreach ($ext in $unwantedExtensions) {
                    if ($path -eq $ext -or $path -like "*$ext") {
                        $unnecessaryFound = $true
                        $unnecessaryHandlers += "Site: $siteName, Handler: $($handler.name), Path: $path, Processor: $scriptProcessor"
                    }
                }
            }
        }
    }

    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'"

    if ($unnecessaryFound) {
        $finalResult = "VULNERABLE"
        $summary = "불필요한 스크립트 매핑이 발견되었습니다: " + ($unnecessaryHandlers -join ", ")
        $status = "취약"
        $commandOutput = $unnecessaryHandlers -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 스크립트 매핑이 발견되지 않았습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Unnecessary handlers: Not found"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함'
$threat = '웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting)등의 공격 위험이 존재함'
$criteria_good = '불필요한 스크립트 매핑이 존재하지 않는 경우'
$criteria_bad = '불필요한 스크립트 매핑이 존재하는 경우'
$remediation = '불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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
