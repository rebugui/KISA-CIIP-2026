# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 웹 서비스 설정 파일 노출 제한
# @Description : IIS 처리기 매핑(handler mappings)에서 *.asa/*.asax 스크립트 매핑 존재 여부와 요청 필터링(requestFiltering)의 파일 확장명 거부 목록(.asa/.asax 등록) 여부를 점검합니다. 스크립트 매핑이 존재하거나 파일 필터링이 설정되지 않은 경우 취약으로 판단합니다. (가이드: asa/asax 스크립트 매핑 또는 파일 필터링 중 하나라도 설정 시 취약)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-13"
$ITEM_NAME = "웹 서비스 설정 파일 노출 제한"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: *.asa/*.asax 처리기 매핑 및 요청 필터링 거부 목록 점검
    # 가이드: asa/asax 스크립트 매핑이 존재하거나, 파일 확장명 거부 목록에 미등록 시 취약.
    $sites = Get-Website
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/fileExtensions'"
    $dangerousExts = @(".asa", ".asax")
    $vulnSites = @()
    $details = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $activeMappings = @()
        $deniedExts = @()

        # 1) 처리기 매핑에서 *.asa / *.asax 확인
        $handlers = Get-WebConfiguration -Filter "/system.webServer/handlers" -Location $siteName -ErrorAction SilentlyContinue
        if ($handlers) {
            foreach ($handler in $handlers.Collection) {
                $hPath = "$($handler.path)"
                foreach ($ext in $dangerousExts) {
                    if ($hPath -like "*$ext") {
                        $activeMappings += "$hPath -> $($handler.name)"
                    }
                }
            }
        }

        # 2) 요청 필터링 파일 확장명 거부 목록 확인
        $fileExts = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering/fileExtensions" -Location $siteName -ErrorAction SilentlyContinue
        if ($fileExts) {
            foreach ($fe in $fileExts.Collection) {
                $feName = "$($fe.fileExtension)".ToLower()
                $allowed = $fe.allowed
                if (($allowed -eq $false) -or ("$allowed" -ieq "false")) {
                    $deniedExts += $feName
                }
            }
        }

        # 거부 목록 미등록 확장자(참고용 — 1차 완화책인 매핑 제거 시 취약 아님)
        $missingDeny = @()
        foreach ($ext in $dangerousExts) {
            if ($deniedExts -notcontains $ext) {
                $missingDeny += $ext
            }
        }

        $details += "Site: $siteName, 활성 매핑: $($activeMappings -join '|'), 거부목록: $($deniedExts -join '|'), 거부목록 미등록: $($missingDeny -join '|')"

        # 취약 판정: 활성 *.asa/*.asax 스크립트 매핑이 존재(미제거)하는 경우에만 취약.
        # 처리기 매핑이 제거되면 1차 완화가 충족되므로(criteria_good) 거부 목록 미등록만으로는 취약 아님.
        # (거부 목록 등록은 매핑 제거에 대한 보조/대체 통제임)
        if ($activeMappings.Count -gt 0) {
            $vulnSites += "Site: $siteName, 활성 asa/asax 매핑 존재: $($activeMappings -join ', ')"
        }
    }

    $commandOutput = $details -join "`n"

    if ($vulnSites.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "활성 asa/asax 스크립트 매핑이 제거되지 않은 사이트가 있습니다: " + ($vulnSites -join "; ")
        $status = "취약"
        $commandOutput = $commandOutput + "`n`n취약 항목:`n" + ($vulnSites -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에서 불필요한 asa/asax 스크립트 매핑이 제거되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/handlers'; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/fileExtensions'"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹 서비스에서 DB 연결 파일에 대한 접근 권한 제한 및 불필요한 스크립트 매핑을 제거하여, DB 연결 정보(사용자 이름, 비밀번호 등)가 외부에 노출되거나 공격자의 DB 접근 및 관리자 권한 획득 등의 다양한 공격을 방지하기 위함'
$threat = '웹 서비스에서 DB 연결 파일에 대한 접근 권한 제한 및 불필요한 스크립트 매핑을 제거하지 않을 경우, DB 연결 파일에 존재하는 데이터 베이스 관련 정보(IP 주소, DB 명, 비밀번호), 서버 내부 IP 주소, 웹 서비스 환경 설정 정보 등 보안상 민감한 내용이 악의적인 사용자에게 노출될 위험이 존재함'
$criteria_good = '일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우'
$criteria_bad = '일반 사용자의 DB 연결 파일에 대한 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우'
$remediation = 'DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정'

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
