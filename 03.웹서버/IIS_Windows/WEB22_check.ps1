# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-22
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 하
# @Title       : 에러 페이지 관리
# @Description : 기본 에러 페이지(Default Error Pages)를 커스텀 페이지로 변경하여 서버 내부 구조 및 정보 노출을 방지합니다. 기본 에러 페이지 사용 시 서버 버전, 경로 등 민감한 정보가 노출될 수 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-22"
$ITEM_NAME = "에러 페이지 관리"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: 사용자 지정 오류 페이지 설정 및 errorMode 점검
    # - httpErrors 가 없거나 비어있으면(사용자 지정 에러 페이지 미설정) -> 취약
    # - errorMode 가 Detailed (원격 클라이언트에 상세 오류 노출) -> 취약
    # - 기본 IIS 오류 페이지(custerr) 사용 -> 취약
    $sites = Get-Website
    $vulnSites = @()
    $details = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $siteVuln = @()

        # 사이트가 서버 수준(applicationHost.config) 설정을 상속하는 경우 -Location 은 null 을
        # 반환하므로, -PSPath 로 상속이 반영된 유효(effective) 구성을 조회한다.
        $errorPages = Get-WebConfiguration -Filter "/system.webServer/httpErrors" -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue

        if (-not $errorPages) {
            # 상속을 포함해도 httpErrors 구성이 전혀 없음 -> 사용자 지정 에러 페이지 미지정
            $siteVuln += "httpErrors 미구성(사용자 지정 에러 페이지 없음)"
        } else {
            $errorMode = "$($errorPages.errorMode)"

            # errorMode=Detailed: 원격 클라이언트에 상세 오류 정보 노출
            if ($errorMode -ieq "Detailed") {
                $siteVuln += "errorMode=Detailed (원격 정보 노출)"
            }

            $entryCount = 0
            $defaultPageEntries = @()
            if ($errorPages.Collection) {
                foreach ($error in $errorPages.Collection) {
                    $entryCount++
                    $statusCode = $error.statusCode
                    $path = "$($error.path)"
                    # 기본 IIS 오류 페이지(custerr) 또는 경로 미지정
                    if ($path -like "*custerr*" -or $path -eq "") {
                        $defaultPageEntries += "Code ${statusCode}: 기본 IIS 오류 페이지"
                    }
                }
            }

            # 사용자 지정 에러 페이지 항목이 전혀 없음
            if ($entryCount -eq 0) {
                $siteVuln += "사용자 지정 에러 페이지 항목 없음"
            }
            if ($defaultPageEntries.Count -gt 0) {
                $siteVuln += ($defaultPageEntries -join ", ")
            }
        }

        $details += "Site: $siteName, errorMode: $($errorPages.errorMode), 문제: $($siteVuln -join '|')"

        if ($siteVuln.Count -gt 0) {
            $vulnSites += "Site: $siteName -> " + ($siteVuln -join "; ")
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpErrors'"
    $commandOutput = $details -join "`n"

    if (($null -eq $sites) -or ($sites.Count -eq 0)) {
        $finalResult = "MANUAL"
        $summary = "점검 대상 웹사이트 없음. 수동 확인이 필요합니다."
        $status = "수동진단"
        if ([string]::IsNullOrEmpty($commandOutput)) { $commandOutput = "Get-Website 결과 구성된 웹사이트가 없습니다." }
    } elseif ($vulnSites.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "사용자 지정 에러 페이지가 지정되지 않았거나 상세 오류가 노출되는 사이트가 있습니다: " + ($vulnSites -join " / ")
        $status = "취약"
        $commandOutput = $commandOutput + "`n`n취약 항목:`n" + ($vulnSites -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 사용자 지정 에러 페이지가 지정되어 있으며 상세 오류가 노출되지 않습니다. (보안 권고사항 준수)"
        $status = "양호"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpErrors'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '에러 페이지에서 웹 서버 버전 및 종류, OS 정보 등 웹 서버와 관련된 불필요한 정보 및 에러 코드를 통한 기술적 취약점이 노출되는 것을 최소화하기 위함'
$threat = '에러 페이지에서 불필요한 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점 등을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함 필수 에러 코드에 대해 일원화된 에러 페이지로 관리하지 않는 경우 에러 코드를 통해 각종 정보 유추의 위험이 존재함'
$criteria_good = '웹 서비스 에러 페이지가 별도로 지정된 경우'
$criteria_bad = '웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우'
$remediation = '필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정'

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
