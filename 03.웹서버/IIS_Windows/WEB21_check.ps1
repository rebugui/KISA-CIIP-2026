# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : HTTP 접근 시 HTTPS로의 리디렉션 활성화 여부를 점검합니다. 각 사이트의 SSL(https) 바인딩 존재 여부와 URL Rewrite 규칙(또는 httpRedirect) 설정을 확인하여, HTTPS 리디렉션이 구성되어 있으면 양호, 명확히 미설정이면 취약, 정적 판단이 어려운 경우 수동진단으로 판단합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-21"
$ITEM_NAME = "HTTP 리디렉션"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: HTTP -> HTTPS 리디렉션 점검
    # 판단 근거: (1) SSL(https) 바인딩 존재, (2) URL Rewrite 규칙 또는 httpRedirect 설정
    $sites = Get-Website
    $commandExecuted = "Get-Website; Get-WebBinding; Get-WebConfiguration -Filter '/system.webServer/rewrite/rules'; Get-WebConfiguration -Filter '/system.webServer/httpRedirect'"
    $redirectConfigured = @()
    $noRedirect = @()
    $details = @()

    foreach ($site in $sites) {
        $siteName = $site.Name

        # https 바인딩 존재 여부
        $bindings = $site.Bindings.Collection
        $hasHttps = $false
        if ($bindings) {
            foreach ($b in $bindings) {
                if ("$($b.protocol)" -ieq "https") {
                    $hasHttps = $true
                }
            }
        }

        # URL Rewrite 규칙 존재 여부 (HTTPS 리디렉션 추정)
        $hasRewrite = $false
        $rules = Get-WebConfiguration -Filter "/system.webServer/rewrite/rules" -Location $siteName -ErrorAction SilentlyContinue
        if ($rules -and $rules.Collection) {
            foreach ($rule in $rules.Collection) {
                $action = "$($rule.action.type)"
                $actionUrl = "$($rule.action.url)"
                if ($action -ieq "Redirect" -and $actionUrl -match "https") {
                    $hasRewrite = $true
                }
            }
        }

        # httpRedirect 설정 (https 대상)
        $hasHttpRedirect = $false
        $httpRedirect = Get-WebConfiguration -Filter "/system.webServer/httpRedirect" -Location $siteName -ErrorAction SilentlyContinue
        if ($httpRedirect -and ("$($httpRedirect.enabled)" -ieq "true") -and ("$($httpRedirect.destination)" -match "https")) {
            $hasHttpRedirect = $true
        }

        $details += "Site: $siteName, HTTPS바인딩: $hasHttps, URLRewrite(https): $hasRewrite, httpRedirect(https): $hasHttpRedirect"

        if (($hasRewrite -or $hasHttpRedirect) -and $hasHttps) {
            $redirectConfigured += "Site: $siteName (HTTPS 리디렉션 구성됨)"
        } elseif (-not $hasHttps) {
            $noRedirect += "Site: $siteName (HTTPS 바인딩 없음 - 리디렉션 불가)"
        } else {
            # https 바인딩은 있으나 리디렉션 규칙을 정적으로 확인 불가
            $noRedirect += "Site: $siteName (HTTPS 리디렉션 규칙 미확인)"
        }
    }

    $commandOutput = $details -join "`n"

    if ($sites.Count -eq 0) {
        $finalResult = "MANUAL"
        $summary = "점검할 웹 사이트가 없습니다. 수동 확인이 필요합니다."
        $status = "수동진단"
    } elseif ($noRedirect.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 HTTPS 리디렉션이 구성되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
    } else {
        # URL Rewrite 모듈 미설치 등으로 규칙 판단이 정적으로 어려운 경우가 포함되므로 수동진단
        $finalResult = "MANUAL"
        $summary = "HTTPS 리디렉션 구성이 확인되지 않은 사이트가 있어 수동 확인이 필요합니다: " + ($noRedirect -join "; ")
        $status = "수동진단"
        $commandOutput = $commandOutput + "`n`n확인 필요:`n" + ($noRedirect -join "`n")
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/rewrite/rules'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평 문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함'
$threat = 'HTTP 통신은 암호화 전송이 아닌 평 문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함'
$criteria_good = 'HTTP 접근 시 HTTPSRedirection이 활성화된 경우'
$criteria_bad = 'HTTP 접근 시 HTTPSRedirection이 비활성화된 경우'
$remediation = 'HTTP Redirection 활성화 설정'

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
