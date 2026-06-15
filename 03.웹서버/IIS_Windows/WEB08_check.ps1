# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-08
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 하
# @Title       : 웹 서비스 파일 업로드 및 다운로드 용량 제한
# @Description : IIS 환경의 파일 업로드/다운로드 용량 제한 설정을 점검합니다. web.config의 maxAllowedContentLength(requestLimits) 및 applicationHost.config의 bufferingLimit/maxRequestEntityAllowed(asp/limits) 설정 여부를 확인하여, 용량 제한이 전혀 설정되지 않은 경우 취약으로 판단합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-08"
$ITEM_NAME = "웹 서비스 파일 업로드 및 다운로드 용량 제한"
$SEVERITY = "하"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: 업로드/다운로드 용량 제한 설정 점검
    # 1) 각 사이트 web.config 의 maxAllowedContentLength (requestLimits)
    # 2) applicationHost.config 의 bufferingLimit / maxRequestEntityAllowed (asp/limits)
    # 제한이 전혀 설정되지 않은 사이트가 있으면 취약.
    # IIS 기본 상속값: maxAllowedContentLength 의 applicationHost.config 전역 기본값은 30000000(30MB).
    # 관리자가 사이트/앱 수준에서 명시적으로 설정하지 않아도 IIS 는 항상 이 상속 기본값을 반환하므로,
    # 단순히 값 존재 여부만 보면 무제한/기본 구성 사이트도 GOOD 로 오판(false-good)된다.
    # 따라서 (a) 속성의 IsInherited 로 명시 설정 여부를 구분하고, (b) 상속 여부를 알 수 없으면 30MB 기본값을
    # "명시적 제한 아님"으로 간주하여 GOOD 로 단정하지 않는다.
    $IIS_DEFAULT_MAX_CONTENT = 30000000
    # asp/limits 스키마 기본값: Classic ASP 설치 시 Get-WebConfiguration 이 모든 사이트에
    # 상속 기본값으로 반환(bufferingLimit=4194304(4MB), maxRequestEntityAllowed=200000).
    # maxAllowedContentLength 와 동일하게, 이 상속 기본값을 명시적 제한으로 오인하면 안 됨.
    $IIS_DEFAULT_BUFFERING_LIMIT = 4194304
    $IIS_DEFAULT_MAX_REQ_ENTITY = 200000

    $sites = Get-Website
    $details = @()
    $unlimitedSites = @()
    $manualSites = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $hasLimit = $false
        $inheritanceUnknown = $false

        # maxAllowedContentLength: web.config 또는 IIS 구성에서 확인
        $maxContent = $null
        $maxContentExplicit = $false
        $reqLimits = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering/requestLimits" -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
        if ($reqLimits -and $reqLimits.maxAllowedContentLength) {
            $maxContent = $reqLimits.maxAllowedContentLength
        }

        # 명시 설정 여부 판별: 구성 속성의 IsInherited 사용 (상속된 전역 기본값과 사이트/앱 명시값 구분)
        $maxContentAttr = $null
        try {
            if ($reqLimits -and $reqLimits.Attributes) {
                $maxContentAttr = $reqLimits.Attributes['maxAllowedContentLength']
            }
        } catch {
            $maxContentAttr = $null
        }
        if ($null -ne $maxContentAttr -and ($maxContentAttr.PSObject.Properties.Name -contains 'IsInherited')) {
            # IsInherited=$false 이면 사이트/앱 수준에서 관리자가 명시적으로 설정한 것
            if (-not $maxContentAttr.IsInherited) {
                $maxContentExplicit = $true
            }
        } else {
            # IsInherited 를 정적으로 확인할 수 없는 경우: 전역 기본값(30MB)과 명시값을 구분할 수 없음
            if ($null -ne $maxContent -and "$maxContent" -ne "" -and [int64]"$maxContent" -ne $IIS_DEFAULT_MAX_CONTENT) {
                # 30MB 기본값과 다른 값이면 관리자가 변경한 명시값으로 간주
                $maxContentExplicit = $true
            } elseif ($null -ne $maxContent -and [int64]"$maxContent" -eq $IIS_DEFAULT_MAX_CONTENT) {
                # 30MB 기본값과 동일 + 상속 여부 불명 → 명시 설정 여부를 단정할 수 없음
                $inheritanceUnknown = $true
            }
        }

        # ASP 한계값(bufferingLimit / maxRequestEntityAllowed)
        $aspLimits = Get-WebConfiguration -Filter "/system.webServer/asp/limits" -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
        $bufferingLimit = $null
        $maxReqEntity = $null
        $maxReqEntityExplicit = $false
        $bufferingLimitExplicit = $false
        if ($aspLimits) {
            $bufferingLimit = $aspLimits.bufferingLimit
            $maxReqEntity = $aspLimits.maxRequestEntityAllowed
        }

        # ASP 한계값도 maxAllowedContentLength 와 동일한 상속-기본값 판별 적용:
        # IsInherited=$false 이면 관리자 명시값. IsInherited 를 확정할 수 없으면 스키마 기본값
        # (200000 / 4194304)과 다른 값일 때만 명시값으로 간주하고, 기본값과 같으면 명시 설정으로 단정 불가.
        $maxReqEntityAttr = $null
        $bufferingLimitAttr = $null
        try {
            if ($aspLimits -and $aspLimits.Attributes) {
                $maxReqEntityAttr = $aspLimits.Attributes['maxRequestEntityAllowed']
                $bufferingLimitAttr = $aspLimits.Attributes['bufferingLimit']
            }
        } catch {
            $maxReqEntityAttr = $null
            $bufferingLimitAttr = $null
        }

        # maxRequestEntityAllowed 명시 설정 여부 판별 (0 또는 미설정 = 무제한 취약 신호)
        if ($null -ne $maxReqEntity -and "$maxReqEntity" -ne "" -and [int64]"$maxReqEntity" -gt 0) {
            if ($null -ne $maxReqEntityAttr -and ($maxReqEntityAttr.PSObject.Properties.Name -contains 'IsInherited')) {
                if (-not $maxReqEntityAttr.IsInherited) {
                    $maxReqEntityExplicit = $true
                }
            } elseif ([int64]"$maxReqEntity" -ne $IIS_DEFAULT_MAX_REQ_ENTITY) {
                # IsInherited 불명 + 스키마 기본값과 다른 값 → 관리자 변경 명시값으로 간주
                $maxReqEntityExplicit = $true
            } else {
                # 스키마 기본값(200000)과 동일 + 상속 여부 불명 → 명시 설정 여부 단정 불가
                $inheritanceUnknown = $true
            }
        }

        # bufferingLimit 명시 설정 여부 판별 (ASP 업로드 버퍼 제한, 가이드라인 Step 3)
        if ($null -ne $bufferingLimit -and "$bufferingLimit" -ne "" -and [int64]"$bufferingLimit" -gt 0) {
            if ($null -ne $bufferingLimitAttr -and ($bufferingLimitAttr.PSObject.Properties.Name -contains 'IsInherited')) {
                if (-not $bufferingLimitAttr.IsInherited) {
                    $bufferingLimitExplicit = $true
                }
            } elseif ([int64]"$bufferingLimit" -ne $IIS_DEFAULT_BUFFERING_LIMIT) {
                # IsInherited 불명 + 스키마 기본값과 다른 값 → 관리자 변경 명시값으로 간주
                $bufferingLimitExplicit = $true
            } else {
                # 스키마 기본값(4194304)과 동일 + 상속 여부 불명 → 명시 설정 여부 단정 불가
                $inheritanceUnknown = $true
            }
        }

        # 명시적으로 설정된 제한(maxAllowedContentLength / ASP 한계값)이 하나라도 있으면 제한 있음으로 판단
        # (상속 기본값은 제외 — false-good 방지)
        if ($maxContentExplicit -or $maxReqEntityExplicit -or $bufferingLimitExplicit) {
            $hasLimit = $true
        }

        $details += "Site: $siteName, maxAllowedContentLength: $maxContent (explicit: $maxContentExplicit), bufferingLimit: $bufferingLimit, maxRequestEntityAllowed: $maxReqEntity"

        if ($hasLimit) {
            # 어떤 명시적 제한이라도 확인되면 해당 사이트는 제한 있음
        } elseif ($inheritanceUnknown) {
            # 30MB 기본값만 존재하고 상속 여부를 정적으로 확정할 수 없음 → 수동 확인 필요 (GOOD 로 단정 금지)
            $manualSites += "Site: $siteName (maxAllowedContentLength 가 IIS 기본값 30MB 이며 명시 설정 여부를 정적으로 확인 불가)"
        } else {
            $unlimitedSites += "Site: $siteName (업로드 용량 제한 미설정)"
        }
    }

    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/requestLimits'; Get-WebConfiguration -Filter '/system.webServer/asp/limits'"
    $commandOutput = $details -join "`n"

    if ($unlimitedSites.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "파일 업로드/다운로드 용량 제한이 설정되지 않은 사이트가 있습니다: " + ($unlimitedSites -join ", ")
        $status = "취약"
        $commandOutput = $commandOutput + "`n`n제한 미설정:`n" + ($unlimitedSites -join "`n")
    } elseif ($manualSites.Count -gt 0) {
        $finalResult = "MANUAL"
        $summary = "일부 사이트의 업로드 용량 제한이 IIS 기본 상속값(30MB)으로만 확인되어 관리자의 명시적 설정 여부를 수동으로 확인해야 합니다: " + ($manualSites -join ", ")
        $status = "수동진단"
        $commandOutput = $commandOutput + "`n`n수동 확인 필요:`n" + ($manualSites -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 파일 업로드/다운로드 용량 제한이 명시적으로 설정되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/requestLimits'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '기반 시설 시스템은 원칙적으로 파일 업로드 및 다운로드를 금지하지만 불가피하게 파일의 업로드 및 다운로드 기능이 필요한 경우, 파일의 용량 제한을 설정하여 불필요한 업로드 및 다운로드를 방지해 서버의 과부하를 예방하고, 웹 서버 자원을 효율적으로 관리하기 위함'
$threat = '웹 서비스의 파일 업로드 및 다운로드의 용량을 제한하지 않은 경우, 악의적인 목적을 가진 사용자가 반복 업로드 및 웹 쉘 공격 등으로 시스템 권한을 탈취하거나 대용량 파일의 업로드 및 다운로드로 서버 자원을 고갈시켜 서비스 장애를 발생시킬 위험이 존재함'
$criteria_good = '파일 업로드 및 다운로드 용량을 제한한 경우'
$criteria_bad = '파일 업로드 및 다운로드 용량을 제한하지 않은 경우'
$remediation = '파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정'

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
