# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-12
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 웹 서비스 링크 사용 금지
# @Description : 각 웹 사이트의 실제 경로(PhysicalPath)를 탐색하여 바로가기(.lnk) 파일 및 재분석 지점(ReparsePoint, 정션/심볼릭 링크) 존재 여부를 점검합니다. 링크가 발견되면 취약, 없으면 양호, 경로 탐색이 불가능하면 수동진단으로 판단합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-12"
$ITEM_NAME = "웹 서비스 링크 사용 금지"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: 각 사이트 PhysicalPath 내 바로가기(.lnk) 및 ReparsePoint(정션/심볼릭 링크) 탐색
    $sites = Get-Website
    $commandExecuted = "Get-Website; Get-ChildItem -Recurse (PhysicalPath) -> .lnk / ReparsePoint 탐색"
    $linkFindings = @()
    $unreadable = @()
    $scannedDetails = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # 환경변수 확장 (%SystemDrive% 등)
        if ($path) {
            $path = [System.Environment]::ExpandEnvironmentVariables($path)
        }

        if (-not $path -or -not (Test-Path $path)) {
            $unreadable += "Site: $siteName, Path: $path (경로 접근 불가)"
            continue
        }

        try {
            $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction Stop
            $scannedDetails += "Site: $siteName, Path: $path (탐색 완료)"

            foreach ($item in $items) {
                # 바로가기 파일
                if ($item.Extension -eq ".lnk") {
                    $linkFindings += "Site: $siteName, 바로가기 파일: $($item.FullName)"
                }
                # 재분석 지점 (정션/심볼릭 링크)
                if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    $linkFindings += "Site: $siteName, ReparsePoint(링크/정션): $($item.FullName)"
                }
            }
        } catch {
            $unreadable += "Site: $siteName, Path: $path (탐색 실패: $($_.Exception.Message))"
        }
    }

    if ($linkFindings.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "웹 사이트 실제 경로에서 링크(바로가기/ReparsePoint)가 발견되었습니다: " + ($linkFindings -join "; ")
        $status = "취약"
        $commandOutput = ($linkFindings -join "`n")
    } elseif ($unreadable.Count -gt 0) {
        # 일부 사이트라도 경로 접근/탐색이 불가능하면(누락된 사이트에 링크가 숨어 있을 수 있으므로)
        # 전수 탐색이 보장되지 않은 것이므로 양호로 단정하지 않고 수동진단 처리한다.
        # (전수 탐색이 모두 성공한 경우에만 아래 else 분기에서 양호로 판단)
        $finalResult = "MANUAL"
        $summary = "일부 웹 사이트 실제 경로를 탐색할 수 없어 링크 부재를 전수 확인하지 못했습니다. 수동 확인이 필요합니다: " + ($unreadable -join "; ")
        $status = "수동진단"
        $commandOutput = "탐색 불가 경로:`n" + ($unreadable -join "`n")
        if ($scannedDetails.Count -gt 0) {
            $commandOutput = $commandOutput + "`n`n탐색 완료 경로:`n" + ($scannedDetails -join "`n")
        }
    } else {
        $finalResult = "GOOD"
        $summary = "웹 사이트 실제 경로에서 바로가기/링크가 발견되지 않았습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = ($scannedDetails -join "`n")
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-ChildItem -Recurse (PhysicalPath)"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함'
$threat = '보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함'
$criteria_good = '심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우'
$criteria_bad = '심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우'
$remediation = '웹 서비스 링크 사용 제한 설정'

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
