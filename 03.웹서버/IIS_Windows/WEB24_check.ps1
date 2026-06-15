# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 별도의 업로드 경로 사용 및 권한 설정
# @Description : 파일 업로드 경로가 웹 루트 디렉터리와 분리되어 있고 일반 사용자의 접근 권한이 부여되지 않았는지 점검합니다. 각 사이트의 실제 경로(PhysicalPath) 하위에 업로드 디렉터리가 존재하면 웹 루트 내부 업로드로 취약 신호이며, 업로드 경로의 위치 및 권한 분리 여부는 정적으로 단정하기 어려우므로 증거와 함께 수동진단으로 보고합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-24"
$ITEM_NAME = "별도의 업로드 경로 사용 및 권한 설정"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: 업로드 경로 분리 및 일반 사용자 접근 권한 점검
    # 웹 루트(PhysicalPath) 하위에 업로드성 디렉터리가 존재하는지, 존재 시 일반 사용자 쓰기 권한 여부를 확인.
    # 업로드 경로의 외부 분리 여부는 정적으로 단정 곤란 -> 증거와 함께 수동진단.
    $sites = Get-Website
    $commandExecuted = "Get-Website; Get-ChildItem (PhysicalPath); Get-Acl (업로드 디렉터리)"
    $uploadCandidates = @()
    $aclWarnings = @()
    $details = @()
    $uploadKeywords = @("upload", "uploads", "files", "data", "temp", "attach")

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath
        if ($path) {
            $path = [System.Environment]::ExpandEnvironmentVariables($path)
        }

        if (-not $path -or -not (Test-Path $path)) {
            $details += "Site: $siteName, Path: $path (경로 접근 불가)"
            continue
        }

        # 웹 루트 하위 업로드성 디렉터리 탐색
        $subDirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $subDirs) {
            $dirNameLower = $dir.Name.ToLower()
            foreach ($kw in $uploadKeywords) {
                if ($dirNameLower -eq $kw -or $dirNameLower -like "*$kw*") {
                    $uploadCandidates += "Site: $siteName, 웹루트 내 업로드 추정 디렉터리: $($dir.FullName)"

                    # ACL 점검: 일반 사용자(Everyone/Users/Authenticated Users) Allow 권한
                    try {
                        $acl = Get-Acl -Path $dir.FullName
                        foreach ($rule in $acl.Access) {
                            $identity = "$($rule.IdentityReference.Value)"
                            if ($rule.AccessControlType -eq "Allow" -and
                                ($identity -like "*Everyone*" -or $identity -like "*\Users" -or $identity -like "*Authenticated Users*" -or $identity -like "*BUILTIN\Users*")) {
                                $aclWarnings += "Site: $siteName, $($dir.FullName) -> $identity ($($rule.FileSystemRights))"
                            }
                        }
                    } catch {
                        $details += "ACL 확인 실패: $($dir.FullName) ($($_.Exception.Message))"
                    }
                    break
                }
            }
        }
        $details += "Site: $siteName, Path: $path 점검 완료"
    }

    $commandOutput = $details -join "`n"
    if ($uploadCandidates.Count -gt 0) {
        $commandOutput = $commandOutput + "`n`n업로드 추정 디렉터리:`n" + ($uploadCandidates -join "`n")
    }
    if ($aclWarnings.Count -gt 0) {
        $commandOutput = $commandOutput + "`n`n일반 사용자 접근 권한:`n" + ($aclWarnings -join "`n")
    }

    # 업로드 경로의 외부 분리 여부 및 의도된 업로드 디렉터리 식별은 정적 판단 한계 -> 수동진단
    $finalResult = "MANUAL"
    $status = "수동진단"
    if ($uploadCandidates.Count -gt 0 -and $aclWarnings.Count -gt 0) {
        $summary = "웹 루트 내부에 업로드 추정 디렉터리가 존재하고 일반 사용자 접근 권한이 확인되었습니다. 업로드 경로 분리 및 권한 제한을 수동 확인하세요: " + ($aclWarnings -join "; ")
    } elseif ($uploadCandidates.Count -gt 0) {
        $summary = "웹 루트 내부에 업로드 추정 디렉터리가 존재합니다. 별도 경로 사용 여부 및 접근 권한을 수동 확인하세요: " + ($uploadCandidates -join "; ")
    } else {
        $summary = "업로드 경로의 위치 및 권한 분리 여부는 정적으로 단정할 수 없어 수동 확인이 필요합니다."
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-ChildItem (PhysicalPath); Get-Acl"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함'
$threat = '웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음'
$criteria_good = '별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우'
$criteria_bad = '별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우'
$remediation = '기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정'

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
