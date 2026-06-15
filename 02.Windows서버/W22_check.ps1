# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-22
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : FTP 디렉토리 접근 권한 설정
# @Description : FTP 디렉토리의 쓰기 권한 제거로 무단 파일 업로드 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-22"
$ITEM_NAME = "FTP 디렉토리 접근 권한 설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check FTP home directory permissions
# 가이드라인 판단기준: 'FTP 홈 디렉터리에 Everyone 권한이 있는 경우' = 취약 (쓰기 한정 아님, 모든 Everyone 권한 대상).
# FTP 홈 디렉터리 경로는 하드코딩하지 않고 IIS FTP 사이트 구성에서 실제 physicalPath를 해석한다.
# 경로를 해석할 수 없으면 GOOD으로 단정하지 않고 MANUAL로 처리한다.
try {
    $commandExecuted = "Import-Module WebAdministration; (Get-Website | Where binding=ftp).physicalPath | Get-Acl"

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    # IIS에서 FTP 바인딩을 가진 모든 사이트의 홈 디렉터리 경로를 수집한다.
    $ftpRoots = @()
    $ftpSitesFound = $false
    if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
        $sites = @(Get-Website -ErrorAction SilentlyContinue)
        foreach ($site in $sites) {
            $hasFtpBinding = $false
            foreach ($b in @($site.Bindings.Collection)) {
                if ($b.protocol -eq 'ftp') { $hasFtpBinding = $true }
            }
            if ($hasFtpBinding) {
                $ftpSitesFound = $true
                $resolved = [System.Environment]::ExpandEnvironmentVariables([string]$site.physicalPath)
                if (-not [string]::IsNullOrWhiteSpace($resolved)) {
                    $ftpRoots += [PSCustomObject]@{ Name = $site.Name; Path = $resolved }
                }
            }
        }
    }

    if (-not $ftpSitesFound) {
        # FTP 사이트 자체가 없으면 FTP 홈 디렉터리 점검 대상 없음 → 양호.
        $finalResult = "GOOD"
        $summary = "IIS에 FTP 사이트가 구성되어 있지 않음 (FTP 서비스 미사용)"
        $status = "양호"
        $commandOutput = "No IIS FTP site configured"
    } else {
        $resolvableRoots = @($ftpRoots | Where-Object { Test-Path $_.Path })
        $unresolvable = @($ftpRoots | Where-Object { -not (Test-Path $_.Path) })

        if ($resolvableRoots.Count -eq 0) {
            # FTP 사이트는 있으나 홈 디렉터리 경로를 해석/접근할 수 없음 → 자동 단정 불가, 수동 진단.
            $finalResult = "MANUAL"
            $summary = "FTP 사이트는 존재하나 홈 디렉터리 경로를 해석할 수 없어 Everyone 권한을 자동으로 점검할 수 없음 (수동 확인 필요)"
            $status = "수동진단"
            $commandOutput = "Unresolvable FTP roots: " + (($ftpRoots | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join '; ')
        } else {
            $hasEveryone = $false
            $everyonePermissions = @()

            foreach ($root in $resolvableRoots) {
                $acl = Get-Acl -Path $root.Path -ErrorAction SilentlyContinue
                if ($acl) {
                    foreach ($access in $acl.Access) {
                        # 권한 종류(읽기/쓰기 등)와 무관하게 Everyone에 대한 모든 Allow 권한을 취약으로 간주.
                        # Everyone 계정은 로케일에 따라 현지화됨(한국어: '모든 사람')되므로 이름 매칭은
                        # 신뢰할 수 없음. well-known SID S-1-1-0으로 변환해 비교한다(W-43/W-58과 동일).
                        $sid = $null
                        try {
                            $sid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch {
                            $sid = $null
                        }
                        if ($access.AccessControlType -eq 'Allow' -and ($sid -eq 'S-1-1-0' -or $access.IdentityReference.Value -like '*Everyone*')) {
                            $hasEveryone = $true
                            $everyonePermissions += "$($root.Name) [$($root.Path)] $($access.IdentityReference): $($access.FileSystemRights)"
                        }
                    }
                }
            }

            if ($hasEveryone) {
                $finalResult = "VULNERABLE"
                $summary = "FTP 홈 디렉터리에 Everyone 권한이 존재함"
                $status = "취약"
                $commandOutput = $everyonePermissions -join '; '
            } elseif ($unresolvable.Count -gt 0) {
                # 해석된 경로에는 Everyone 권한이 없으나, 일부 FTP 홈 경로를 해석/접근할 수 없어
                # 해당 경로의 Everyone 권한을 확인할 수 없음 → 자동 양호 단정 불가, 수동 진단.
                $finalResult = "MANUAL"
                $summary = "일부 FTP 홈 디렉터리 경로를 해석할 수 없어 Everyone 권한을 자동으로 점검할 수 없음 (수동 확인 필요)"
                $status = "수동진단"
                $checked = ($resolvableRoots | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join '; '
                $commandOutput = "Checked (no Everyone): $checked; Unresolved roots requiring manual check: " + (($unresolvable | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join ', ')
            } else {
                $finalResult = "GOOD"
                $summary = "FTP 홈 디렉터리에 Everyone 권한이 없음"
                $status = "양호"
                $checked = ($resolvableRoots | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join '; '
                $commandOutput = "No Everyone permission on FTP home directory. Checked: $checked"
            }
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Import-Module WebAdministration; (Get-Website | Where binding=ftp).physicalPath | Get-Acl"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "FTP 서비스 디렉터리의 접근 권한을 적절하게 설정하여 의도치 않은 정보 유출을 방지하기 위함"
$threat = "FTP 홈 디렉터리에 과도한 권한(예. Everyone Full Control)이 부여된 경우 임의의 사용자가 쓰기, 수정이 가능하여 정보 유출, 파일 위 ‧ 변조 등의 위험이 존재함"
$criteria_good = "FTP 홈 디렉터리에 Everyone 권한이 없는 경우"
$criteria_bad = "FTP 홈 디렉터리에 Everyone 권한이 있는 경우"
$remediation = "FTP 홈 디렉터리에서 Everyone 권한 삭제, 각 사용자에게 적절한 권한 부여"

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
