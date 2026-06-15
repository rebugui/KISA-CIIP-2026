# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
# @Description : 웹서비스 경로 내 백업 파일(.bak), 설정 파일(.config), 소스 코드 등 민감한 파일에 대한 웹 접근을 차단하여 정보 노출을 방지합니다. IIS Request Filtering을 사용하여 파일 확장자별 접근 제어가 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-14"
$ITEM_NAME = "웹 서비스 경로 내 파일의 접근 통제"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

# 광범위(broad) 보안 주체 여부 판단: Everyone/Users/Authenticated Users/Guests/Domain Users
function Test-Web14BroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)

    try {
        $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $sid = [string]$Identity
    }

    return @(
        $sid -eq 'S-1-1-0',           # Everyone
        $sid -eq 'S-1-5-11',          # Authenticated Users
        $sid -eq 'S-1-5-32-545',      # BUILTIN\Users
        $sid -eq 'S-1-5-32-546',      # Guests
        $sid -match '-513$',          # Domain Users
        ([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|\bUsers\b|Guests|Domain Users'
    ) -contains $true
}

function Test-Web14AnyRight {
    param(
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.FileSystemRights[]]$Expected
    )
    foreach ($right in $Expected) {
        if (($Rights -band $right) -eq $right) { return $true }
    }
    return $false
}

# 지정 경로의 ACL에서 광범위 주체의 읽기/쓰기 권한 증거를 수집
function Get-Web14AclEvidence {
    param([string]$Path, [string]$Role)

    $readRights = @(
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.FileSystemRights]::ListDirectory
    )
    $writeRights = @(
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.FileSystemRights]::WriteData,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::CreateFiles,
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" }
    }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-Web14BroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = Test-Web14AnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-Web14AnyRight -Rights $rule.FileSystemRights -Expected $readRights
        if ($hasWrite -or $hasRead) {
            [pscustomobject]@{
                Path = $Path
                Role = $Role
                Access = if ($hasWrite) { 'Write' } else { 'Read' }
                Principal = [string]$rule.IdentityReference
                Rights = [string]$rule.FileSystemRights
            }
        }
    }
}

try {
    # WEB-14는 파일 존재 여부가 아니라 '접근 권한(ACL)'을 점검해야 함.
    # 웹 루트 및 민감 설정 파일(web.config 등)에 광범위 주체의 읽기/쓰기 권한이
    # 부여되어 있으면 취약(criteria_bad)으로 판정한다.
    $sites = @(Get-Website)
    $assessedPaths = [System.Collections.Generic.List[object]]::new()
    $sensitiveLeafNames = @('web.config', 'global.asax', 'connectionstrings.config', 'machine.config', 'applicationhost.config')

    foreach ($site in $sites) {
        $path = $site.PhysicalPath
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($path)
        if (-not (Test-Path -LiteralPath $expanded)) {
            # 웹 루트를 확인할 수 없으면 양호로 단정하지 않고 별도 표시 → 최종 MANUAL 유도
            $assessedPaths.Add([pscustomobject]@{ Path = $expanded; Role = 'WebRoot(Unresolved)'; SiteName = $site.Name }) | Out-Null
            continue
        }

        $assessedPaths.Add([pscustomobject]@{ Path = $expanded; Role = 'WebRoot'; SiteName = $site.Name }) | Out-Null

        # 웹 루트 내 민감 설정 파일도 개별 ACL 점검
        foreach ($leaf in $sensitiveLeafNames) {
            $sf = Get-ChildItem -LiteralPath $expanded -Filter $leaf -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $sf) {
                $assessedPaths.Add([pscustomobject]@{ Path = $file.FullName; Role = 'SensitiveFile'; SiteName = $site.Name }) | Out-Null
            }
        }
    }

    $commandExecuted = "Get-Website; Get-Acl on each site PhysicalPath and sensitive config files (web.config 등); broad-principal Read/Write 검사"

    if ($assessedPaths.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "IIS 사이트의 물리 경로를 확인할 수 없습니다. 웹 서비스 경로 및 주요 설정 파일의 접근 권한을 수동으로 확인하세요."
        $commandOutput = "No resolvable IIS site physical paths."
    }
    else {
        $aclEvidence = foreach ($p in $assessedPaths) {
            if ($p.Role -eq 'WebRoot(Unresolved)') {
                [pscustomobject]@{ Path = $p.Path; Role = 'WebRoot(Unresolved)'; Access = 'Unknown'; Principal = 'N/A'; Rights = "Site '$($p.SiteName)' physical path not accessible" }
            } else {
                Get-Web14AclEvidence -Path $p.Path -Role $p.Role
            }
        }
        $aclEvidence = @($aclEvidence | Where-Object { $_ })

        # 취약: 광범위 주체에 쓰기 권한, 또는 ACL 확인 불가(Unknown), 또는 민감 파일에 광범위 읽기
        $vulnerableEvidence = @($aclEvidence | Where-Object {
            $_.Access -eq 'Write' -or
            ($_.Role -eq 'SensitiveFile' -and $_.Access -eq 'Read')
        })
        # ACL 확인 불가 또는 웹 루트에 광범위 읽기 → 수동진단(양호로 단정 불가)
        $manualEvidence = @($aclEvidence | Where-Object {
            $_.Access -eq 'Unknown' -or
            ($_.Role -eq 'WebRoot' -and $_.Access -eq 'Read')
        })

        $commandOutput = if ($aclEvidence) {
            ($aclEvidence | ForEach-Object { "$($_.Role): $($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n"
        } else {
            "No broad Everyone/Users/Authenticated Users/Guests/Domain Users ACL entries found on assessed IIS paths."
        }

        if ($vulnerableEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "웹 서비스 경로 또는 주요 설정 파일에 일반 사용자(광범위 주체)의 불필요한 접근 권한이 부여되어 있습니다."
        }
        elseif ($manualEvidence.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "웹 루트에 광범위 읽기 권한이 있거나 일부 경로의 ACL을 확인할 수 없습니다. 해당 권한의 필요 여부 및 민감 파일 노출 여부를 수동으로 확인하세요."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "웹 서비스 경로 및 주요 설정 파일에 일반 사용자의 불필요한 접근 권한이 부여되어 있지 않습니다. (보안 권고사항 준수)"
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-Acl -Path [SitePath]"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함'
$threat = '웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함'
$criteria_good = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우'
$criteria_bad = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우'
$remediation = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정'

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
