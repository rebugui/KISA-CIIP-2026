# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-26
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 로그 디렉터리 및 파일 권한 설정
# @Description : IIS 로그 디렉터리(C:\Windows\System32\LogFiles) 및 파일의 권한을 제한하여 비인가자의 로그 파일 접근을 차단합니다. 로그 파일에는 공격자에게 유용한 정보가 포함될 수 있으며 권한 미설정 시 정보유출, 로그파일 훼손 및 변조 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-26"
$ITEM_NAME = "로그 디렉터리 및 파일 권한 설정"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 로그 디렉터리 경로 확인
    $logDir = "C:\Windows\System32\LogFiles"
    $permissionIssues = @()
    $aclDetails = @()

    if (Test-Path $logDir) {
        # 로그 디렉터리 ACL 확인
        $acl = Get-Acl -Path $logDir
        $commandExecuted = "Get-Acl -Path '$logDir'"

        # 광범위 주체(일반 사용자 그룹) 판정 함수: BUILTIN\Users 를 제외하지 않음
        # 대상: Everyone, BUILTIN\Users, Authenticated Users, Users, Guests, Domain Users 등
        # 한국어 로케일 Windows에서는 Get-Acl 이 잘 알려진 SID 를 번역된 이름(예: Everyone -> '모든 사람')으로
        # 반환하므로 영문 문자열 비교만으로는 누락된다. 따라서 SID 로 변환하여 well-known SID 를 비교하고,
        # 변환 실패 시에만 영문 이름 정규식을 보조 수단으로 사용한다.
        function Test-BroadPrincipal {
            param([System.Security.Principal.IdentityReference]$Identity)

            try {
                $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                $sid = [string]$Identity
            }

            return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|\bUsers\b|Guests|Domain Users')
        }

        # ACL 분석: 모든 규칙 검사 (BUILTIN 제외 필터 제거)
        foreach ($rule in $acl.Access) {
            $identity = $rule.IdentityReference.Value
            $rights = $rule.FileSystemRights
            $type = $rule.AccessControlType

            # 광범위 주체에 Allow 권한(읽기 포함 모든 접근)이 있으면 취약
            if ($type -eq "Allow" -and (Test-BroadPrincipal $rule.IdentityReference)) {
                $permissionIssues += "ID: $identity, 권한: $rights, 타입: $type"
            }

            $aclDetails += "ID: $identity, 권한: $rights, 타입: $type, 상속: $($rule.IsInherited)"
        }

        # 로그 파일 권한 샘플링 (샘플링 상한 확대: 5 -> 200)
        $logFiles = Get-ChildItem -Path $logDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 200
        $filePermissionDetails = @()

        foreach ($file in $logFiles) {
            try {
                $fileAcl = Get-Acl -Path $file.FullName
                foreach ($fr in $fileAcl.Access) {
                    if ($fr.AccessControlType -eq "Allow" -and (Test-BroadPrincipal $fr.IdentityReference)) {
                        $filePermissionDetails += "파일: $($file.Name), ID: $($fr.IdentityReference), 권한: $($fr.FileSystemRights)"
                    }
                }
            } catch {
                # 파일 접근 실패 무시
            }
        }

        $commandOutput = "디렉터리 ACL:`n" + ($aclDetails -join "`n") + "`n`n파일 권한 문제:`n" + ($filePermissionDetails -join "`n")

        # 판정
        if ($permissionIssues.Count -gt 0 -or $filePermissionDetails.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $summary = "IIS 로그 디렉터리 또는 파일에 일반 사용자의 접근 권한이 있습니다. 비인가자의 로그 파일 접근 가능성 존재."
            $status = "취약"
        } else {
            $finalResult = "GOOD"
            $summary = "IIS 로그 디렉터리 및 파일의 권한이 적절하게 설정되어 있습니다. (보안 권고사항 준수)"
            $status = "양호"
        }

    } else {
        $finalResult = "MANUAL"
        $summary = "IIS 로그 디렉터리를 찾을 수 없습니다. 기본 경로($logDir)가 아닌 다른 경로인지 수동 확인 필요."
        $status = "수동진단"
        $commandExecuted = "Test-Path -Path '$logDir'"
        $commandOutput = "로그 디렉터리 존재하지 않음: $logDir"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl -Path '$logDir'"
    $commandOutput = "진단 실패: $_"
}

# lib를 통한 결과 저장
$purpose = '로그 파일에 공격자에게 유용한 정보가 들어 있을 수 있으므로 권한 관리를 통해 비인가자에 의한 정보 유출, 로그 파일의 훼손 및 변조를 방지하기 위함'
$threat = '로그 디렉터리 및 파일에 적절한 권한이 설정되어 있지 않은 경우, 비인가자가 로그 파일에 접근할 수 있으므로 사용자 및 시스템 정보 유출, 로그 파일 조작 등의 공격 위험이 존재함'
$criteria_good = '로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우'
$criteria_bad = '로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우'
$remediation = '로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정'

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
