# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-03
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 비밀번호 파일 권한 관리
# @Description : IIS 환경의 비밀번호 파일(%systemroot%\system32\config\SAM)에 대한 접근 권한을 점검합니다. SAM 파일은 Administrators, SYSTEM 계정 외의 사용자/그룹에 권한이 부여되지 않아야 합니다. 그 외 일반 사용자/그룹에 Allow 권한이 존재하면 취약합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-03"
$ITEM_NAME = "비밀번호 파일 권한 관리"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 대상: SAM 파일(%systemroot%\system32\config\SAM) ACL 점검
    # 허용 원칙: Administrators, SYSTEM 만 권한 보유. 그 외 일반 사용자/그룹 Allow 권한 존재 시 취약.
    $samFile = Join-Path $env:SystemRoot "system32\config\SAM"
    $commandExecuted = "Get-Acl -Path '$samFile'"

    if (-not (Test-Path $samFile)) {
        $finalResult = "MANUAL"
        $summary = "SAM 파일을 찾을 수 없습니다($samFile). 경로 및 권한을 수동으로 확인하세요."
        $status = "수동진단"
        $commandOutput = "SAM 파일 미존재: $samFile"
    } else {
        # 허용된 식별자(부분 일치): Administrators, SYSTEM
        $allowedPatterns = @('Administrators', 'SYSTEM', 'TrustedInstaller')
        $acl = Get-Acl -Path $samFile
        $violations = @()
        $aclDetails = @()

        foreach ($rule in $acl.Access) {
            $identity = $rule.IdentityReference.Value
            $rights = $rule.FileSystemRights
            $type = $rule.AccessControlType
            $aclDetails += "ID: $identity, 권한: $rights, 타입: $type, 상속: $($rule.IsInherited)"

            if ($type -eq "Allow") {
                $isAllowed = $false
                foreach ($pat in $allowedPatterns) {
                    if ($identity -like "*$pat*") {
                        $isAllowed = $true
                        break
                    }
                }
                if (-not $isAllowed) {
                    $violations += "ID: $identity, 권한: $rights, 타입: $type"
                }
            }
        }

        $commandOutput = "SAM 파일: $samFile`nACL:`n" + ($aclDetails -join "`n")

        if ($violations.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $summary = "SAM 파일에 Administrators/SYSTEM 외 계정의 Allow 권한이 존재합니다: " + ($violations -join "; ")
            $status = "취약"
            $commandOutput = $commandOutput + "`n`n불필요 권한:`n" + ($violations -join "`n")
        } else {
            $finalResult = "GOOD"
            $summary = "SAM 파일 권한이 Administrators, SYSTEM 으로 제한되어 있습니다. (보안 권고사항 준수)"
            $status = "양호"
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요 (SAM 파일 접근에는 관리자 권한이 필요합니다)"
    $status = "수동진단"
    $commandExecuted = "Get-Acl -Path '%systemroot%\system32\config\SAM'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '비밀번호 파일의 접근 권한을 적절하게 설정하여 비인가자가 비밀번호 파일에 무단 접근 및 유출 등을 방지하기 위함'
$threat = '비밀번호 파일의 권한을 적절하게 설정하지 않은 경우, 비인가자에게 비밀번호 정보가 노출될 수 있고 웹 서버에 접속하는 등의 침해 사고가 발생할 위험이 존재함'
$criteria_good = '비밀번호 파일에 권한이 600 이하로 설정된 경우'
$criteria_bad = '비밀번호 파일에 권한이 600 초과로 설정된 경우'
$remediation = '비밀번호 파일 권한 600 이하로 설정'

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
