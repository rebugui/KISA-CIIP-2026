# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-43
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 이벤트 로그 파일 접근 통제 설정
# @Description : 이벤트 로그 파일 접근 통제로 로그 파일 훼손 및 변조 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-43"
$ITEM_NAME = "이벤트 로그 파일 접근 통제 설정"
$SEVERITY = "중"
$CATEGORY = "4.로그관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check event log directory access control
try {
    $logPath = 'C:\Windows\System32\winevt\Logs'

    if (Test-Path $logPath) {
        $acl = Get-Acl $logPath -ErrorAction SilentlyContinue

        if ($acl) {
            $hasEveryone = $false
            $accessList = @()

            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $accessList += "$identity : $($access.FileSystemRights)"

                # The Everyone account localizes (Korean: '모든 사람'), so a name
                # substring match is unreliable. Compare by the well-known SID
                # S-1-1-0 after translating the identity reference.
                $sid = $null
                try {
                    $sid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch {
                    $sid = $null
                }

                if ($sid -eq 'S-1-1-0' -or $identity -like '*Everyone*') {
                    $hasEveryone = $true
                }
            }

            if ($hasEveryone) {
                $finalResult = "VULNERABLE"
                $summary = "로그 디렉터리의 접근 권한에 Everyone 권한이 있음"
                $status = "취약"
            } else {
                $finalResult = "GOOD"
                $summary = "로그 디렉터리의 접근 권한에 Everyone 권한이 없음"
                $status = "양호"
            }

            $commandOutput = $accessList -join "`n"
        } else {
            $finalResult = "MANUAL"
            $summary = "진단 실패: 수동으로 로그 디렉터리 권한 확인 필요"
            $status = "수동진단"
            $commandOutput = "ACL을 가져올 수 없음"
        }
    } else {
        $finalResult = "MANUAL"
        $summary = "진단 실패: 수동으로 로그 디렉터리 권한 확인 필요"
        $status = "수동진단"
        $commandOutput = "로그 디렉터리가 존재하지 않음: $logPath"
    }

    $commandExecuted = "Get-Acl 'C:\Windows\System32\winevt\Logs'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl 'C:\Windows\System32\winevt\Logs'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "원격에서 로그 파일에 접근하는 것을 차단하여 로그 파일의 훼손 및 변조를 차단하기 위함"
$threat = "원격 익명 사용자의 시스템 로그 파일에 접근이 가능한 경우'중요 시스템 로그' 파일 및'응용 프로그램 로그'등 중요 보안 감사 정보의 변조· 삭제· 유출의 위험이 존재함"
$criteria_good = "로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우"
$criteria_bad = "로그 디렉터리의 접근 권한에 Everyone 권한이 있는 경우"
$remediation = "로그 디렉터리의 접근 권한에 Everyone 제거"

# Save results using lib
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

exit 0
