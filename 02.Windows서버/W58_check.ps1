# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-58
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 사용자별 홈 디렉터리 권한 설정
# @Description : 홈 디렉터리 권한 설정으로 비인가 사용자 정보 노출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-58"
$ITEM_NAME = "사용자별 홈 디렉터리 권한 설정"
$SEVERITY = "중"
$CATEGORY = "5.보안관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check home directory permissions
try {
    $homeDirs = @('C:\Users', 'C:\Documents and Settings')
    $hasEveryone = $false

    foreach ($dir in $homeDirs) {
        if (Test-Path $dir) {
            $acls = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue
            foreach ($acl in $acls) {
                if ($acl.Name -notin @('All Users', 'Default User', 'Public', 'Default')) {
                    try {
                        $access = Get-Acl $acl.FullName -ErrorAction SilentlyContinue
                        if ($access.AccessToString -match 'Everyone') {
                            $hasEveryone = $true
                            break
                        }
                    } catch {
                        # Ignore access errors
                    }
                }
            }
        }
    }

    if (-not $hasEveryone) {
        $finalResult = "GOOD"
        $summary = "홈 디렉터리에 Everyone 권한이 없음 (적절하게 설정됨)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "홈 디렉터리에 Everyone 권한이 존재함"
        $status = "취약"
    }

    $commandExecuted = "Get-Acl 확인 (C:\Users 또는 C:\Documents and Settings 하위 사용자 디렉터리)"
    $commandOutput = "Everyone 권한 존재: $hasEveryone"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl 확인 (C:\Users 또는 C:\Documents and Settings 하위 사용자 디렉터리)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "사용자 홈 디렉터리에 적절한 권한을 부여하여 비인가 사용자에 의한 불필요한 정보 노출을 방지하기 위함"
$threat = "사용자 계정별 홈 디렉터리의 권한이 제한되어 있지 않으면 임의의 사용자나 다른 사용자의 홈 디렉터리에 악의적인 목적으로 접근할 수 있으며, 접근 후 의도 또는, 의도하지 않은 행위로 시스템에 악영향을 미칠 위험이 존재함"
$criteria_good = "홈 디렉터리에 Everyone 권한이 없는 경우(All Users, Default User 디렉터리 제외)"
$criteria_bad = "홈 디렉터리에 Everyone 권한이 있는 경우"
$remediation = "Everyone 권한 제거"

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
