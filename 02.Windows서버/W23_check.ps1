# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-23
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 폴더의 익명 접근 제한으로 무단 데이터 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-23"
$ITEM_NAME = "공유 서비스에 대한 익명 접근 제한 설정"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check anonymous access permissions on shared folders
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Windows' -and $_.Name -notlike '*$' }
    $hasAnonymous = $false
    $vulnerableShares = @()

    foreach ($share in $shares) {
        $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        foreach ($access in $acl) {
            if ($access.AccountName -match 'Anonymous|Everyone' -and $access.AccessControlType -eq 'Allow' -and ($access.AccessRight -match 'Full' -or $access.AccessRight -match 'Change')) {
                $hasAnonymous = $true
                $vulnerableShares += "$($share.Name): $($access.AccountName) has $($access.AccessRight)"
            }
        }
    }

    if ($hasAnonymous) {
        $finalResult = "VULNERABLE"
        $summary = "하나 이상의 공유 폴더에 Everyone 또는 Anonymous Logon에게 허용 권한 존재"
        $status = "취약"
        $commandOutput = $vulnerableShares -join '; '
    } else {
        $finalResult = "GOOD"
        $summary = "공유 폴더에 익명 접근 권한이 제한됨"
        $status = "양호"
        $commandOutput = if ($shares) { "No anonymous access found on $($shares.Count) shares" } else { "No Windows shares found" }
    }

    $commandExecuted = "Get-SmbShare | Get-SmbShareAccess"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-SmbShare | Get-SmbShareAccess"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "공유 익명 접속을 제한하여, 중요 정보의 불법 유출을 차단하기 함"
$threat = "공유 익명 접속이 허용되면 핵심 기밀 자료나 내부 정보의 불법 유출 위험이 존재함"
$criteria_good = "공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우"
$criteria_bad = "공유 서비스를 사용하거나, 익명 인증 사용함으로 설정된 경우"
$remediation = "공유 서비스를 사용하지 않는 경우 서비스 중지, 사용할 경우 익명 인증 사용 안 함 설정 적용"

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
