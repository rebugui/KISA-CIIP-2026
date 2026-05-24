

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-07
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : Everyone 사용 권한을 익명 사용자에 적용
# @Description : Everyone 사용권한이 익명사용자에게 적용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-07"
$ITEM_NAME = "Everyone 사용 권한을 익명 사용자에 적용"
$SEVERITY = "중"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check EveryoneIncludesAnonymous policy
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous

    if ($null -eq $value -or $value -eq 0) {
        $finalResult = "GOOD"
        $summary = "'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 '사용 안 함'으로 설정됨"
        $status = "양호"
        $commandOutput = if ($null -eq $value) { "EveryoneIncludesAnonymous = (not set, defaults to 0 = Disabled)" } else { "EveryoneIncludesAnonymous = 0 (Disabled)" }
    } else {
        $finalResult = "VULNERABLE"
        $summary = "'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 '사용'으로 설정됨 (보안 위협)"
        $status = "취약"
        $commandOutput = "EveryoneIncludesAnonymous = $value (Enabled)"
    }

    $commandExecuted = "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "익명 사용자가 Everyone 그룹으로 사용 권한을 준 모든 리소스에 접근하는 것을 차단하여 비인가자에 의한 접근 가능성을 제한하기 위함"
$threat = "해당 정책이 '사용'으로 설정될 경우 권한이 없는 사용자가 익명으로 계정 이름 및 공유 리소스를 나열하고 이 정보를 사용하여 암호를 추측하거나 DoS(Denial of Service) 공격을 실행할 위험이 존재함"
$criteria_good = '''Everyone 사용 권한을 익명 사용자에게 적용''정책이''사용 안 함''으로 되어 있는 경우'
$criteria_bad = '''Everyone 사용 권한을 익명 사용자에게 적용''정책이''사용''으로 되어 있는 경우'
$remediation = '''Everyone 사용 권한을 익명 사용자에게 적용''정책을''사용 안 함''으로 설정'

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
