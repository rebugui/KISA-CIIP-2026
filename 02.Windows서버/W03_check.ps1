

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-03
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 계정 제거를 통해 시스템 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-03"
$ITEM_NAME = "불필요한 계정 제거"
$SEVERITY = "상"
$CATEGORY = "1.계정관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check for unnecessary accounts
# 불필요/의심 계정 존재 여부는 운영상 필요성(human judgment)에 따라 결정되므로,
# 빌트인 외 모든 계정(활성/비활성 포함)을 열거하여 수동 검토 대상으로 제시한다.
# 활성 계정을 점검 범위에서 제외(비활성+90일 한정)하면 불필요한 활성 계정이 GOOD으로 누락되는 false-good이 발생함.
try {
    $builtinAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    $currentDate = Get-Date
    $daysThreshold = 90  # 참고용: 90일 이상 미로그온 비활성 계정은 명백히 의심 계정으로 표시
    $reviewAccounts = @()

    # Get all local users
    $allUsers = Get-LocalUser

    foreach ($user in $allUsers) {
        # Skip built-in accounts
        if ($user.Name -in $builtinAccounts) {
            continue
        }

        $state = if ($user.Enabled) { "활성" } else { "비활성" }
        $logonNote = ""

        # Get last logon time using WMI (locale-independent) for additional context
        try {
            $lastLogonWmi = Get-WmiObject -Class Win32_NetworkLoginProfile -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $user.Name } |
                Sort-Object LastLogon -Descending |
                Select-Object -First 1 -ExpandProperty LastLogon

            if ($lastLogonWmi) {
                $lastLogonDate = [Management.ManagementDateTimeConverter]::ToDateTime($lastLogonWmi)
                $daysSinceLogon = ($currentDate - $lastLogonDate).Days
                if ($daysSinceLogon -gt $daysThreshold) {
                    $logonNote = ", $($daysSinceLogon)일 미로그온"
                } else {
                    $logonNote = ", $($daysSinceLogon)일 전 로그온"
                }
            } else {
                $logonNote = ", 로그온 기록 없음"
            }
        } catch {
            $logonNote = ", 로그온 확인 필요"
        }

        # 빌트인 외 모든 계정을 검토 대상으로 수집 (활성/비활성 무관)
        $reviewAccounts += "$($user.Name) ($state$logonNote)"
    }

    $commandExecuted = "Get-LocalUser; Get-WmiObject -Class Win32_NetworkLoginProfile | Where-Object { `$_.Name -eq `$user.Name } | Select-Object -First 1 -ExpandProperty LastLogon"

    if ($reviewAccounts.Count -gt 0) {
        $accountList = $reviewAccounts -join ', '
        # 불필요 계정 여부는 운영 필요성 판단이 요구되므로 수동진단 (활성 계정을 건너뛰고 GOOD 처리 금지)
        $finalResult = "MANUAL"
        $summary = "빌트인 외 로컬 계정 $($reviewAccounts.Count)개 존재. 각 계정의 업무상 필요성을 확인하여 불필요/의심 계정(퇴직·전직·휴직자 등) 여부를 수동 점검 필요: $accountList"
        $status = "수동진단"
        $commandOutput = $accountList
    } else {
        $finalResult = "GOOD"
        $summary = "빌트인 계정 외 추가 로컬 계정이 존재하지 않음 (불필요한 계정 없음)"
        $status = "양호"
        $commandOutput = "No non-builtin local accounts found"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-LocalUser; net user [accountname]"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "퇴직, 전직, 휴직 등의 이유로 사용하지 않는 계정, 불필요한 계정 및 의심스러운 계정을 삭제하여, 일반적으로 로그인이 필요치 않은 해당 계정들을 통한 로그인을 차단하고, 계정의 패스워드 추측 공격 시도를 차단하기 위함"
$threat = "관리되지 않은 불필요한 계정은 장기간 비밀번호가 변경되지 않아 무차별 대입 공격(Brute Force Attack)이나 비밀번호 추측 공격(Password Guessing Attack)의 가능성이 존재하며, 또한 이런 공격으로 계정 정보가 유출되어도 유출 사실을 인지하기 어려워 초기 대응이 불가능한 위험이 존재함"
$criteria_good = "불필요한 계정이 존재하지 않는 경우"
$criteria_bad = "불필요한 계정이 존재하는 경우"
$remediation = "현재 계정 현황 확인 후 불필요한 계정 삭제"

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

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
