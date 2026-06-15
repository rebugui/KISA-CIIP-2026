# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-46
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : SAM 파일 접근 통제 설정
# @Description : SAM 파일 접근 통제로 악의적인 계정 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-46"
$ITEM_NAME = "SAM 파일 접근 통제 설정"
$SEVERITY = "상"
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

# 1. Check SAM file access permissions
try {
    $samPath = Join-Path $env:SystemRoot "System32\config\SAM"

    if (-not (Test-Path $samPath)) {
        $finalResult = "MANUAL"
        $summary = "SAM 파일을 찾을 수 없거나 진단 실패: 수동 확인 필요"
        $status = "수동진단"
        $commandExecuted = "Get-Acl $samPath"
        $commandOutput = "SAM 파일을 찾을 수 없음"
    } else {
        $acl = Get-Acl $samPath -ErrorAction Stop
        $access = $acl.AccessToString
        $hasUnauthorized = $false

        # 기준(criteria_bad): Administrator,System 그룹 외 다른 주체에 '권한이 설정된 경우'.
        # 권한 수준(FullControl 여부)과 무관하게 Allow ACE가 존재하면 취약.
        # 허용 주체는 잘 알려진 SID로 비교(로케일 안전): Administrators(S-1-5-32-544),
        # SYSTEM(S-1-5-18). 한글 로케일에서 'BUILTIN\Administrators' 등이 현지화되어
        # 문자열 매칭이 어긋나는 문제를 방지하기 위해 SID로 식별하며, 번역 실패 시에만
        # 이름 부분 문자열로 보조 판단한다.
        $allowedSids = @('S-1-5-32-544', 'S-1-5-18')

        foreach ($ace in $acl.Access) {
            # Deny ACE는 권한 부여가 아니므로 판단 대상에서 제외
            if ($ace.AccessControlType -ne 'Allow') {
                continue
            }

            $identity = $ace.IdentityReference.Value
            $sid = $null
            try {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                $sid = $null
            }

            $isAllowedPrincipal = $false
            if ($sid -and ($allowedSids -contains $sid)) {
                $isAllowedPrincipal = $true
            } elseif (-not $sid) {
                # SID 번역 실패 시 이름 기반 보조 판단
                if ($identity -match 'BUILTIN\\Administrators' -or $identity -match 'NT AUTHORITY\\SYSTEM') {
                    $isAllowedPrincipal = $true
                }
            }

            if (-not $isAllowedPrincipal) {
                # Administrator,System 외 주체에 권한이 부여됨 -> 취약
                $hasUnauthorized = $true
                break
            }
        }

        if (-not $hasUnauthorized) {
            $finalResult = "GOOD"
            $summary = "SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정됨"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "SAM 파일 접근 권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정됨"
            $status = "취약"
        }

        $commandExecuted = "Get-Acl $samPath"
        $commandOutput = $access
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "SAM 파일을 찾을 수 없거나 진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl $samPath"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "Administrator 및 System 그룹만 SAM 파일에 접근할 수 있도록 제한하여 악의적인 계정 정보 유출을 차단하기 위함"
$threat = "SAM 파일이 노출될 경우 비밀번호 공격 시도로 인해 계정 및 비밀번호 데이터베이스 정보가 탈취될 위험이 존재함"
$criteria_good = "SAM 파일 접근 권한에 Administrator,System 그룹만 모든 권한으로 설정된 경우"
$criteria_bad = "SAM 파일 접근 권한에 Administrator,System 그룹 외 다른 그룹에 권한이 설정된 경우"
$remediation = "SAM 파일 권한 확인 후 Administrator,System 그룹 외 다른 그룹에 설정된 권한 제거"

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
