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

# 1. Check FTP root directory write permissions
try {
    $ftpRoot = 'C:\inetpub\ftproot'

    if (Test-Path $ftpRoot) {
        $acl = Get-Acl -Path $ftpRoot -ErrorAction SilentlyContinue
        $hasWrite = $false
        $writePermissions = @()

        foreach ($access in $acl.Access) {
            if ($access.FileSystemRights -match 'Write' -and $access.AccessControlType -eq 'Allow' -and $access.IdentityReference -match 'Everyone') {
                $hasWrite = $true
                $writePermissions += "$($access.IdentityReference): $($access.FileSystemRights)"
            }
        }

        if ($hasWrite) {
            $finalResult = "VULNERABLE"
            $summary = "FTP 루트 디렉토리에 Everyone 쓰기 권한이 존재하여 무단 업로드 가능"
            $status = "취약"
            $commandOutput = $writePermissions -join '; '
        } else {
            $finalResult = "GOOD"
            $summary = "FTP 루트 디렉토리에 Everyone 쓰기 권한이 제거됨"
            $status = "양호"
            $commandOutput = "No write permissions found on FTP root directory"
        }
    } else {
        $finalResult = "GOOD"
        $summary = "FTP 루트 디렉토리가 존재하지 않음 (FTP 서비스 미사용)"
        $status = "양호"
        $commandOutput = "FTP root directory does not exist"
    }

    $commandExecuted = "Get-Acl -Path 'C:\inetpub\ftproot' | Select-Object -ExpandProperty Access"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Acl -Path 'C:\inetpub\ftproot' | Select-Object -ExpandProperty Access"
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
