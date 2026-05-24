# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-61
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 파일 및 디렉토리 보호
# @Description : NTFS 파일 시스템 사용으로 강화된 보안 기능 및 접근 통제 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-61"
$ITEM_NAME = "파일 및 디렉토리 보호"
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

# 1. Check file system type (NTFS vs FAT)
try {
    $systemDrive = $env:SystemDrive
    $volInfo = fsutil fsinfo volumeinfo $systemDrive 2>&1

    if ($volInfo -match 'File System Name\s*:\s*NTFS') {
        $finalResult = "GOOD"
        $summary = "NTFS 파일 시스템을 사용함"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "FAT 파일 시스템을 사용함 (취약)"
        $status = "취약"
    }

    $commandExecuted = "fsutil fsinfo volumeinfo $systemDrive"
    $commandOutput = $volInfo

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "fsutil fsinfo volumeinfo $env:SystemDrive"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "FAT 파일 시스템에 비해 더 강화된 보안 기능을 제공하는 파일 시스템을 사용하기 위함 (파일과 디렉터리에 소유권과 사용 권한 설정이 가능하고 ACL(접근 통제 목록)을 제공)"
$threat = "FAT 파일 시스템 사용 시 사용자별 접근 통제를 적용할 수 없어 중요 정보에 대한 책임 추적성 확보가 어려운 위험이 존재함"
$criteria_good = "NTFS 파일 시스템을 사용하는 경우"
$criteria_bad = "FAT 파일 시스템을 사용하는 경우"
$remediation = "FAT 파일 시스템을 사용 시 가능한 NTFS 파일 시스템 변환 설정"

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
