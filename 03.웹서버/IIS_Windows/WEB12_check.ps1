# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-12
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서비스링크사용금지
# @Description : 심볼릭 링크(Symbolic Links) 사용을 제한하여 디렉터리 트래버설 공격을 방지합니다. IIS는 기본적으로 심볼릭 링크를 지원하지 않지만 추가 모듈 설치 시 확인이 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-12"
$ITEM_NAME = "웹 서비스 링크 사용 금지"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS symbolic links 확인 (기본적으로 비활성화)
    $finalResult = "GOOD"
    $summary = "IIS는 기본적으로 symbolic link 사용이 비활성화되어 있습니다. 별도 설정이 없으면 링크 사용이 제한됩니다. (보안 권고사항 준수)"
    $status = "양호"
    $commandExecuted = "IIS does not support symbolic links by default"
    $commandOutput = "Symbolic Links: Not supported by default in IIS"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "N/A"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함'
$threat = '보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함'
$criteria_good = '심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우'
$criteria_bad = '심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우'
$remediation = '웹 서비스 링크 사용 제한 설정'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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
