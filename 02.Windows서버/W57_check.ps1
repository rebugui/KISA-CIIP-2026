# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-57
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 하
# @Title       : 로그 온 시 경고 메시지 설정
# @Description : 로그온 시 경고 메시지 설정으로 사용자에게 경각심 고취
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-57"
$ITEM_NAME = "로그 온 시 경고 메시지 설정"
$SEVERITY = "하"
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

# 1. Check logon warning message settings
try {
    $legalNotice = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

    $caption = if ($legalNotice) { $legalNotice.LegalNoticeCaption } else { '' }
    $text = if ($legalNotice) { $legalNotice.LegalNoticeText } else { '' }

    if ($caption -and $caption.Length -gt 0 -and $text -and $text.Length -gt 0) {
        $finalResult = "GOOD"
        $summary = "로그온 시 경고 메시지 제목 및 내용이 설정됨"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "로그온 시 경고 메시지 제목 또는 내용이 설정되지 않음"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' (LegalNoticeCaption, LegalNoticeText)"
    $captionValue = if ($caption) { $caption } else { "설정되지 않음" }
    $textValue = if ($text) { $text } else { "설정되지 않음" }
    $commandOutput = "LegalNoticeCaption=$captionValue, LegalNoticeText=$textValue"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' (LegalNoticeCaption, LegalNoticeText)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "로그온 시 경고 메시지를 설정하여 시스템에 로그온을 시도하는 사용자들에게 관리자는 시스템의 불법적인 사용에 대하여 경고 창을 띄움으로써 경각심을 주기 위함"
$threat = "로그온 경고 메시지가 없는 경우 악의적인 사용자에게 관리자가 적절한 보안 수준으로 시스템을 보호하고 있으며, 공격자의 활동을 주시하고 있다는 생각을 상기시킬 수 없어 간접적인 공격 기회를 제공할 위험이 존재함"
$criteria_good = "로그인 경고 메시지 제목 및 내용이 설정된 경우"
$criteria_bad = "로그인 경고 메시지 제목 및 내용이 설정되어 있지 않은 경우"
$remediation = "로그인 메시지 제목 및 메시지 내용에 경고 문구 삽입"

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
