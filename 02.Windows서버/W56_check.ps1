# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-56
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : SMB 세션 중단 관리 설정
# @Description : SMB 세션 타임아웃 설정으로 서비스 거부 공격 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-56"
$ITEM_NAME = "SMB 세션 중단 관리 설정"
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

# 1. Check SMB session timeout settings
try {
    # EnableForcedLogOff, AutoDisconnect 은 LanmanServer\Parameters 레지스트리 값(REG_DWORD)이며
    # secedit [System Access] 에 존재하지 않으므로 레지스트리에서 직접 조회함 (분 단위)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $regProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    $enableForcedLogoff = $null
    $autoDisconnect = $null
    if ($null -ne $regProps) {
        if ($null -ne $regProps.EnableForcedLogOff) {
            $enableForcedLogoff = [int]$regProps.EnableForcedLogOff
        }
        if ($null -ne $regProps.AutoDisconnect) {
            $autoDisconnect = [int]$regProps.AutoDisconnect
        }
    }

    $commandExecuted = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters 의 EnableForcedLogOff, AutoDisconnect 값 확인"
    $forcedLogoffStatus = switch ($enableForcedLogoff) {
        1 { "사용" }
        0 { "사용안함" }
        $null { "설정값 없음" }
        default { "알 수 없음 ($enableForcedLogoff)" }
    }
    $forcedLogoffDisplay = if ($null -eq $enableForcedLogoff) { "미설정" } else { $enableForcedLogoff }
    $autoDisconnectDisplay = if ($null -eq $autoDisconnect) { "미설정" } else { "$autoDisconnect 분" }
    $commandOutput = "EnableForcedLogOff=$forcedLogoffDisplay ($forcedLogoffStatus), AutoDisconnect=$autoDisconnectDisplay"

    if ($null -eq $enableForcedLogoff -or $null -eq $autoDisconnect) {
        # 레지스트리 값이 없거나 읽을 수 없는 경우 정적으로 양호/취약을 단정할 수 없으므로 수동 진단
        $finalResult = "MANUAL"
        $summary = "SMB 세션 중단 관련 레지스트리 값(EnableForcedLogOff/AutoDisconnect)을 확인할 수 없어 수동 진단 필요"
        $status = "수동진단"
    } elseif ($enableForcedLogoff -eq 1 -and $autoDisconnect -le 15) {
        $finalResult = "GOOD"
        $summary = "SMB 세션 타임아웃이 적절하게 설정됨 (15분 이하)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "SMB 세션 타임아웃이 설정되지 않았거나 15분 초과"
        $status = "취약"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters 의 EnableForcedLogOff, AutoDisconnect 값 확인"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "Session이 중단되기 전에 SMB(서버 메시지 블록) Session에서 보내야 하는 연속 유휴 시간을 결정하여 서비스 거부 공격 등에 악용되지 않도록하기 위함"
$threat = "SMB Session에서는 서버 리소스를 사용하며, NULL Session 수가 많으면 서버 속도가 느려지거나 서버에 오류를 발생시킬 수 있으므로 공격자는 이를 악용하여 SMB Session을 반복 설정하여 서버의 SMB 서비스가 느려지거나 응답하지 않게하여 서비스 거부 공격을 실행할 위험이 존재함"
$criteria_good = '''로그온 시간이 만료되면 클라이언트 연결 끊기''정책을''사용''으로,''세션 연결을 중단하기 전에 필요한 유휴 시간''정책을''15분''이하로 설정한 경우'
$criteria_bad = '''로그 온 시간이 만료되면 클라이언트 연결 끊기'' 정책이 ''사용 안 함'' 또는 ''세션 연결을 중단하기 전에 필요한 유휴 시간''정책이''15분''초과로 설정한 경우'
$remediation = '''로그인 시간이 만료되면 클라이언트 연결 끊기''정책''사용''설정 ''세션 연결을 중단하기 전에 필요한 유휴 시간''정책''15분''이하로 설정'

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
