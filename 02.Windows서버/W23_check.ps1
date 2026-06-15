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

# 1. Check anonymous/Everyone access on shared services (SMB + IIS FTP anonymous auth)
# 가이드라인: 공유서비스(FTP, SMB, NFS, TFTP)에 익명 인증이 허용되면 취약.
# SMB는 Everyone/Anonymous에 대한 모든 Allow 권한을 대상으로 하며(쓰기 한정 아님),
# IIS FTP의 익명 인증(anonymousAuthentication)도 함께 점검한다. 점검 불가 영역은 MANUAL로 라우팅한다.
try {
    $commandExecuted = "Get-SmbShare | Get-SmbShareAccess; Get-WebConfigurationProperty ftpServer/security/authentication/anonymousAuthentication"

    $vulnerableFindings = @()
    $manualNotes = @()

    # --- (1) SMB 공유 익명/Everyone 접근 점검 ---
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Windows' -and $_.Name -notlike '*$' })
    foreach ($share in $shares) {
        $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        foreach ($access in $acl) {
            if ($access.AccessControlType -ne 'Allow') { continue }

            # AccountName은 로캘에 따라 'Everyone'/'모든 사람', 'ANONYMOUS LOGON'/'익명 로그온' 등
            # 현지화된 표시 이름으로 반환되므로 영문 문자열 매칭만으로는 한국어 로캘에서 누락됨.
            # 따라서 잘 알려진 SID(Everyone=S-1-1-0, Anonymous=S-1-5-7)로 비교하고
            # 문자열(영문/한글) 매칭을 보조 수단으로 사용한다(W-16/W-43/W-58 방식 미러링).
            $acctName = $access.AccountName
            $sid = $null
            try {
                $sid = (New-Object System.Security.Principal.NTAccount($acctName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                $sid = $null
            }

            $isEveryone = ($sid -eq 'S-1-1-0') -or ($acctName -match 'Everyone|모든 사람')
            $isAnonymous = ($sid -eq 'S-1-5-7') -or ($acctName -match 'Anonymous|익명')

            # 권한 수준(Read/Change/Full)과 무관하게 Everyone/Anonymous에 대한 모든 Allow 권한을 취약으로 간주.
            if ($isEveryone -or $isAnonymous) {
                $vulnerableFindings += "SMB $($share.Name): $($access.AccountName) has $($access.AccessRight)"
            }
        }
    }

    # --- (2) IIS FTP 익명 인증 점검 ---
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
        $sites = @(Get-Website -ErrorAction SilentlyContinue)
        foreach ($site in $sites) {
            $hasFtpBinding = $false
            foreach ($b in @($site.Bindings.Collection)) {
                if ($b.protocol -eq 'ftp') { $hasFtpBinding = $true }
            }
            if ($hasFtpBinding) {
                $anon = Get-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -Name 'enabled' -PSPath 'IIS:\' -Location $site.Name -ErrorAction SilentlyContinue
                if ($null -eq $anon) {
                    $manualNotes += "FTP site '$($site.Name)': anonymous auth state could not be determined"
                } elseif ($anon.Value -eq $true) {
                    $vulnerableFindings += "FTP $($site.Name): anonymous authentication enabled"
                }
            }
        }
    } else {
        # IIS 구성 모듈을 사용할 수 없으면 FTP 익명 인증 점검 결과를 단정할 수 없음.
        $manualNotes += "WebAdministration module unavailable; IIS FTP anonymous auth not inspected"
    }

    if ($vulnerableFindings.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "공유 서비스에 익명(Everyone/Anonymous) 접근이 허용됨"
        $status = "취약"
        $commandOutput = $vulnerableFindings -join '; '
    } elseif ($manualNotes.Count -gt 0) {
        # 알 수 없는 영역이 남아 있으면 GOOD으로 단정하지 않고 수동 진단.
        $finalResult = "MANUAL"
        $summary = "일부 공유 서비스의 익명 접근 설정을 자동으로 확인할 수 없어 수동 확인 필요"
        $status = "수동진단"
        $commandOutput = $manualNotes -join '; '
    } else {
        $finalResult = "GOOD"
        $summary = "공유 서비스에 익명 접근 권한이 제한됨"
        $status = "양호"
        $commandOutput = "No anonymous/Everyone access on $($shares.Count) SMB shares; IIS FTP anonymous auth disabled or no FTP site"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-SmbShare | Get-SmbShareAccess; Get-WebConfigurationProperty ftpServer/security/authentication/anonymousAuthentication"
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
