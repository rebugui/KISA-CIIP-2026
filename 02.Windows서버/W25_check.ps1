# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-25
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : DNS Zone Transfer 설정
# @Description : DNS Zone Transfer 제한으로 DNS 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-25"
$ITEM_NAME = "DNS Zone Transfer 설정"
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

# 1. Check DNS Zone Transfer settings
# Get-DnsServerZoneTransferPolicy는 RPZ(DNS 방화벽) 정책용 cmdlet으로 영역 전송 제어와 무관하다.
# 올바른 API는 Get-DnsServerZone의 SecureSecondaries / SecondaryServers 속성이다.
#   SecureSecondaries: NoTransfer / TransferToZoneNameServer / TransferToSecureServers / TransferAnyServer
# 양호 기준: DNS 서비스 미사용, 또는 영역 전송 미허용, 또는 특정 서버로만 제한된 경우.
# DNS 서비스는 구동 중이나 DnsServer 모듈을 사용할 수 없으면 GOOD으로 단정하지 않고 MANUAL.
try {
    $commandExecuted = "Get-Service DNS; Get-DnsServerZone | Select ZoneName,SecureSecondaries,SecondaryServers"

    $dnsService = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
    $dnsRunning = ($dnsService -and $dnsService.Status -eq 'Running')

    Import-Module DnsServer -ErrorAction SilentlyContinue
    $hasCmdlet = [bool](Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)

    if (-not $hasCmdlet) {
        if ($dnsRunning) {
            # DNS 서버가 구동 중인데 점검 cmdlet이 없으면 영역 전송 설정을 단정할 수 없음 → 수동 진단.
            $finalResult = "MANUAL"
            $summary = "DNS 서비스가 구동 중이나 DnsServer 모듈을 사용할 수 없어 Zone Transfer 설정을 자동으로 확인할 수 없음 (수동 확인 필요)"
            $status = "수동진단"
            $commandOutput = "DNS service running but Get-DnsServerZone unavailable"
        } else {
            $finalResult = "GOOD"
            $summary = "DNS 서비스가 비활성화됨 (DNS Server 역할 미설치 또는 미구동)"
            $status = "양호"
            $commandOutput = "DNS Server role not installed / service not running"
        }
    } else {
        $zones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object {
            $_.ZoneType -eq 'Primary' -and $_.IsAutoCreated -eq $false -and $_.ZoneName -ne 'TrustAnchors'
        })
        $hasInsecureTransfer = $false
        $zoneDetails = @()

        foreach ($zone in $zones) {
            $secSec = [string]$zone.SecureSecondaries
            # NoTransfer(미허용) 또는 TransferToZoneNameServer/TransferToSecureServers(특정 서버 제한) = 양호.
            # TransferAnyServer(모든 서버로 전송) 또는 알 수 없는 값 = 취약.
            $isSecure = ($secSec -eq 'NoTransfer' -or $secSec -eq 'TransferToZoneNameServer' -or $secSec -eq 'TransferToSecureServers')
            if (-not $isSecure) {
                $hasInsecureTransfer = $true
                $secList = if ($zone.SecondaryServers) { ($zone.SecondaryServers -join ',') } else { '(none)' }
                $zoneDetails += "$($zone.ZoneName): SecureSecondaries=$secSec, SecondaryServers=$secList"
            }
        }

        if ($hasInsecureTransfer) {
            $finalResult = "VULNERABLE"
            $summary = "하나 이상의 DNS Zone에서 제한 없이 Zone Transfer 허용 (TransferAnyServer)"
            $status = "취약"
            $commandOutput = $zoneDetails -join '; '
        } else {
            $finalResult = "GOOD"
            $summary = "DNS Zone Transfer가 제한됨 (미허용 또는 특정 서버로만 허용)"
            $status = "양호"
            $commandOutput = if ($zones.Count -gt 0) { "All $($zones.Count) primary zones restrict zone transfer" } else { "No primary zones configured" }
        }
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service DNS; Get-DnsServerZone | Select ZoneName,SecureSecondaries,SecondaryServers"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "DNSZoneTransfer 차단 설정을 적용하여 도메인 정보의 불법 외부 유출을 방지하기 위함"
$threat = "DNSZoneTransfer 차단 설정이 적용되지 않는 경우 DNS 서버에 저장된 도메인 정보를 승인된 DNS 서버가 아닌 외부로 유출 위험이 존재함"
$criteria_good = "아래 기준에 해당하는 경우 1.DNS 서비스가 비활성화인 경우 2. 영역 전송 허용을 하지 않는 경우 3. 특정 서버로만 설정이 되어 있는 경우"
$criteria_bad = "위 3개 기준 중 하나라도 해당하지 않는 경우"
$remediation = "불필요시 서비스 중지/ 사용 안 함 설정, 사용하는 경우 영역 전송을 특정 서버로 제한하거나'영역 전송 허용'에 체크 해제"

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
