# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-20
# @Category    : 웹서비스>3.보안설정
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : SSL/TLS 활성화
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-20"
$ITEM_NAME = "SSL/TLS 활성화"
$SEVERITY = "상"

$purpose = "서버와 클라이언트 간 통신 시 데이터의 평문 전송을 사용하지 않고 데이터가 암호화되는 SSL/TLS 인증 암호화 접속을 통해 스니 핑을 통한 정보 유출의 위험을 방지하기 위함"
$threat = "웹상의 데이터 통신 시 서버와 클라이언트 간에 데이터를 평문 전송하는 경우, 간단한 도청(스니핑)을 통해 정보가 탈취 및 도용될 위험이 존재함 SSL/TLS가 활성화되어 있지 않을 경우, 데이터는 암호화되지 않아 공격자가 중간에서 데이터를 가로채거나 도청할 수 있으며, 더 나아가 평문으로 전송되어 중간에서 변경될 우려가 있어 데이터의 정확성이 훼손될 위험이 존재함"
$criteria_good = "SSL/TLS 설정이 활성화되어 있는 경우"
$criteria_bad = "SSL/TLS 설정이 비활성화되어 있는 경우"
$remediation = "웹 서비스 내 SSL/TLS 활성화 설정"

try {
    $processes = @(Get-NginxWindowsProcesses)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    if ($processes.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx process exists, but configuration files were not found for SSL/TLS inspection."; $commandOutput = ($processes | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }) -join "`n"; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    else {
        $config = Get-NginxWindowsConfigText -ConfigFiles $configFiles
        $lines = Get-NginxActiveLines -ConfigText $config.Text
        $sslListen = @($lines | Where-Object { $_ -match '^(?i)listen\s+.*443.*ssl' -or $_ -match '^(?i)listen\s+.*ssl.*443' })
        $cert = @($lines | Where-Object { $_ -match '^(?i)ssl_certificate\s+\S+' })
        $key = @($lines | Where-Object { $_ -match '^(?i)ssl_certificate_key\s+\S+' })
        $protocols = @($lines | Where-Object { $_ -match '^(?i)ssl_protocols\s+' })
        $weakProtocols = @($protocols | Where-Object { $_ -match '(?i)\bSSLv2\b|\bSSLv3\b|\bTLSv1\b|\bTLSv1\.1\b' })
        $sslEnabled = ($sslListen.Count -gt 0 -and $cert.Count -gt 0 -and $key.Count -gt 0)
        $commandExecuted = "Parse Nginx Windows SSL listen/certificate/protocol directives"
        $commandOutput = (@($sslListen + $cert + $key + $protocols) -join "`n")
        if (-not $commandOutput) { $commandOutput = "No SSL/TLS directives found." }
        if (-not $sslEnabled) {
            # SSL 리스너/인증서/키 중 하나라도 누락 → SSL/TLS 미활성화 또는 불완전
            $finalResult = "VULNERABLE"; $status = "취약"; $summary = "SSL/TLS configuration is missing or incomplete (listener, certificate, or key directive not found)."
        }
        elseif ($weakProtocols.Count -gt 0) {
            # ssl_protocols에 약한 프로토콜(SSLv2/SSLv3/TLSv1/TLSv1.1) 포함 → 취약
            $finalResult = "VULNERABLE"; $status = "취약"; $summary = "SSL/TLS is enabled but ssl_protocols includes weak protocols (SSLv2/SSLv3/TLSv1/TLSv1.1). Restrict to TLSv1.2/TLSv1.3 only."
        }
        elseif ($protocols.Count -eq 0) {
            # SSL은 활성화되었으나 ssl_protocols 미지정. Nginx 기본값(1.18 이전)은 TLSv1/TLSv1.1을 포함하므로
            # 약한 프로토콜 차단 여부를 정적으로 단정할 수 없어 수동진단으로 분류한다.
            $finalResult = "MANUAL"; $status = "수동진단"; $summary = "SSL/TLS is enabled but no explicit ssl_protocols directive was found. Nginx defaults (pre-1.18) may include TLSv1/TLSv1.1; manually confirm the active protocol set and set 'ssl_protocols TLSv1.2 TLSv1.3;'."
        }
        else {
            # ssl_protocols가 명시되어 있고 약한 프로토콜 없음(현대 프로토콜 전용) → 양호
            $finalResult = "GOOD"; $status = "양호"; $summary = "SSL/TLS listener and certificate directives were found with an explicit ssl_protocols set and no weak protocol evidence."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows SSL/TLS configuration discovery"
}

$resultParams = @{
    ItemId = $ITEM_ID
    ItemName = $ITEM_NAME
    Status = $status
    FinalResult = $finalResult
    InspectionSummary = $summary
    CommandResult = $commandOutput
    CommandExecuted = $commandExecuted
    GuidelinePurpose = $purpose
    GuidelineThreat = $threat
    GuidelineCriteriaGood = $criteria_good
    GuidelineCriteriaBad = $criteria_bad
    GuidelineRemediation = $remediation
    ScriptDir = $SCRIPT_DIR
}

Save-DualResult @resultParams

exit 0
