# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-21
# @Category    : 웹서비스>3.보안설정
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-21"
$ITEM_NAME = "HTTP 리디렉션"
$SEVERITY = "중"

$purpose = "HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
$threat = "HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
$criteria_good = "HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
$criteria_bad = "HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
$remediation = "HTTP Redirection 활성화 설정"

try {
    $processes = @(Get-NginxWindowsProcesses)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    if ($processes.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"; $status = "N/A"; $summary = "Nginx for Windows process/configuration was not found."; $commandOutput = "No nginx.exe process or known nginx.conf path found."; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"; $status = "수동진단"; $summary = "Nginx process exists, but configuration files were not found for HTTP redirect inspection."; $commandOutput = ($processes | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }) -join "`n"; $commandExecuted = "Get-CimInstance Win32_Process; known nginx.conf paths"
    }
    else {
        $config = Get-NginxWindowsConfigText -ConfigFiles $configFiles
        $lines = Get-NginxActiveLines -ConfigText $config.Text
        $http = @($lines | Where-Object { $_ -match '^(?i)listen\s+.*\b80\b' -and $_ -notmatch '443|ssl' })
        # 실제 HTTP→HTTPS 리디렉션은 return 30x https:// 또는 rewrite ... https:// 만 인정.
        # HSTS(add_header Strict-Transport-Security)는 HTTP 요청을 리디렉션하지 않으므로 리디렉션 증적이 아님.
        $redirect = @($lines | Where-Object { $_ -match '^(?i)return\s+30[1278]\s+https://' -or $_ -match '^(?i)rewrite\s+.+\s+https://' })
        $hsts = @($lines | Where-Object { $_ -match '^(?i)add_header\s+Strict-Transport-Security\b' })

        # 리디렉션 증적은 반드시 listen 80 을 소유한 server{} 블록 안(또는 그 블록의 기본 동작)에 있어야 함.
        # 전역 매칭은 443(ssl) 블록의 canonicalization 리디렉션을 80 블록의 리디렉션으로 오인하여 false GOOD을 유발함.
        # server{} 블록을 중괄호 매칭으로 분리하여 블록 단위로 listen 80 / 리디렉션 동시 보유 여부를 판정.
        $servers80 = @()              # listen 80(비-ssl)을 소유한 server 블록들
        $servers80WithRedirect = @()  # 그 중 동일 블록 내 https 리디렉션을 가진 블록들
        $blockScopingOk = $true
        try {
            $cfgText = [string]$config.Text
            $serverBlocks = [System.Collections.Generic.List[string]]::new()
            $idx = 0
            while ($true) {
                $m = [regex]::Match($cfgText.Substring($idx), '(?im)\bserver\s*\{')
                if (-not $m.Success) { break }
                $open = $idx + $m.Index + $m.Length - 1   # position of the '{'
                $depth = 0
                $end = -1
                for ($p = $open; $p -lt $cfgText.Length; $p++) {
                    $ch = $cfgText[$p]
                    if ($ch -eq '{') { $depth++ }
                    elseif ($ch -eq '}') {
                        $depth--
                        if ($depth -eq 0) { $end = $p; break }
                    }
                }
                if ($end -lt 0) { $blockScopingOk = $false; break }   # 불균형 중괄호 → 정적 블록 연관 불가
                $serverBlocks.Add($cfgText.Substring($open + 1, $end - $open - 1)) | Out-Null
                $idx = $end + 1
            }
            if ($blockScopingOk) {
                foreach ($block in $serverBlocks) {
                    $blockLines = Get-NginxActiveLines -ConfigText $block
                    $hasHttp = @($blockLines | Where-Object { $_ -match '^(?i)listen\s+.*\b80\b' -and $_ -notmatch '443|ssl' }).Count -gt 0
                    if (-not $hasHttp) { continue }
                    $servers80 += , $block
                    $hasRedirect = @($blockLines | Where-Object { $_ -match '^(?i)return\s+30[1278]\s+https://' -or $_ -match '^(?i)rewrite\s+.+\s+https://' }).Count -gt 0
                    if ($hasRedirect) { $servers80WithRedirect += , $block }
                }
            }
        }
        catch {
            $blockScopingOk = $false
        }

        $commandExecuted = "Parse Nginx Windows HTTP listen and HTTPS redirect directives (server-block scoped)"
        $commandOutput = (@($http + $redirect + $hsts) -join "`n")
        if (-not $commandOutput) { $commandOutput = "No HTTP listener or HTTPS redirect evidence found." }

        if ($http.Count -eq 0) {
            $finalResult = "MANUAL"; $status = "수동진단"; $summary = "No port 80 listener was found in static configuration; confirm active server blocks and upstream redirect policy."
        }
        elseif (-not $blockScopingOk) {
            # listen 80 은 존재하나 server{} 블록 경계를 정적으로 확정할 수 없음(중괄호 불균형 등) → 수동 판정으로 안전하게 강등.
            $finalResult = "MANUAL"; $status = "수동진단"; $summary = "HTTP (port 80) listener was found, but server{} block boundaries could not be resolved statically to confirm a same-block HTTP-to-HTTPS redirect. Manual review required."
        }
        elseif ($servers80.Count -gt 0 -and $servers80WithRedirect.Count -eq $servers80.Count) {
            # 모든 listen 80 server 블록이 동일 블록 내 https 리디렉션을 보유 → 양호.
            $finalResult = "GOOD"; $status = "양호"; $summary = "Every port 80 server block redirects HTTP to HTTPS (return 30x https:// or rewrite ... https://) within the same server block."
        }
        elseif ($servers80.Count -gt 0) {
            # listen 80 을 가진 server 블록 중 동일 블록 내 리디렉션이 없는 블록이 존재 → 평문 HTTP가 HTTPS로 리디렉션되지 않으므로 취약.
            $finalResult = "VULNERABLE"; $status = "취약"
            if ($hsts.Count -gt 0) {
                $summary = "A port 80 server block does not redirect HTTP to HTTPS within its own block (an HSTS header was present elsewhere, but HSTS alone does not redirect plaintext HTTP). Add a same-block return 30x/rewrite redirect."
            }
            else {
                $summary = "A port 80 server block does not redirect HTTP to HTTPS within its own block. A redirect elsewhere (e.g. inside the TLS/443 vhost) does not redirect plaintext HTTP on port 80."
            }
        }
        else {
            # $http(평탄화 라인 기준)에는 listen 80 이 있으나 server 블록 단위로는 분리되지 않음(블록 밖 listen 등) → 수동 판정.
            $finalResult = "MANUAL"; $status = "수동진단"; $summary = "A port 80 listener directive was found but could not be associated with a server{} block; confirm the redirect policy manually."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows HTTP redirect configuration discovery"
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
