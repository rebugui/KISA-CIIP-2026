#!/bin/bash
# KISA 취약점 진단 시스템 - 결과 관리자
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: 진단 결과 파일 생성, 저장, 관리 (T025-T029)

set -euo pipefail

# 결과 디렉토리 기본 경로
RESULT_DIR_BASE="results"
DATE_SUFFIX=$(date +%Y%m%d)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# POSIX-safe JSON string-field extractor (line-based, same coverage as the
# previous grep -P pattern: matches "key": "value" on a single line).
# Usage: json_extract_field "$json_text" "key" [head|tail]
json_extract_field() {
    local _json="$1"
    local _key="$2"
    local _mode="${3:-head}"
    local _matches
    _matches=$(printf '%s\n' "${_json}" | sed -n "s/.*\"${_key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
    if [ "${_mode}" = "tail" ]; then
        printf '%s' "${_matches}" | tail -1
    else
        printf '%s' "${_matches}" | head -1
    fi
}

# Run-all 모드 확인 (다중 환경 변수 지원 - PowerShell 표준화)
# 향후 표준: UNIX_RUNALL_MODE 사용 권장
# 하위 호환성: 기존 환경 변수들도 지원 (WS/PC/DBMS_RUNALL_MODE)
is_runall_mode() {
    [ "${UNIX_RUNALL_MODE:-0}" = "1" ] || \
    [ "${WS_RUNALL_MODE:-0}" = "1" ] || \
    [ "${PC_RUNALL_MODE:-0}" = "1" ] || \
    [ "${DBMS_RUNALL_MODE:-0}" = "1" ]
}

# JSON 문자열 이스케이프 헬퍼 함수
# 백슬래시, 쿼트, TAB, 줄바꿈을 이스케이프
escape_json_string() {
    local input="$1"
    # printf와 sed를 사용하여 이스케이프
    printf '%s' "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | awk '{printf "%s", $0} END {printf ""}' | tr '\n' '\\n'
}

# JSON 내용만 생성 (T027 - mode check 없음)
generate_json_content() {
    local item_id="$1"
    local item_name="$2"
    local status="$3"
    local final_result="$4"
    local inspection_summary="$5"
    local command_result="$6"
    local command_executed="$7"
    local guideline_purpose="$8"
    local guideline_threat="$9"
    local guideline_criteria_good="${10}"
    local guideline_criteria_bad="${11}"
    local guideline_remediation="${12}"

    # 모든 텍스트 필드 이스케이프
    inspection_summary=$(escape_json_string "$inspection_summary")
    guideline_purpose=$(escape_json_string "$guideline_purpose")
    guideline_threat=$(escape_json_string "$guideline_threat")
    guideline_criteria_good=$(escape_json_string "$guideline_criteria_good")
    guideline_criteria_bad=$(escape_json_string "$guideline_criteria_bad")
    guideline_remediation=$(escape_json_string "$guideline_remediation")
    command_executed=$(escape_json_string "$command_executed")

    # command_result는 while loop로 이스케이프 (줄바꿈을 \\n으로 변환)
    local escaped_result=""
    local newline=""
    while IFS= read -r line; do
        # 백슬래시, 쿼트, TAB 이스케이프
        line="${line//\\/\\\\}"
        line="${line//\"/\\\"}"
        line="${line//$'\t'/\\t}"
        escaped_result="${escaped_result}${newline}${line}"
        newline="\\\\n"
    done <<< "$command_result"

    cat << EOF
{
  "item_id": "${item_id}",
  "item_name": "${item_name}",
  "inspection": {
    "summary": "${inspection_summary}",
    "status": "${status}"
  },
  "final_result": "${final_result}",
  "command": "${command_executed}",
  "command_result": "${escaped_result}",
  "guideline": {
    "purpose": "${guideline_purpose}",
    "security_threat": "${guideline_threat}",
    "judgment_criteria_good": "${guideline_criteria_good}",
    "judgment_criteria_bad": "${guideline_criteria_bad}",
    "remediation": "${guideline_remediation}"
  },
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(get_hostname)"
}
EOF
}

# 결과 파일 경로 생성 (T026)
# 사용법: create_result_file_path <item_id> [<script_dir>]
# script_dir이 없으면 SCRIPT_DIR 사용 (호환성 유지)
create_result_file_path() {
    local item_id="$1"
    local script_dir="${2:-${SCRIPT_DIR}}"
    local platform_dir="${script_dir}/${RESULT_DIR_BASE}/${DATE_SUFFIX}"
    local hostname=$(get_hostname)

    # 날짜별 폴더 생성 (FR-003: results/YYYYMMDD/ 구조)
    mkdir -p "${platform_dir}"

    # 결과 파일 경로 반환: {HOSTNAME}_{ITEM_ID}_result_{YYYYMMDD}_{HHMMSS}
    echo "${platform_dir}/${hostname}_${item_id}_result_${TIMESTAMP}"
}

# JSON 결과 생성 및 저장 (T027)
save_json_result() {
    local item_id="$1"
    local item_name="$2"
    local status="$3"           # 양호, 취약, 수동진단, N/A
    local final_result="$4"      # GOOD, VULNERABLE, MANUAL, N/A
    local inspection_summary="$5"
    local command_result="$6"
    local command_executed="$7"
    local guideline_purpose="$8"
    local guideline_threat="$9"
    local guideline_criteria_good="${10}"
    local guideline_criteria_bad="${11}"
    local guideline_remediation="${12}"

    local result_path=$(create_result_file_path "${item_id}")

    # JSON 결과 생성 (generate_json_content 함수 호출 - escaping 포함)
    local json_content=$(generate_json_content \
        "${item_id}" \
        "${item_name}" \
        "${status}" \
        "${final_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${guideline_purpose}" \
        "${guideline_threat}" \
        "${guideline_criteria_good}" \
        "${guideline_criteria_bad}" \
        "${guideline_remediation}")

    # Run-all 모드: stdout으로 JSON만 출력, 파일 생성 안함
    if is_runall_mode; then
        echo "$json_content"
        return 0
    fi

    # 개별 실행 모드: 파일로 저장
    echo "$json_content" > "${result_path}.json"

    # JSON 유효성 검증 (jq가 있을 경우)
    if command -v jq &>/dev/null; then
        if ! jq empty "${result_path}.json" &>/dev/null; then
            echo "❌ 치명적 오류: JSON 유효성 검증 실패" >&2
            echo "파일: ${result_path}.json" >&2
            return 1
        fi
    fi

    echo "${result_path}.json"
}

# 텍스트 결과 생성 및 저장 (T028) - Appendix C 형식 준수
save_text_result() {
    local item_id="$1"
    local item_name="$2"
    local status="$3"
    local final_result="$4"
    local inspection_summary="$5"
    local command_result="$6"
    local command_executed="$7"
    local guideline_purpose="${8:-}"
    local guideline_threat="${9:-}"
    local guideline_criteria_good="${10:-}"
    local guideline_criteria_bad="${11:-}"
    local guideline_remediation="${12:-}"

    local result_path=$(create_result_file_path "${item_id}")

    # Run-all 모드: 파일 생성 안함
    if is_runall_mode; then
        return 0
    fi

    # 개별 실행 모드: 파일로 저장
    # Appendix C 형식으로 텍스트 결과 생성 (PC run_all 표준 형식)
    cat > "${result_path}.txt" << EOF
============================================================
[${item_id}] ${item_name}
============================================================
[${item_id}-START]

${inspection_summary}

[현황]
1) 진단 확인
command: ${command_executed}
command_result:
${command_result}

[${item_id}-END]

[${item_id}]Result : ${final_result}

[참고]
진단 목적: ${guideline_purpose}
보안 위협: ${guideline_threat}
양호 기준: ${guideline_criteria_good}
취약 기준: ${guideline_criteria_bad}
조치 방법: ${guideline_remediation}

============================================================
EOF

    echo "${result_path}.txt"
}

# 이중 결과 생성 (JSON + Text)
save_dual_result() {
    # Run-all 모드: JSON만 stdout로 직접 출력 (변수 할당 없이)
    if is_runall_mode; then
        save_json_result "$@"
        return 0
    fi

    # 개별 실행 모드: 파일로 저장 후 경로 출력
    local json_path=$(save_json_result "$@")
    local text_path=$(save_text_result "$@")

    #echo "JSON: ${json_path}"
    #echo "Text: ${text_path}"

    # 텍스트 파일 내용 출력 (사용자가 바로 확인 가능)
    echo ""
    #echo "============================================================"
    #echo "📄 상세 진단 결과"
    #echo "============================================================"
    cat "${text_path}"
}

# 결과 파일 존재 확인 (FR-003: 생성 실패 시 exit 1)
verify_result_saved() {
    local item_id="$1"
    local result_path=$(create_result_file_path "${item_id}")

    # Run-all 모드: 파일 확인 건너뜀
    if is_runall_mode; then
        return 0
    fi

    # 개별 실행 모드: 파일 존재 확인
    if [ ! -f "${result_path}.json" ] || [ ! -f "${result_path}.txt" ]; then
        echo "❌ 치명적 오류: 결과 파일 생성 실패" >&2
        echo "예상 경로: ${result_path}" >&2
        exit 1
    fi
    echo ""
    echo "결과 파일 저장 확인: ${result_path}.{json,txt}"
    echo ""

}

# 과거 결과 파일 조회 (T193 이후 배치 진단용)
list_historical_results() {
    local item_id="$1"
    local days="${2:-7}"  # 기본 7일

    local cutoff_date=$(date -d "${days} days ago" +%Y%m%d 2>/dev/null || date -v-${days}d +%Y%m%d)
    local results_dir="${SCRIPT_DIR}/../${RESULT_DIR_BASE}"

    if [ ! -d "${results_dir}" ]; then
        echo "⚠️  결과 디렉토리 없음: ${results_dir}"
        return 0
    fi

    echo "📋 과거 진단 결과 (최근 ${days}일):"
    echo ""

    # 날짜별 폴더 순회
    for date_dir in $(ls -1 "${results_dir}" | sort -r | grep -E "^[0-9]{8}$"); do
        if [ "${date_dir}" -ge "${cutoff_date}" ]; then
            local results=$(find "${results_dir}/${date_dir}" -name "*_${item_id}_result_*.json" 2>/dev/null || true)

            if [ -n "$results" ]; then
                echo "📁 ${date_dir}:"
                echo "$results" | while read -r result_file; do
                    local timestamp=$(stat -c %y "${result_file}" 2>/dev/null | cut -d'.' -f1 || stat -f "%Sm" "${result_file}")
                    local filename=$(basename "${result_file}")
                    echo "   - ${filename} (${timestamp})"
                done
                echo ""
            fi
        fi
    done
}

# 결과 파일 정리 (오래된 결과 보관/삭제)
cleanup_old_results() {
    local keep_days="${1:-30}"  # 기본 30일 보관
    local results_dir="${SCRIPT_DIR}/../${RESULT_DIR_BASE}"

    if [ ! -d "${results_dir}" ]; then
        echo "⚠️  결과 디렉토리 없음: ${results_dir}"
        return 0
    fi

    echo "🧹 ${keep_days}일 이상된 결과 정리 중..."

    local cutoff_date=$(date -d "${keep_days} days ago" +%Y%m%d 2>/dev/null || date -v-${keep_days}d +%Y%m%d)
    local cleaned_count=0

    for date_dir in $(ls -1 "${results_dir}" | grep -E "^[0-9]{8}$" || true); do
        if [ "${date_dir}" -lt "${cutoff_date}" ]; then
            echo "🗑️  삭제: ${results_dir}/${date_dir}"
            # rm -rf "${results_dir}/${date_dir}"  # 실제 삭제는 비활성화 (안전장치)
            ((cleaned_count++))
        fi
    done

    if [ $cleaned_count -eq 0 ]; then
        echo "✅ 정리할 과거 결과 없음"
    else
        echo "✅ ${cleaned_count}개 디렉토리 정리 대상 (삭제 미실행)"
    fi
}

# 결과 통계 생성 (T193 배치 진단용)
generate_result_statistics() {
    local results_dir="${SCRIPT_DIR}/../${RESULT_DIR_BASE}"

    if [ ! -d "${results_dir}" ]; then
        echo "⚠️  결과 디렉토리 없음"
        return 0
    fi

    echo "📊 진단 결과 통계:"
    echo ""

    local total_json=$(find "${results_dir}" -name "*.json" 2>/dev/null | wc -l)
    local total_txt=$(find "${results_dir}" -name "*.txt" 2>/dev/null | wc -l)
    local good_count=$(grep -l '"final_result": "GOOD"' "${results_dir}"/*/*.json 2>/dev/null | wc -l || echo 0)
    local vulnerable_count=$(grep -l '"final_result": "VULNERABLE"' "${results_dir}"/*/*.json 2>/dev/null | wc -l || echo 0)
    local manual_count=$(grep -l '"final_result": "MANUAL"' "${results_dir}"/*/*.json 2>/dev/null | wc -l || echo 0)

    echo "총 JSON 결과: ${total_json}"
    echo "총 텍스트 결과: ${total_txt}"
    echo "양호 (GOOD): ${good_count}"
    echo "취약 (VULNERABLE): ${vulnerable_count}"
    echo "수동진단 (MANUAL): ${manual_count}"
    echo ""
}

# 공통 라이브러리 함수 호환성을 위한 별칭 (alias)
if [ -z "$(type -t create_result_path)" ]; then
    create_result_path() { create_result_file_path "$@"; }
fi

if [ -z "$(type -t create_json_result)" ]; then
    create_json_result() { save_json_result "$@"; }
fi

if [ -z "$(type -t create_text_result)" ]; then
    create_text_result() { save_text_result "$@"; }
fi

# ============================================================================
# Run-all 통합 결과 관리 (Unix 형식)
# ============================================================================

# 전역 변수: run_all 텍스트 파일 경로
TXT_FILE=""

# 텍스트 파일 헤더 초기화 (Unix run_all 패턴)
# 사용법: init_runall_text_file "$CATEGORY" "$PLATFORM" "$SCRIPT_DIR"
init_runall_text_file() {
    local category="$1"
    local platform="$2"
    local script_dir="$3"

    local hostname=$(get_hostname)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local date_suffix=$(date +%Y%m%d)
    local result_dir="${script_dir}/results/${date_suffix}"

    # 결과 디렉토리 생성
    mkdir -p "${result_dir}"

    # 텍스트 파일 경로 설정 (전역 변수)
    local normalized_category="${category// /_}"  # 공백을 언더스코어로 변환
    TXT_FILE="${result_dir}/${hostname}_${normalized_category}_${platform}_all_results_${timestamp}.txt"

    # 헤더 생성
    cat > "${TXT_FILE}" << EOF
==============================================================================
KISA-CIIP-2026 Vulnerability Assessment Scripts
Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
Version: 1.0.0
Last Updated: 2026-01-16
==============================================================================

=================================================================
KISA 취약점 진단 시스템 - 전체 항목 진단 결과
=================================================================

카테고리: ${category}
플랫폼: ${platform}
진단 시간: $(date '+%Y-%m-%d %H:%M:%S')
호스트네임: ${hostname}

-----------------------------------------------------------------
진단 통계
-----------------------------------------------------------------
EOF

    # TXT_FILE 전역 변수 설정 (호출자에게 반환)
    printf '%s' "${TXT_FILE}"
}

# 텍스트 파일에 단일 항목 결과 append (Unix run_all 패턴)
# 사용법: append_runall_text_result "$json_obj" "$txt_file"
append_runall_text_result() {
    local json_obj="$1"
    local txt_file="$2"

    # JSON 필드 추출
    local item_id=$(json_extract_field "$json_obj" "item_id")
    local item_name=$(json_extract_field "$json_obj" "item_name")

    # inspection 객체에서 추출
    local summary=$(json_extract_field "$json_obj" "summary")

    local command=$(json_extract_field "$json_obj" "command")
    local command_result=$(json_extract_field "$json_obj" "command_result")
    # \r\n 이스케이프 문자를 실제 줄바꿈으로 변환
    command_result=$(echo "$command_result" | sed 's/\\r\\n/\n/g; s/\\n/\n/g; s/\\r/\r/g')
    local final_result=$(json_extract_field "$json_obj" "final_result")

    # guideline 객체에서 추출 (단순화된 패턴)
    local guideline_purpose=$(json_extract_field "$json_obj" "purpose" tail)
    local guideline_threat=$(json_extract_field "$json_obj" "security_threat" tail)
    local guideline_criteria_good=$(json_extract_field "$json_obj" "judgment_criteria_good" tail)
    local guideline_criteria_bad=$(json_extract_field "$json_obj" "judgment_criteria_bad" tail)
    local guideline_remediation=$(json_extract_field "$json_obj" "remediation" tail)

    # TXT 형식으로 append (PC run_all과 동일한 형식)
    cat >> "${txt_file}" << EOF

============================================================
[${item_id}]${item_name}
============================================================
[${item_id}-START]

${summary}

[현황]
1) 진단 확인
command: ${command}
command_result:
${command_result}

[${item_id}-END]

[${item_id}]Result : ${final_result}

[참고]
진단 목적: ${guideline_purpose}
보안 위협: ${guideline_threat}
양호 기준: ${guideline_criteria_good}
취약 기준: ${guideline_criteria_bad}
조치 방법: ${guideline_remediation}

============================================================
EOF
}

# 통합 결과 파일 생성 (최종 JSON + 텍스트 푸터)
# 사용법: create_runall_aggregated_results "$category" "$platform" "$script_dir" "$total_items" "${passed_items[@]}" "${failed_items[@]}" "${RESULTS_JSON[@]}"
create_runall_aggregated_results() {
    local category="$1"
    local platform="$2"
    local script_dir="$3"
    local total_items="$4"
    shift 4

    # passed_items 배열 첫 번째 요소로 배열 크기 계산
    # 첫 번째 배열: passed_items
    # 두 번째 배열: failed_items
    # 세 번째 배열: results_json

    # 모든 인자를 받아서 처리
    local all_args=("$@")
    local total_args=${#all_args[@]}

    # 첫 번째 배열(passed_items)의 크기는 passed_count와 동일
    # 첫 번째 배열과 두 번째 배열(failed_items)의 크기 합은 results_json보다 작음
    # 우리는 RESULTS_JSON 배열의 크기를 알고 있음 (total_items와 동일)

    # passed_items와 failed_items를 분리하기 위해 구분자 사용
    # 각 배열의 크기는 호출자가 알고 있으므로, 모든 인자를 results_json으로 처리
    # passed_items와 failed_items는 결과에서 추출

    local passed_items_array=()
    local failed_items_array=()
    local results_json_array=()

    # 첫 번째 배열은 passed_items (passed_count만큼)
    # 두 번째 배열은 failed_items (failed_count만큼)
    # 나머지는 results_json

    # 실제로는 RESULTS_JSON의 각 항목에서 final_result를 확인하여 분류
    local good_items_array=()  # 양호 (GOOD)
    local vuln_items_array=()  # 취약 (VULNERABLE)
    local manual_items_array=() # 수동진단 (MANUAL)
    local error_items_array=()  # 진단 실패/N/A

    for json_obj in "${all_args[@]}"; do
        # JSON 파싱
        local item_id=$(json_extract_field "$json_obj" "item_id")
        local final_result=$(json_extract_field "$json_obj" "final_result")

        results_json_array+=("$json_obj")

        # final_result에 따라 분류
        case "$final_result" in
            "GOOD")
                good_items_array+=("$item_id")
                ;;
            "VULNERABLE")
                vuln_items_array+=("$item_id")
                ;;
            "MANUAL")
                manual_items_array+=("$item_id")
                ;;
            *)
                error_items_array+=("$item_id")
                ;;
        esac
    done

    local good_count=${#good_items_array[@]}
    local vuln_count=${#vuln_items_array[@]}
    local manual_count=${#manual_items_array[@]}
    local error_count=${#error_items_array[@]}
    local total_count=$((good_count + vuln_count + manual_count + error_count))

    local hostname=$(get_hostname)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local date_suffix=$(date +%Y%m%d)
    local result_dir="${script_dir}/results/${date_suffix}"

    # 결과 디렉토리 생성
    mkdir -p "${result_dir}"

    # 통계를 텍스트 파일에 append
    if [ -n "${TXT_FILE:-}" ] && [ -f "${TXT_FILE}" ]; then
        local good_rate=0
        if [ "$total_items" -gt 0 ]; then
            good_rate=$(awk "BEGIN {printf \"%.1f\", ($good_count * 100.0) / $total_items}")
        fi

        cat >> "${TXT_FILE}" << EOF

총 항목: ${total_items}
양호: ${good_count}
취약: ${vuln_count}
N/A: ${error_count}
수동: ${manual_count}
양호율: ${good_rate}%

-----------------------------------------------------------------
양호 항목 (${good_count}개)
-----------------------------------------------------------------
$(printf '%s\n' "${good_items_array[@]}")

-----------------------------------------------------------------
취약 항목 (${vuln_count}개)
-----------------------------------------------------------------
$(printf '%s\n' "${vuln_items_array[@]}")

-----------------------------------------------------------------
수동 진단 항목 (${manual_count}개)
-----------------------------------------------------------------
$(printf '%s\n' "${manual_items_array[@]}")

-----------------------------------------------------------------
진단 실패/N/A 항목 (${error_count}개)
-----------------------------------------------------------------
$(printf '%s\n' "${error_items_array[@]}")

EOF
        # 텍스트 파일에 푸터 추가
        cat >> "${TXT_FILE}" << EOF

=================================================================
진단 시간: $(date '+%Y-%m-%d %H:%M:%S')
=================================================================
EOF
        echo "📄 통합 텍스트 결과 완료: ${TXT_FILE}"
    fi

    # JSON 통합 결과 생성
    local normalized_category="${category// /_}"  # 공백을 언더스코어로 변환
    local json_file="${result_dir}/${hostname}_${normalized_category}_${platform}_all_results_${timestamp}.json"

    # 최종 JSON 생성
    (
        echo "{"
        echo "  \"category\": \"${category}\","
        echo "  \"platform\": \"${platform}\","
        echo "  \"total_items\": ${total_items},"
        echo "  \"good_items\": ${good_count},"
        echo "  \"vulnerable_items\": ${vuln_count},"
        echo "  \"manual_items\": ${manual_count},"
        echo "  \"error_items\": ${error_count},"
        echo "  \"timestamp\": \"$(date -Iseconds 2>/dev/null || date)\","
        echo "  \"hostname\": \"${hostname}\","
        echo "  \"items\": ["
        local first=true
        for json_obj in "${results_json_array[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "$json_obj" | sed 's/^/    /'
        done
        echo ""
        echo "  ]"
        echo "}"
    ) > "${json_file}"

    echo "📊 통합 JSON 결과 저장: ${json_file}"
}
