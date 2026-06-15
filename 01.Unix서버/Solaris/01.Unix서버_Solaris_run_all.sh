#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-17
# ============================================================================
# [점검 항목 상세]
# @ID          : All
# @Category    : Unix Server (유닉스 서버)
# @Platform    : Oracle Solaris
# @Severity    : 중
# @Title       : 모든 Unix 서버 점검 스크립트 실행
# @Description : Unix 서버 모든 점검 항목을 실행하는 스크립트 (Unix 형식)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

echo ""
echo "=============================================================================="
echo "KISA-CIIP-2026 Vulnerability Assessment Scripts"
echo "Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved."
echo "Version: 1.0.0"
echo "Last Updated: 2026-01-17"
echo "=============================================================================="
echo ""

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"

# ============================================================================
# 전체 진단 설정
# ============================================================================
CATEGORY="Unix 서버"
PLATFORM="Solaris"
TOTAL_ITEMS=67  # U-01~U-67

# 결과 저장 배열
declare -a RESULTS_JSON=()
declare -a FAILED_ITEMS=()
declare -a PASSED_ITEMS=()

# 진단 항목 목록 (U-01~U-67)
DIAGNOSIS_ITEMS=()
for i in {1..67}; do
    DIAGNOSIS_ITEMS+=("$(printf 'U-%02d' $i)")
done

# ============================================================================
# 진단 실행 함수 (Unix run_all 패턴)
# ============================================================================

# 단일 항목 진단 실행
run_single_check() {
    local item_id="$1"
    local script_file="${SCRIPT_DIR}/${item_id//-/}_check.sh"
    local tmp_output=$(mktemp)

    # 스크립트 파일 존재 확인
    if [ ! -f "$script_file" ]; then
        echo "[WARN] 스크립트 파일 없음: ${script_file}" >&2
        FAILED_ITEMS+=("$item_id")
        rm -f "$tmp_output"
        return 0
    fi

    # 진단 스크립트 실행 (출력 캡처)
    local start_time=$(date +%s)
    local exit_code=0

    # run_all 모드 설정 후 스크립트 실행
    export UNIX_RUNALL_MODE=1
    bash "$script_file" > "$tmp_output" 2>&1 || exit_code=$?
    unset UNIX_RUNALL_MODE

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # 결과 JSON 파싱 (stdout 캡처에서 추출)
    local json_output=""
    local final_result=""
    local summary=""
    local item_name=""

    # tmp_output에서 JSON 추출 (완전한 JSON 객체)
    # 중괄호 깊이를 추적하여 완전한 JSON 추출
    json_output=$(awk '
    BEGIN { obj=0; brace=0; in_json=0 }
    /^{/ {
        if (brace == 0) {
            obj = 1
            in_json = 1
        }
        brace++
    }
    /^}/ {
        brace--
        if (brace == 0 && obj) {
            print
            exit
        }
    }
    in_json { print }
    ' "$tmp_output")

    if [ -n "$json_output" ]; then
        # JSON 필드 추출
        item_name=$(json_extract_field "$json_output" "item_name")
        final_result=$(json_extract_field "$json_output" "final_result")

        # inspection.summary 추출
        summary=$(json_extract_field "$json_output" "summary")
        if [ -z "$summary" ]; then
            summary="진단 실패"
        fi

        RESULTS_JSON+=("$json_output")
    fi

    # 결과 확인
    if [ $exit_code -eq 0 ]; then
        PASSED_ITEMS+=("$item_id")
    else
        FAILED_ITEMS+=("$item_id")
    fi

    # PC 형식으로 CLI 출력 (간단한 요약만)
    echo "==================================================================="
    echo "진단 항목: ${item_id} (${current}/${TOTAL_ITEMS})"
    echo "==================================================================="
    echo "진단 항목: ${item_id} - ${item_name}"
    echo "${summary}"
    echo "  > 진단 완료: ${final_result}"
    echo ""

    # 텍스트 파일에 결과 append
    if [ -n "${json_output}" ] && [ -n "${TXT_FILE:-}" ]; then
        append_runall_text_result "$json_output" "$TXT_FILE"
    fi

    # 임시 파일 삭제
    rm -f "$tmp_output"

    return $exit_code
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    echo "==================================================================="
    echo "KISA 취약점 진단 시스템 - 전체 항목 일괄 진단"
    echo "==================================================================="
    echo "카테고리: ${CATEGORY}"
    echo "플랫폼: ${PLATFORM}"
    echo "진단 항목: ${DIAGNOSIS_ITEMS[*]}"
    echo "==================================================================="
    echo ""

    # 디스크 공간 확인
    check_disk_space

    # 텍스트 파일 초기화 (result_manager.sh 함수 사용)
    TXT_FILE=$(init_runall_text_file "${CATEGORY}" "${PLATFORM}" "${SCRIPT_DIR}")

    # 진단 시작 시간
    local start_time=$(date +%s)

    # 각 항목 진단 실행
    local current=0
    for item_id in "${DIAGNOSIS_ITEMS[@]}"; do
        current=$((current + 1))

        if run_single_check "$item_id"; then
            :
        else
            echo "[WARN] ${item_id} 진단 실패" >&2
        fi
    done

    # 진단 종료 시간
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))

    echo ""
    echo "==================================================================="
    echo "전체 진단 완료"
    echo "==================================================================="
    echo "총 소요 시간: ${total_duration}초 ($((total_duration / 60))분)"
    echo "성공: ${#PASSED_ITEMS[@]}개"
    echo "실패: ${#FAILED_ITEMS[@]}개"
    echo "==================================================================="
    echo ""

    # 통합 결과 파일 생성 (result_manager.sh 함수 사용)
    create_runall_aggregated_results \
        "${CATEGORY}" \
        "${PLATFORM}" \
        "${SCRIPT_DIR}" \
        "${TOTAL_ITEMS}" \
        "${RESULTS_JSON[@]}"

    echo ""
    echo "[완료] 전체 진단 완료"
    echo ""

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
