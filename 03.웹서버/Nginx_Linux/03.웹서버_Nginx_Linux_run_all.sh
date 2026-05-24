#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (?묒슦??. All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-17
# ============================================================================
# [?먭? ??ぉ ?곸꽭]
# @ID          : All
# @Category    : Web Server (???쒕쾭)
# @Platform    : Nginx
# @Severity    : 以?# @Title       : 紐⑤뱺 ?뱀꽌踰??먭? ?ㅽ겕由쏀듃 ?ㅽ뻾
# @Description : ?뱀꽌踰?紐⑤뱺 ?먭? ??ぉ???ㅽ뻾?섎뒗 ?ㅽ겕由쏀듃 (Unix ?뺤떇)
# @Reference   : 2026 KISA 二쇱슂?뺣낫?듭떊湲곕컲?쒖꽕 湲곗닠??痍⑥빟??遺꾩꽍쨌?됯? ?곸꽭 媛?대뱶
# ============================================================================

echo ""
echo "=============================================================================="
echo "KISA-CIIP-2026 Vulnerability Assessment Scripts"
echo "Copyright (c) 2026 Yang Uhyeok (?묒슦??. All rights reserved."
echo "Version: 1.0.0"
echo "Last Updated: 2026-01-17"
echo "=============================================================================="
echo ""

# ?ㅽ겕由쏀듃 ?붾젆?좊━ ?ㅼ젙
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# ?꾩닔 ?쇱씠釉뚮윭由?濡쒕뱶
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"

# ============================================================================
# ?꾩껜 吏꾨떒 ?ㅼ젙
# ============================================================================
CATEGORY="Web Server"
PLATFORM="Nginx_Linux"
TOTAL_ITEMS=26  # WEB-01~WEB-26

# 寃곌낵 ???諛곗뿴
declare -a RESULTS_JSON=()
declare -a FAILED_ITEMS=()
declare -a PASSED_ITEMS=()

# 吏꾨떒 ??ぉ 紐⑸줉 (WEB-01~WEB-26)
DIAGNOSIS_ITEMS=()
for i in {1..26}; do
    DIAGNOSIS_ITEMS+=("$(printf 'WEB-%02d' $i)")
done

# ============================================================================
# 吏꾨떒 ?ㅽ뻾 ?⑥닔 (Unix run_all ?⑦꽩)
# ============================================================================

# ?⑥씪 ??ぉ 吏꾨떒 ?ㅽ뻾
run_single_check() {
    local item_id="$1"
    local script_file="${SCRIPT_DIR}/${item_id//-/}_check.sh"
    local tmp_output=$(mktemp)

    # ?ㅽ겕由쏀듃 ?뚯씪 議댁옱 ?뺤씤
    if [ ! -f "$script_file" ]; then
        echo "[WARN] ?ㅽ겕由쏀듃 ?뚯씪 ?놁쓬: ${script_file}" >&2
        FAILED_ITEMS+=("$item_id")
        rm -f "$tmp_output"
        return 0
    fi

    # 吏꾨떒 ?ㅽ겕由쏀듃 ?ㅽ뻾 (異쒕젰 罹≪쿂)
    local start_time=$(date +%s)
    local exit_code=0

    # run_all 紐⑤뱶 ?ㅼ젙 ???ㅽ겕由쏀듃 ?ㅽ뻾
    export WS_RUNALL_MODE=1
    bash "$script_file" > "$tmp_output" 2>&1 || exit_code=$?
    unset WS_RUNALL_MODE

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # 寃곌낵 JSON ?뚯떛 (stdout 罹≪쿂?먯꽌 異붿텧)
    local json_output=""
    local final_result=""
    local summary=""
    local item_name=""

    # tmp_output?먯꽌 JSON 異붿텧 (?꾩쟾??JSON 媛앹껜)
    # 以묎큵??源딆씠瑜?異붿쟻?섏뿬 ?꾩쟾??JSON 異붿텧
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
        # JSON ?꾨뱶 異붿텧
        item_name=$(echo "$json_output" 2>/dev/null | grep -oP '"item_name":\s*"\K[^"]+' | head -1 || echo "")
        final_result=$(echo "$json_output" 2>/dev/null | grep -oP '"final_result":\s*"\K[^"]+' | head -1 || echo "")

        # inspection.summary 異붿텧
        summary=$(echo "$json_output" 2>/dev/null | grep -oP '"inspection":\s*\{[^}]*"summary":\s*"\K[^"]+' | head -1 || echo "")
        if [ -z "$summary" ]; then
            summary=$(echo "$json_output" 2>/dev/null | grep -oP '"summary":\s*"\K[^"]+' | head -1 || echo "吏꾨떒 ?ㅽ뙣")
        fi

        RESULTS_JSON+=("$json_output")
    fi

    # 寃곌낵 ?뺤씤
    if [ $exit_code -eq 0 ]; then
        PASSED_ITEMS+=("$item_id")
    else
        FAILED_ITEMS+=("$item_id")
    fi

    # Print concise per-item progress.
    echo "==================================================================="
    echo "Diagnostic item: ${item_id} (${current}/${TOTAL_ITEMS})"
    echo "==================================================================="
    echo "Diagnostic item: ${item_id} - ${item_name}"
    echo "${summary}"
    echo "  > Diagnostic complete: ${final_result}"
    echo ""

    # ?띿뒪???뚯씪??寃곌낵 append
    if [ -n "${json_output}" ] && [ -n "${TXT_FILE:-}" ]; then
        append_runall_text_result "$json_output" "$TXT_FILE"
    fi

    # ?꾩떆 ?뚯씪 ??젣
    rm -f "$tmp_output"

    return $exit_code
}

# ============================================================================
# 硫붿씤 ?ㅽ뻾
# ============================================================================

main() {
    echo "==================================================================="
    echo "KISA 痍⑥빟??吏꾨떒 ?쒖뒪??- ?꾩껜 ??ぉ ?쇨큵 吏꾨떒"
    echo "==================================================================="
    echo "移댄뀒怨좊━: ${CATEGORY}"
    echo "?뚮옯?? ${PLATFORM}"
    echo "吏꾨떒 ??ぉ: ${DIAGNOSIS_ITEMS[*]}"
    echo "==================================================================="
    echo ""

    # ?붿뒪??怨듦컙 ?뺤씤
    check_disk_space

    # ?띿뒪???뚯씪 珥덇린??(result_manager.sh ?⑥닔 ?ъ슜)
    TXT_FILE=$(init_runall_text_file "${CATEGORY}" "${PLATFORM}" "${SCRIPT_DIR}")

    # 吏꾨떒 ?쒖옉 ?쒓컙
    local start_time=$(date +%s)

    # 媛???ぉ 吏꾨떒 ?ㅽ뻾
    local current=0
    for item_id in "${DIAGNOSIS_ITEMS[@]}"; do
        current=$((current + 1))

        if run_single_check "$item_id"; then
            :
        else
            echo "[WARN] ${item_id} 吏꾨떒 ?ㅽ뙣" >&2
        fi
    done

    # 吏꾨떒 醫낅즺 ?쒓컙
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))

    echo ""
    echo "==================================================================="
    echo "?꾩껜 吏꾨떒 ?꾨즺"
    echo "==================================================================="
    echo "珥??뚯슂 ?쒓컙: ${total_duration}珥?($((total_duration / 60))遺?"
    echo "?깃났: ${#PASSED_ITEMS[@]}媛?
    echo "?ㅽ뙣: ${#FAILED_ITEMS[@]}媛?
    echo "==================================================================="
    echo ""

    # ?듯빀 寃곌낵 ?뚯씪 ?앹꽦 (result_manager.sh ?⑥닔 ?ъ슜)
    create_runall_aggregated_results \
        "${CATEGORY}" \
        "${PLATFORM}" \
        "${SCRIPT_DIR}" \
        "${TOTAL_ITEMS}" \
        "${RESULTS_JSON[@]}"

    echo ""
    echo "[?꾨즺] ?꾩껜 吏꾨떒 ?꾨즺"
    echo ""

    return 0
}

# ?ㅽ겕由쏀듃 吏곸젒 ?ㅽ뻾 ?쒖뿉留?吏꾨떒 ?섑뻾
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
