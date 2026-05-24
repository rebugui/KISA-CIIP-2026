#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

CATEGORY="DBMS"
PLATFORM="Altibase_Linux"
TOTAL_ITEMS=26
declare -a RESULTS_JSON=()

for i in {1..26}; do
    item_id="$(printf 'D-%02d' "$i")"
    script_file="${SCRIPT_DIR}/${item_id//-/}_check.sh"
    if [ -f "${script_file}" ]; then
        export DBMS_RUNALL_MODE=1
        output="$(bash "${script_file}")"
        unset DBMS_RUNALL_MODE
        RESULTS_JSON+=("${output}")
        echo "${output}"
    fi
done

create_runall_aggregated_results "${CATEGORY}" "${PLATFORM}" "${SCRIPT_DIR}" "${TOTAL_ITEMS}" "${RESULTS_JSON[@]}"