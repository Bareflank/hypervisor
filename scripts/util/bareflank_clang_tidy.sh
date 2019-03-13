#!/bin/bash -e
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

OUTPUT=$PWD/.clang_tidy_results.txt
NUM_CORES=$(grep -c ^processor /proc/cpuinfo)

get_changed_files() {
    pushd $2 > /dev/null
    if [[ "$1" == "all" ]]; then
        files=$(git ls-files | grep -Ee "\.(cpp|h|c)$" || true)
    elif [[ "$1" == "upstream" ]]; then
        files=$(git diff --relative --name-only --diff-filter=d upstream/master $PWD | grep -Ee "\.(cpp|h|c)$" || true)
    else
        files=$(git diff --relative --name-only --diff-filter=d origin $PWD | grep -Ee "\.(cpp|h|c)$" || true)
    fi
    popd > /dev/null
}

verify_analysis() {
    if [[ -n $(grep "warning: " $OUTPUT) ]] || [[ -n $(grep "error: " $OUTPUT) ]]; then
        echo ""
        echo "############################"
        echo "# Clang-Tidy Checks Failed #"
        echo "############################"
        echo ""
        grep --color -E '^|warning: |error: ' $OUTPUT
        exit -1;
    else
        echo -e "  \033[1;32m\xE2\x9C\x93 passed:\033[0m $3: $(realpath $2/$4)";
    fi
}

run_clang_tidy_script() {
    list=$(grep "TIDY_EXCLUSION" $2/$4 || true)

    checks=$3
    if [[ ! $3 == "clan*" ]]; then
        checks="$checks,-clang-analyzer*"
    fi

    while read -r line; do
        checks="$checks,$(echo $line | awk -F '=' '{print $2}')"
    done <<< "$list"

    # This test generates an error for all tests that include Hippomocks,
    # so we disable it here to keep things simple
    if [[ -n $(grep "MockRepository" $2/$4) ]]; then
        checks="$checks,-clang-analyzer-core.StackAddressEscape"
    fi

    # This test is really buggy an trips on structed bindings, falsely
    # stating that the variables are not read
    checks="$checks,-clang-analyzer-deadcode.DeadStores"

    run-clang-tidy-6.0.py \
        -clang-tidy-binary clang-tidy-6.0 \
        -header-filter="*.h" \
        -j=$NUM_CORES \
        -checks=$checks \
        files $(realpath $2/$4) > $OUTPUT 2>&1
}

analyze() {
    for f in $files; do
        run_clang_tidy_script $1 $2 $3 $f
        verify_analysis $1 $2 $3 $f
    done
}

if [[ "$#" -lt 2 ]]; then
    echo "ERROR: missing arguments"
    exit 1
fi

if [[ ! -x "$(which run-clang-tidy-6.0.py)" ]]; then
    echo "ERROR: run-clang-tidy-6.0.py not in PATH"
    exit 1
fi

if [[ ! "$1" == "all" ]] && [[ ! "$1" == "diff" ]] && [[ ! "$1" == "upstream" ]]; then
    echo "ERROR: invalid opcode '$1'. Expecting 'all' or 'diff'"
    exit 1
fi

get_changed_files $1 $2

if [[ -z "$files" ]]; then
    echo -e "\033[1;32m\xE2\x9C\x93 nothing changed:\033[0m $2";
    exit 0
elif [[ ! -f compile_commands.json ]]; then
    # INTERFACE libraries are not compiled, so they
    # will not have a compile_commands.json.
    exit 0
else
    echo -e "\033[1;33m- processing:";
    echo -e "  \033[1;35msrc - \033[0m$2";
    echo -e "  \033[1;35mbld - \033[0m$PWD";
fi

#
# Perform Checks
#
analyze $1 $2 "clan*"
analyze $1 $2 "cert*"
analyze $1 $2 "misc*"
analyze $1 $2 "perf*"
analyze $1 $2 "cppc*"
analyze $1 $2 "read*"
analyze $1 $2 "mode*"
