#!/bin/bash -e
#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# Arguments
#
# 1: all|diff If "all" is provided, all of the source will be examined, which
#    can take a long time depending on how large the code base is. If "diff"
#    is provide, only the files that have changed will be examined. It should
#    be noted that if you only change a header, it is likely that the header
#    will not be examined as it is not listed in the compilation database
#
# 2: To support out of tree builds, this script needs to be run from the
#    build folder, and you must provide the source directory associated with
#    the build folder.
#
# 3: Additional arguments for the "-checks=" flag for clang tidy. This can
#    be used to disable specific checks that do not apply
#

# Note:
#
# To use this script, you need make sure you have a compilation database, and
# clang tidy set up properly.
#
#   cmake -DENABLE_TIDY=ON ..
#
# Once you have compiled Bareflank and created a compilation database,
# you should be able to run this script which will tell you if there are
# any issues with the code. The following describes what we turned off
# and why:
#
# - cppcoreguidelines-pro-type-reinterpret-cast: There are legit cases where we
#   need reinterpret_cast. As a result, we have disabled this. That being said,
#   each instance were it is used has been reviewed, and determined to be
#   needed. The remaining instances were removed in place of safer code.
#
# - cppcoreguidelines-pro-type-vararg: This needs to be turned off because
#   we require C apis that use this paradigm.
#
# - cert-err58-cpp: This is triggered by catch.hpp which we need
#
# - cert-err60-cpp: This is triggered by libc++ with std::runtime_error and
#   std::logic_error. The only solution to this would be to provide custom
#   exceptions which we might do in the future, but for now this is a bit
#   pedantic.
#
# - misc-noexcept-move-constructor: still buggy in LLVM 4.0
#

OUTPUT=$PWD/.clang_tidy_results.txt
NUM_CORES=$(grep -c ^processor /proc/cpuinfo)

get_changed_files() {
    pushd $2 > /dev/null
    if [[ "$1" == "all" ]]; then
        files=$(git ls-files | grep -Ee "\.(cpp|h|c)$" || true)
    else
        files=$(git diff --relative --name-only HEAD $PWD | grep -Ee "\.(cpp|h|c)$" || true)
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
        echo -e "\033[1;32m\xE2\x9C\x93 passed:\033[0m $1";
    fi
}

run_clang_tidy_script() {
    if [[ ! $2 == *"pthread.cpp" ]] && [[ ! $2 == *"syscall.cpp" ]]; then
        run-clang-tidy-4.0.py \
            -clang-tidy-binary clang-tidy-4.0 \
            -header-filter="*.h" \
            -j=$NUM_CORES \
            -checks=$1 \
            files $2 > $OUTPUT 2>&1
    fi
}

analyze() {
    for f in $files; do
        run_clang_tidy_script $2 $f
        verify_analysis "$3: $f"
    done
}

if [[ "$#" -lt 2 ]]; then
    echo "ERROR: missing arguments"
    exit 1
fi

if [[ ! -f "compile_commands.json" ]]; then
    echo "ERROR: database is missing. Did you run?"
    echo "    - cmake -DENABLE_TIDY=ON .."
    exit 1
fi

if [[ ! -x "$(which run-clang-tidy-4.0.py)" ]]; then
    echo "ERROR: run-clang-tidy-4.0.py not in PATH"
    exit 1
fi

if [[ ! "$1" == "all" ]] && [[ ! "$1" == "diff" ]]; then
    echo "ERROR: invalid opcode '$1'. Expecting 'all' or 'diff'"
    exit 1
fi

get_changed_files $1 $2

#
# Perform Checks
#
analyze $1 "clan*$3" "static analysis"
analyze $1 "cert*,-clang-analyzer*,-cert-err58-cpp,-cert-err60-cpp$3" "cert compliance"
analyze $1 "misc*,-clang-analyzer*,-misc-noexcept-move-constructor$3" "misc checks"
analyze $1 "perf*,-clang-analyzer*$3" "performance checks"
analyze $1 "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast,-cppcoreguidelines-pro-type-vararg$3" "c++ core guideline compliance"
analyze $1 "read*,-clang-analyzer*$3" "readability checks"
analyze $1 "mode*,-clang-analyzer*$3" "modernization checks"
