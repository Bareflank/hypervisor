#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

# Note:
#
# To use this script, you need to create a compilation database, which
# can be done by installing bear on your system, and running make with
# bear:
#
#   STATIC_ANALYSIS_ENABLED=true bear make
#
# Once you have compiled Bareflank and created a compilation database,
# you should be able to run this script which will tell you if there are
# any issues with the code. The following describes what we turned off
# and why:
#
# - CastToStruct: we disable this at the moment because we are doing a lot
#   of legit casting in the ELF loader, as this is really how the spec is
#   written.
#
# - UnreachableCode: we disable this because it seems to output buggy
#   results. For some reason, anything with a try catch block, this seems
#   to get triggered. Furthermore, its not really needed since Coveralls tells
#   us if code cannot be reached, which is also evidence this check is not
#   working right, as it has a lot of false positives.
#
# - reinterpret-cast: There are legit cases where we need reinterpret_cast.
#   As a result, we have disabled this. That being said, each instance were
#   it is used has been reviewed, and determined to be needed. The remaining
#   instances were removed in place of safer code.
#
# - braces-around-statements: Simply disagree with this one, and has
#   actually been proposed and declined for the C++ Core Guidelines. Instead,
#   analysis tools should detect incorrect indentation when these types
#   of errors occur.
#
# - cert-err60-cpp: This not only triggers an issue with Hippomocks, but is
#   also triggering on std::run_time and std::logic_error on Travis CI,
#   so we have it turned off where needed.
#
# Additional Note:
#
# Currently we have -Wcast-align disabled for C as clang-tidy does not have
# a way to turn this off and it complains about the ELF loader. This means
# that right now, we only support archiectures with byte alignment.
#

if [[ ! -d "bfelf_loader" ]]; then
    echo "This script must be run from bareflank root directory"
    exit 1
fi

#
# Output
#
OUTPUT=$PWD/verify_source_results.txt

#
# Cleanup
#
rm -Rf $OUTPUT

#
# Header
#
header() {
    echo "[ --- Verifying: $1 --- ]"
}

#
# Run Clang Tidy
#
run_clang_tidy() {
    run-clang-tidy-3.8.py -checks=$1 $PWD >> $OUTPUT 2> /dev/null
    if [[ -n $(grep "warning: " $OUTPUT) ]] || [[ -n $(grep "error: " $OUTPUT) ]]; then
        echo ""
        echo "############################"
        echo "# Clang-Tidy Checks Failed #"
        echo "############################"
        echo ""
        grep --color=auto "warning: " $OUTPUT
        exit -1;
    else
        echo -e "\xE2\x9C\x93 passed: $1";
    fi

    rm -Rf $OUTPUT
}

#
# bfcrt
#
pushd bfcrt > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*"
popd > /dev/null

#
# bfdrivers
#
pushd bfdrivers > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*"
popd > /dev/null

#
# bfelf_loader
#
pushd bfelf_loader > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.core.CastToStruct"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*"
popd > /dev/null

#
# bfm
#
pushd bfm > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*"
popd > /dev/null

#
# bfvmm
#
pushd bfvmm > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode,-clang-analyzer-unix.MismatchedDeallocator"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*"
popd > /dev/null
