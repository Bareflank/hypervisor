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
# - CastToStruct: Currently, this is only disabled in the ELF loader as
#   the spec requires us to do this. For all other code this is enabled.
#
# - UnreachableCode: we disable this because it seems to output buggy
#   results. For some reason, anything with a try catch block, this seems
#   to get triggered. Furthermore, its not really needed since Coveralls tells
#   us if code cannot be reached, which is also evidence this check is not
#   working right, as it has a lot of false positives.
#
# - misc-noexcept-move-constructor: Like the above, this is known to be
#   buggy which is a shame because it's useful. Basically, if a move
#   constructor is set to "= default" this check fires even if noexcept is
#   provided (at least with 3.8)
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
# - bounds-pointer-arithmetic
# - bounds-constant-array-index
# - bounds-array-to-pointer-decay
#
#   We disabled the above only for the unwinder, and this is because the
#   unwinder needs to be implemented without using C++ librarys, which
#   includes the GSL, so there is no easy way to avoid these errors. Someday
#   we could implement a portion of the GSL inside the unwinder itself and
#   place it in the GSL namespace. This would provide the checks they are
#   looking for and please the linter, but for now these are simply disabled.
#   It should be noted that under the hood, glibc is not using C++ so the
#   code has the same issues.
#
# - modernize-pass-by-value: Also only turned off by the unwinder, this is
#   a performance issue that cannot be addressed because it requires the STL
#   which we cannot use in the unwinder.
#
# Additional Note:
#
# Currently we have -Wcast-align disabled for C as clang-tidy does not have
# a way to turn this off and it complains about the ELF loader. This means
# that right now, we only support archiectures with byte alignment.
#

%ENV_SOURCE%

if [[ ! -d "bfelf_loader" ]]; then
    echo "This script must be run from bareflank root directory"
    exit 1
fi

#
# Output
#
OUTPUT=$PWD/verify_source_results.txt

#
# Make sure we can run this script
#
if [[ ! -f "$BUILD_ABS/compile_commands.json" ]]; then
    echo "ERROR: database is missing. Did you run?"
    echo "    - STATIC_ANALYSIS_ENABLED=true bear make"
    echo "    - sudo ln -s /usr/bin/clang-tidy-3.8 /usr/bin/clang-tidy"
    exit 1
fi

#
# Cleanup
#
rm -Rf $OUTPUT

if [[ ! $BUILD_ABS == $HYPER_ABS ]]; then
    cp -Rf $BUILD_ABS/compile_commands.json $HYPER_ABS/compile_commands.json
fi

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
        grep -E --color=auto "warning: |error: " $OUTPUT
        exit -1;
    else
        echo -e "\xE2\x9C\x93 passed: $1";
    fi

    rm -Rf $OUTPUT
}

shopt -s extglob

#
# extensions
#
if ls src_*/ 1> /dev/null 2>&1; then
    for d in src_*/ ; do
        pushd $d > /dev/null
        header $PWD
        run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
        run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
        run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
        run_clang_tidy "perf*,-clang-analyzer*"
        run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
        run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
        run_clang_tidy "mode*,-clang-analyzer*"
        popd > /dev/null
    done

    if [[ $SRC_EXTENSION == "true" ]]; then
        exit 0
    fi
fi

#
# extensions
#
if ls hypervisor_*/ 1> /dev/null 2>&1; then
    for d in hypervisor_*/ ; do
        pushd $d > /dev/null
        header $PWD
        run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
        run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
        run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
        run_clang_tidy "perf*,-clang-analyzer*"
        run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
        run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
        run_clang_tidy "mode*,-clang-analyzer*"
        popd > /dev/null
    done

    if [[ $HYPERVISOR_EXTENSION == "true" ]]; then
        exit 0
    fi
fi

#
# hyperkernel
#
if [[ -d hyperkernel ]]; then
    pushd hyperkernel > /dev/null
    header $PWD
    run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
    run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
    run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
    run_clang_tidy "perf*,-clang-analyzer*"
    run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
    run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
    run_clang_tidy "mode*,-clang-analyzer*"
    popd > /dev/null

    if [[ $HYPERKERNEL_EXTENSION == "true" ]]; then
        exit 0
    fi
fi

#
# extended_apis
#
if [[ -d extended_apis ]]; then
    pushd extended_apis > /dev/null
    header $PWD
    run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
    run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
    run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
    run_clang_tidy "perf*,-clang-analyzer*"
    run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
    run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
    run_clang_tidy "mode*,-clang-analyzer*"
    popd > /dev/null

    if [[ $EXTENDED_APIS_EXTENSION == "true" ]]; then
        exit 0
    fi
fi

verify_bfvmm() {
    pushd bfvmm/src/$1 > /dev/null
    header $PWD
    run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
    run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
    run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
    run_clang_tidy "perf*,-clang-analyzer*"
    run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast"
    run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
    run_clang_tidy "mode*,-clang-analyzer*"
    popd > /dev/null
}

#
# bfvmm
#
verify_bfvmm debug_ring
verify_bfvmm entry
verify_bfvmm exit_handler
verify_bfvmm intrinsics
verify_bfvmm memory_manager
verify_bfvmm misc
verify_bfvmm serial
verify_bfvmm vcpu
verify_bfvmm vcpu_factory
verify_bfvmm vmcs
verify_bfvmm vmxon

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
# bfunwind
#
pushd bfunwind > /dev/null
header $PWD
run_clang_tidy "clan*,-clang-analyzer-alpha.deadcode.UnreachableCode"
run_clang_tidy "cert*,-clang-analyzer*,-cert-err60-cpp"
run_clang_tidy "misc*,-clang-analyzer*,-misc-noexcept-move-constructor"
run_clang_tidy "perf*,-clang-analyzer*"
run_clang_tidy "cppc*,-clang-analyzer*,-cppcoreguidelines-pro-type-reinterpret-cast,-cppcoreguidelines-pro-bounds-pointer-arithmetic,-cppcoreguidelines-pro-bounds-constant-array-index,-cppcoreguidelines-pro-bounds-array-to-pointer-decay"
run_clang_tidy "read*,-clang-analyzer*,-readability-braces-around-statements"
run_clang_tidy "mode*,-clang-analyzer*,-modernize-pass-by-value"
popd > /dev/null

#
# Cleanup
#
if [[ ! $BUILD_ABS == $HYPER_ABS ]]; then
    rm -Rf $HYPER_ABS/compile_commands.json
fi

rm -Rf $OUTPUT
