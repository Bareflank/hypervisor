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

# ------------------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------------------

CB='\033[1;35m'
CC='\033[1;36m'
CE='\033[0m'

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

verify_file_exists() {
    if [[ ! -f $1 ]]; then
        echo "test failed [$2]: expected file missing: $1"
        exit 1
    fi
}

verify_link_exists() {
    if [[ ! -L $1 ]]; then
        echo "test failed [$2]: expected link missing: $1"
        exit 1
    fi
}

verify_directory_exists() {
    if [[ ! -d $1 ]]; then
        echo "test failed [$2]: expected directory missing: $1"
        exit 1
    fi
}

verify_file_does_not_exist() {
    if [[ -f $1 ]]; then
        echo "test failed [$2]: file still exists: $1"
        exit 1
    fi
}

verify_link_does_not_exist() {
    if [[ -L $1 ]]; then
        echo "test failed [$2]: link still exists: $1"
        exit 1
    fi
}

verify_directory_does_not_exist() {
    if [[ -d $1 ]]; then
        echo "test failed [$2]: directory still exists: $1"
        exit 1
    fi
}

verify_directory_is_empty() {
    if [[ "$(ls -A $1)" ]]; then
        echo "test failed [$2]: directory is not empty as expected: $1"
        exit 1
    fi
}

verify_file_is_newer_than() {
    if nt "$2" "$1"; then
        echo "test failed [$3]: $1 was never updated"
        exit 1
    fi
}

verify_file_is_older_than() {
    if nt "$1" "$2"; then
        echo "test failed [$3]: $1 was updated and it should not have been"
        exit 1
    fi
}

verify_file_contents() {
    local contents=`cat $1`
    if [[ ! $contents == $2 ]]; then
        echo "test failed [$3]: file does not contain expected contents: $1"
        exit 1
    fi
}

verify_exit_status() {
    if [[ ! $1 == $2 ]]; then
        echo "test failed [$3]: exit status was $1. was expecting $2"
        exit 1
    fi
}

verify_default_created() {
    verify_file_exists $1/Makefile $2
    verify_file_exists $1/build_version $2
    verify_file_exists $1/env.sh $2
    verify_file_exists $1/git_working_tree.sh $2
    verify_file_exists $1/module_file $2
    verify_file_exists $1/build_scripts/compiler_wrapper.sh $2
    verify_file_exists $1/build_scripts/build_libbfc.sh $2
    verify_file_exists $1/build_scripts/build_libcxxabi.sh $2
    verify_file_exists $1/build_scripts/build_libcxx.sh $2
    verify_file_exists $1/build_scripts/build_newlib.sh $2
    verify_file_exists $1/build_scripts/fetch_libbfc.sh $2
    verify_file_exists $1/build_scripts/fetch_libcxxabi.sh $2
    verify_file_exists $1/build_scripts/fetch_libcxx.sh $2
    verify_file_exists $1/build_scripts/fetch_llvm.sh $2
    verify_file_exists $1/build_scripts/fetch_newlib.sh $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-ar $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-clang $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-clang++ $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-nasm $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-docker $2
    verify_file_exists $1/build_scripts/x86_64-bareflank-ranlib $2
    verify_directory_exists $1/makefiles $2
}

verify_default_removed() {
    verify_file_does_not_exist $1/Makefile $2
    verify_file_does_not_exist $1/build_version $2
    verify_file_does_not_exist $1/env.sh $2
    verify_file_does_not_exist $1/git_working_tree.sh $2
    verify_file_does_not_exist $1/module_file $2
    verify_file_does_not_exist $1/build_scripts/compiler_wrapper.sh $2
    verify_file_does_not_exist $1/build_scripts/build_libbfc.sh $2
    verify_file_does_not_exist $1/build_scripts/build_libcxxabi.sh $2
    verify_file_does_not_exist $1/build_scripts/build_libcxx.sh $2
    verify_file_does_not_exist $1/build_scripts/build_newlib.sh $2
    verify_file_does_not_exist $1/build_scripts/fetch_libbfc.sh $2
    verify_file_does_not_exist $1/build_scripts/fetch_libcxxabi.sh $2
    verify_file_does_not_exist $1/build_scripts/fetch_libcxx.sh $2
    verify_file_does_not_exist $1/build_scripts/fetch_llvm.sh $2
    verify_file_does_not_exist $1/build_scripts/fetch_newlib.sh $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-ar $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-clang $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-clang++ $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-nasm $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-docker $2
    verify_file_does_not_exist $1/build_scripts/x86_64-bareflank-ranlib $2
    verify_directory_does_not_exist $1/makefiles $2
}

create_oot_environment() {
    rm -Rf $BR
    mkdir -p $BR
}

create_it_environment() {
    rm -Rf $BR
    mkdir -p $BR

    rm -Rf $TR
    cp -Rfp $HR $TR
}

nt() {

    if [[ ! -f $1 ]]; then
        return 1
    fi

    if [[ ! -f $2 ]]; then
        return 0
    fi

    file1_ts=`date +"%y%m%d%H%M%S" -r $1`
    file2_ts=`date +"%y%m%d%H%M%S" -r $2`

    if [[ $((10#$file1_ts)) -eq $((10#$file2_ts)) ]]; then
        file1_ts=`date +"%N" -r $1`
        file2_ts=`date +"%N" -r $2`
        if [[ $((10#$file1_ts)) -gt $((10#$file2_ts)) ]]; then
            return 0
        else
            return 1
        fi
    else
        if [[ $((10#$file1_ts)) -gt $((10#$file2_ts)) ]]; then
            return 0
        else
            return 1
        fi
    fi
}

touch_file() {
    touch $1
    sync
}

print_test() {
    echo -e "$CC""testing: $CB$1$CE"
}

# ------------------------------------------------------------------------------
# Basic Tests
# ------------------------------------------------------------------------------

test_configure_oot_defaults() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    $HR/configure -c
    verify_default_removed $BR $FUNCNAME
    verify_directory_is_empty $BR $FUNCNAME
    popd
}

test_configure_oot_defaults_custom_module_file() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS=`cat $EXT1/bin/vpid.modules`
    pushd $BR
    $HR/configure -m $MF
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS" $FUNCNAME
    $HR/configure -c
    verify_default_removed $BR $FUNCNAME
    verify_directory_is_empty $BR $FUNCNAME
    popd
}

test_configure_oot_defaults_custom_extension() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -e $EXT1
    verify_default_created $BR $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT1_NAME" $FUNCNAME
    $HR/configure -c
    verify_default_removed $BR $FUNCNAME
    verify_directory_is_empty $BR $FUNCNAME
    popd
}

test_configure_oot_defaults_custom_extensions() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -e $EXT1 -e $EXT2
    verify_default_created $BR $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT2_NAME" $FUNCNAME
    $HR/configure -c
    verify_default_removed $BR $FUNCNAME
    verify_directory_is_empty $BR $FUNCNAME
    popd
}

test_configure_oot_defaults_custom_module_file_and_extensions() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS=`cat $EXT1/bin/vpid.modules`
    pushd $BR
    $HR/configure -m $MF -e $EXT1 -e $EXT2
    verify_default_created $BR $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT2_NAME" $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS" $FUNCNAME
    $HR/configure -c
    verify_default_removed $BR $FUNCNAME
    verify_directory_is_empty $BR $FUNCNAME
    popd
}

test_configure_it_defaults() {
    print_test $FUNCNAME
    create_it_environment
    pushd $TR
    $HR/configure
    verify_default_created $TR $FUNCNAME
    verify_directory_is_empty $TR/extensions $FUNCNAME
    $HR/configure -c
    verify_default_removed $TR $FUNCNAME
    popd
}

test_configure_it_defaults_custom_module_file() {
    print_test $FUNCNAME
    create_it_environment
    local MF_CONTENTS=`cat $EXT1/bin/vpid.modules`
    pushd $TR
    $HR/configure -m $MF
    verify_default_created $TR $FUNCNAME
    verify_directory_is_empty $TR/extensions $FUNCNAME
    verify_file_contents "$TR/module_file" "$MF_CONTENTS" $FUNCNAME
    $HR/configure -c
    verify_default_removed $TR $FUNCNAME
    popd
}

test_configure_it_defaults_custom_extension() {
    print_test $FUNCNAME
    create_it_environment
    pushd $TR
    $HR/configure -e $EXT1
    verify_default_created $TR $FUNCNAME
    verify_link_exists "$TR/extensions/$EXT1_NAME" $FUNCNAME
    $HR/configure -c
    verify_default_removed $TR $FUNCNAME
    popd
}

test_configure_it_defaults_custom_extensions() {
    print_test $FUNCNAME
    create_it_environment
    pushd $TR
    $HR/configure -e $EXT1 -e $EXT2
    verify_default_created $TR $FUNCNAME
    verify_link_exists "$TR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$TR/extensions/$EXT2_NAME" $FUNCNAME
    $HR/configure -c
    verify_default_removed $TR $FUNCNAME
    popd
}

test_configure_it_defaults_custom_module_file_and_extensions() {
    print_test $FUNCNAME
    create_it_environment
    local MF_CONTENTS=`cat $EXT1/bin/vpid.modules`
    pushd $TR
    $HR/configure -m $MF -e $EXT1 -e $EXT2
    verify_default_created $TR $FUNCNAME
    verify_link_exists "$TR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$TR/extensions/$EXT2_NAME" $FUNCNAME
    verify_file_contents "$TR/module_file" "$MF_CONTENTS" $FUNCNAME
    $HR/configure -c
    verify_default_removed $TR $FUNCNAME
    popd
}

# ------------------------------------------------------------------------------
# Test Full Build
# ------------------------------------------------------------------------------

test_build_oot_hypervisor() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -m $MF -e $EXT1
    make -j2
    popd
}

test_build_it_hypervisor() {
    print_test $FUNCNAME
    create_it_environment
    pushd $TR
    $HR/configure -m $MF -e $EXT1
    make -j2
    popd
}

# ------------------------------------------------------------------------------
# Test Configure Updates
# ------------------------------------------------------------------------------

test_root_makefile_update_all() {
    print_test $FUNCNAME
    touch_file $HR/Makefile.bf
    pushd $BR
    $HR/configure -u
    popd
    verify_file_is_newer_than $BR/Makefile $HR/Makefile.bf $FUNCNAME
    verify_file_is_newer_than $BR/makefiles/Makefile $HR/Makefile.bf $FUNCNAME
}

test_root_makefile_update_scripts() {
    print_test $FUNCNAME
    touch_file $HR/Makefile.bf
    pushd $BR
    $HR/configure -s
    popd
    verify_file_is_older_than $BR/Makefile $HR/Makefile.bf $FUNCNAME
    verify_file_is_older_than $BR/makefiles/Makefile $HR/Makefile.bf $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_root_makefile_update_makefiles() {
    print_test $FUNCNAME
    touch_file $HR/Makefile.bf
    pushd $BR
    $HR/configure -r
    popd
    verify_file_is_newer_than $BR/Makefile $HR/Makefile.bf $FUNCNAME
    verify_file_is_newer_than $BR/makefiles/Makefile $HR/Makefile.bf $FUNCNAME
}

test_root_makefile_update_make() {
    print_test $FUNCNAME
    touch_file $HR/Makefile.bf
    pushd $BR
    make
    popd
    verify_file_is_newer_than $BR/Makefile $HR/Makefile.bf $FUNCNAME
    verify_file_is_newer_than $BR/makefiles/Makefile $HR/Makefile.bf $FUNCNAME
}

test_root_makefile_update_make_subdir() {
    print_test $FUNCNAME
    touch_file $HR/Makefile.bf
    pushd $BR/makefiles
    make
    popd
    verify_file_is_older_than $BR/Makefile $HR/Makefile.bf $FUNCNAME
    verify_file_is_newer_than $BR/makefiles/Makefile $HR/Makefile.bf $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_module_file_update_all() {
    print_test $FUNCNAME
    touch_file $MF
    pushd $BR
    $HR/configure -u
    popd
    verify_file_is_newer_than $BR/module_file $MF $FUNCNAME
}

test_module_file_update_scripts() {
    print_test $FUNCNAME
    touch_file $MF
    pushd $BR
    $HR/configure -s
    popd
    verify_file_is_newer_than $BR/module_file $MF $FUNCNAME
}

test_module_file_update_makefiles() {
    print_test $FUNCNAME
    touch_file $MF
    pushd $BR
    $HR/configure -r
    popd
    verify_file_is_older_than $BR/module_file $MF $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_module_file_update_make() {
    print_test $FUNCNAME
    touch_file $MF
    pushd $BR
    make
    popd
    verify_file_is_newer_than $BR/module_file $MF $FUNCNAME
}

test_module_file_update_make_subdir() {
    print_test $FUNCNAME
    touch_file $MF
    pushd $BR/makefiles
    make
    popd
    verify_file_is_older_than $BR/module_file $MF $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_extensions_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/extensions
    pushd $BR
    $HR/configure -u
    popd
    verify_directory_exists $BR/extensions $FUNCNAME
    verify_link_exists $BR/extensions/hypervisor_example_vpid $FUNCNAME
}

test_extensions_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/extensions
    pushd $BR
    $HR/configure -s
    popd
    verify_directory_exists $BR/extensions $FUNCNAME
    verify_link_exists $BR/extensions/hypervisor_example_vpid $FUNCNAME
}

test_extensions_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/extensions
    pushd $BR
    $HR/configure -r
    popd
    verify_directory_does_not_exist $BR/extensions $FUNCNAME
    verify_link_does_not_exist $BR/extensions/hypervisor_example_vpid $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_extensions_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/extensions
    pushd $BR
    make
    popd
    verify_directory_exists $BR/extensions $FUNCNAME
    verify_link_exists $BR/extensions/hypervisor_example_vpid $FUNCNAME
}

test_extensions_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/extensions
    pushd $BR/makefiles
    make
    popd
    verify_directory_does_not_exist $BR/extensions $FUNCNAME
    verify_link_does_not_exist $BR/extensions/hypervisor_example_vpid $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_build_version_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/build_version
    pushd $BR
    $HR/configure -u
    popd
    verify_file_exists $BR/build_version $FUNCNAME
}

test_build_version_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/build_version
    pushd $BR
    $HR/configure -s
    popd
    verify_file_exists $BR/build_version $FUNCNAME
}

test_build_version_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/build_version
    pushd $BR
    $HR/configure -r
    popd
    verify_file_does_not_exist $BR/build_version $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_build_version_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/build_version
    pushd $BR
    make
    popd
    verify_file_exists $BR/build_version $FUNCNAME
}

test_build_version_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/build_version
    pushd $BR/makefiles/bfcrt
    make
    popd
    verify_file_does_not_exist $BR/build_version $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_git_working_tree_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/git_working_tree.sh
    pushd $BR
    $HR/configure -u
    popd
    verify_file_exists $BR/git_working_tree.sh $FUNCNAME
}

test_git_working_tree_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/git_working_tree.sh
    pushd $BR
    $HR/configure -s
    popd
    verify_file_exists $BR/git_working_tree.sh $FUNCNAME
}

test_git_working_tree_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/git_working_tree.sh
    pushd $BR
    $HR/configure -r
    popd
    verify_file_does_not_exist $BR/git_working_tree.sh $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_git_working_tree_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/git_working_tree.sh
    pushd $BR
    make
    popd
    verify_file_exists $BR/git_working_tree.sh $FUNCNAME
}

test_git_working_tree_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/git_working_tree.sh
    pushd $BR/makefiles/bfcrt
    make
    popd
    verify_file_does_not_exist $BR/git_working_tree.sh $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_build_scripts_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/build_scripts
    pushd $BR
    $HR/configure -u
    popd
    verify_directory_exists $BR/build_scripts $FUNCNAME
    verify_file_exists $BR/build_scripts/compiler_wrapper.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_llvm.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ar $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang++ $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-nasm $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-docker $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ranlib $FUNCNAME
}

test_build_scripts_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/build_scripts
    pushd $BR
    $HR/configure -s
    popd
    verify_directory_exists $BR/build_scripts $FUNCNAME
    verify_file_exists $BR/build_scripts/compiler_wrapper.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_llvm.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ar $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang++ $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-nasm $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-docker $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ranlib $FUNCNAME
}

test_build_scripts_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/build_scripts
    pushd $BR
    $HR/configure -r
    popd
    verify_directory_does_not_exist $BR/build_scripts $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/compiler_wrapper.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libbfc.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libcxxabi.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libcxx.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_newlib.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libbfc.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libcxxabi.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libcxx.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_llvm.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_newlib.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-ar $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-clang $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-clang++ $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-nasm $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-docker $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-ranlib $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_build_scripts_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/build_scripts
    pushd $BR
    make
    popd
    verify_directory_exists $BR/build_scripts $FUNCNAME
    verify_file_exists $BR/build_scripts/compiler_wrapper.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/build_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libbfc.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxxabi.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_libcxx.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_llvm.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/fetch_newlib.sh $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ar $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-clang++ $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-nasm $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-docker $FUNCNAME
    verify_file_exists $BR/build_scripts/x86_64-bareflank-ranlib $FUNCNAME
}

test_build_scripts_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/build_scripts
    pushd $BR/makefiles/bfcrt
    make
    popd
    verify_directory_does_not_exist $BR/build_scripts $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/compiler_wrapper.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libbfc.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libcxxabi.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_libcxx.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/build_newlib.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libbfc.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libcxxabi.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_libcxx.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_llvm.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/fetch_newlib.sh $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-ar $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-clang $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-clang++ $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-nasm $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-docker $FUNCNAME
    verify_file_does_not_exist $BR/build_scripts/x86_64-bareflank-ranlib $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_makefile_update_all() {
    print_test $FUNCNAME
    touch_file $HR/bfcrt/src/Makefile.bf
    pushd $BR
    $HR/configure -u
    popd
    verify_file_is_newer_than $BR/makefiles/bfcrt/src/Makefile $HR/bfcrt/src/Makefile.bf $FUNCNAME
}

test_makefile_update_scripts() {
    print_test $FUNCNAME
    touch_file $HR/bfcrt/src/Makefile.bf
    pushd $BR
    $HR/configure -s
    popd
    verify_file_is_older_than $BR/makefiles/bfcrt/src/Makefile $HR/bfcrt/src/Makefile.bf $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_makefile_update_makefiles() {
    print_test $FUNCNAME
    touch_file $HR/bfcrt/src/Makefile.bf
    pushd $BR
    $HR/configure -r
    popd
    verify_file_is_older_than $BR/makefiles/bfcrt/src/Makefile $HR/bfcrt/src/Makefile.bf $FUNCNAME
    pushd $BR
    $HR/configure -u
    popd
}

test_makefile_update_make() {
    print_test $FUNCNAME
    touch_file $HR/bfcrt/src/Makefile.bf
    pushd $BR
    make
    popd
    verify_file_is_newer_than $BR/makefiles/bfcrt/src/Makefile $HR/bfcrt/src/Makefile.bf $FUNCNAME
}

test_makefile_update_make_subdir() {
    print_test $FUNCNAME
    touch_file $HR/bfcrt/src/Makefile.bf
    pushd $BR/makefiles/bfcrt/src/
    make
    popd
    verify_file_is_newer_than $BR/makefiles/bfcrt/src/Makefile $HR/bfcrt/src/Makefile.bf $FUNCNAME
}

test_remove_makefiles_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles
    pushd $BR
    $HR/configure -u
    popd
    verify_directory_exists $BR/makefiles $FUNCNAME
    verify_file_exists $BR/makefiles/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
}

test_remove_makefiles_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles
    pushd $BR
    $HR/configure -s
    popd
    verify_directory_does_not_exist $BR/makefiles $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_makefiles_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles
    pushd $BR
    $HR/configure -r || true
    popd
    verify_directory_does_not_exist $BR/makefiles $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_directory_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt
    pushd $BR
    $HR/configure -u
    popd
    verify_directory_exists $BR/makefiles/bfcrt $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/src $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/test $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/src/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/test/Makefile $FUNCNAME
}

test_remove_directory_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt
    pushd $BR
    $HR/configure -s
    popd
    verify_directory_does_not_exist $BR/makefiles/bfcrt $FUNCNAME
    verify_directory_does_not_exist $BR/makefiles/bfcrt/src $FUNCNAME
    verify_directory_does_not_exist $BR/makefiles/bfcrt/test $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/src/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/test/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_directory_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt
    pushd $BR
    $HR/configure -r
    popd
    verify_directory_does_not_exist $BR/makefiles/bfcrt $FUNCNAME
    verify_directory_does_not_exist $BR/makefiles/bfcrt/src $FUNCNAME
    verify_directory_does_not_exist $BR/makefiles/bfcrt/test $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/src/Makefile $FUNCNAME
    verify_file_does_not_exist $BR/makefiles/bfcrt/test/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_directory_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt
    pushd $BR
    make
    popd
    verify_directory_exists $BR/makefiles/bfcrt $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/src $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/test $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/src/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/test/Makefile $FUNCNAME
}

test_remove_directory_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt
    pushd $BR/makefiles
    make
    popd
    verify_directory_exists $BR/makefiles/bfcrt $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/src $FUNCNAME
    verify_directory_exists $BR/makefiles/bfcrt/test $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/src/Makefile $FUNCNAME
    verify_file_exists $BR/makefiles/bfcrt/test/Makefile $FUNCNAME
}

test_remove_makefile_update_all() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt/Makefile
    pushd $BR
    $HR/configure -u
    popd
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
}

test_remove_makefile_update_scripts() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt/Makefile
    pushd $BR
    $HR/configure -s
    popd
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_makefile_update_makefiles() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt/Makefile
    pushd $BR
    $HR/configure -r
    popd
    verify_file_does_not_exist $BR/makefiles/bfcrt/Makefile $FUNCNAME
    pushd $BR
    $HR/configure -u
    make
    popd
}

test_remove_makefile_update_make() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt/Makefile
    pushd $BR
    make
    popd
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
}

test_remove_makefile_update_make_subdir() {
    print_test $FUNCNAME
    rm -Rf $BR/makefiles/bfcrt/Makefile
    pushd $BR/makefiles
    make
    popd
    verify_file_exists $BR/makefiles/bfcrt/Makefile $FUNCNAME
}

test_remove_env_script_update_all() {
    print_test $FUNCNAME
    mv $BR/env.sh $BR/backup_env.sh
    pushd $BR
    $HR/configure -u || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv $BR/backup_env.sh $BR/env.sh
}

test_remove_env_script_update_scripts() {
    print_test $FUNCNAME
    mv $BR/env.sh $BR/backup_env.sh
    pushd $BR
    $HR/configure -s || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv $BR/backup_env.sh $BR/env.sh
}

test_remove_env_script_update_makefiles() {
    print_test $FUNCNAME
    mv $BR/env.sh $BR/backup_env.sh
    pushd $BR
    $HR/configure -r || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv $BR/backup_env.sh $BR/env.sh
}

test_remove_env_script_update_make() {
    print_test $FUNCNAME
    mv $BR/env.sh $BR/backup_env.sh
    pushd $BR
    make || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv $BR/backup_env.sh $BR/env.sh
}

test_remove_env_script_update_make_subdir() {
    print_test $FUNCNAME
    mv $BR/env.sh $BR/backup_env.sh
    pushd $BR/makefiles
    make
    popd
    mv $BR/backup_env.sh $BR/env.sh
}

# ------------------------------------------------------------------------------
# Move Build Dir
# ------------------------------------------------------------------------------

test_move_build_dir_update_all() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc
    $HR/configure -u || exit_status=$?
    popd
    verify_exit_status $exit_status 3 $FUNCNAME
    mv /tmp/new_loc $BR
}

test_move_build_dir_update_scripts() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc
    $HR/configure -s || exit_status=$?
    popd
    verify_exit_status $exit_status 3 $FUNCNAME
    mv /tmp/new_loc $BR
}

test_move_build_dir_update_makefiles() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc
    $HR/configure -r || exit_status=$?
    popd
    verify_exit_status $exit_status 3 $FUNCNAME
    mv /tmp/new_loc $BR
}

test_move_build_dir_update_make() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc
    make || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv /tmp/new_loc $BR
}

test_move_build_dir_update_make_subdir() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc/makefiles
    make || exit_status=$?
    popd
    verify_exit_status $exit_status 2 $FUNCNAME
    mv /tmp/new_loc $BR
}

test_move_build_dir_clean() {
    print_test $FUNCNAME
    mv $BR /tmp/new_loc
    pushd /tmp/new_loc
    $HR/configure -c || exit_status=$?
    popd
    verify_exit_status $exit_status 3 $FUNCNAME
    mv /tmp/new_loc $BR
}

# ------------------------------------------------------------------------------
# Reconfigure
# ------------------------------------------------------------------------------

test_reconfigure_extensions_to_no_extensions() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure -m $MF -e $EXT1 -e $EXT2
    verify_default_created $BR $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT2_NAME" $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS1" $FUNCNAME
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    popd
}

test_reconfigure_no_extensions_to_extensions() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    $HR/configure -m $MF -e $EXT1 -e $EXT2
    verify_default_created $BR $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT1_NAME" $FUNCNAME
    verify_link_exists "$BR/extensions/$EXT2_NAME" $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS1" $FUNCNAME
    popd
}

# ------------------------------------------------------------------------------
# Version Change
# ------------------------------------------------------------------------------

test_version_change_in_root_update_all() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    echo "0" > $BR/build_version
    $HR/configure -u
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

test_version_change_in_root_update_scripts() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    echo "0" > $BR/build_version
    $HR/configure -s
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

test_version_change_in_root_update_makefiles() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    echo "0" > $BR/build_version
    $HR/configure -r
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

test_version_change_in_root_update_make() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    make
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    echo "0" > $BR/build_version
    make || exit_status=$?
    verify_exit_status $exit_status 2 $FUNCNAME
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

test_version_change_in_root_update_make_subdir() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    make
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    touch_file $HR/bfcrt/Makefile.bf
    echo "0" > $BR/build_version
    cd $BR/makefiles/bfcrt
    make || exit_status=$?
    verify_exit_status $exit_status 2 $FUNCNAME
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

test_version_change_in_root_update_all_down_version() {
    print_test $FUNCNAME
    create_oot_environment
    local MF_CONTENTS1=`cat $EXT1/bin/vpid.modules`
    local MF_CONTENTS2=`cat $HR/bfm/bin/native/vmm.modules`
    pushd $BR
    $HR/configure
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    touch_file $BR/timestamp
    echo "10000" > $BR/build_version
    $HR/configure -u --this-is-make  || exit_status=$?
    verify_exit_status $exit_status 5 $FUNCNAME
    verify_default_created $BR $FUNCNAME
    verify_directory_is_empty $BR/extensions $FUNCNAME
    verify_file_contents "$BR/module_file" "$MF_CONTENTS2" $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/Makefile $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_version $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/env.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/git_working_tree.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/module_file $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/compiler_wrapper.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/build_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libbfc.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxxabi.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_libcxx.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_llvm.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/fetch_newlib.sh $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ar $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-clang++ $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-nasm $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-docker $BR/timestamp $FUNCNAME
    verify_file_is_newer_than $BR/build_scripts/x86_64-bareflank-ranlib $BR/timestamp $FUNCNAME
    popd
}

# ------------------------------------------------------------------------------
# Build Extension
# ------------------------------------------------------------------------------

test_extenions() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -m $MF -e $EXT1 -e $EXT2
    make
    verify_file_exists $BR/makefiles/hypervisor_example_vpid/vcpu_factory_vpid/bin/cross/libvcpu_factory_vpid.so $FUNCNAME
    verify_file_exists $BR/makefiles/hypervisor_example_cpuidcount/vcpu_factory_cpuidcount/bin/cross/libvcpu_factory_cpuidcount.so $FUNCNAME
    popd
}

# ------------------------------------------------------------------------------
# Invalid Args
# ------------------------------------------------------------------------------

test_invalid_module_file() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -m /tmp/missing_module_file.modules || exit_status=$?
    verify_exit_status $exit_status 1 $FUNCNAME
    popd
}

test_invalid_extension() {
    print_test $FUNCNAME
    create_oot_environment
    pushd $BR
    $HR/configure -e /tmp/missing_extension || exit_status=$?
    verify_exit_status $exit_status 1 $FUNCNAME
    popd
}

# ------------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------------

HR=`pwd`
BR="/tmp/build"
TR="/tmp/hypervisor"
MF="/tmp/hypervisor_example_vpid/bin/vpid.modules"

EXT1_NAME="hypervisor_example_vpid"
EXT2_NAME="hypervisor_example_cpuidcount"

EXT1="/tmp/$EXT1_NAME"
EXT2="/tmp/$EXT2_NAME"

if [[ ! -f configure ]]; then
    echo "ERROR: The test_configure script must be run from the hypervisor's root folder"
    exit 1
fi

rm -Rf $EXT1
rm -Rf $EXT2

git clone -b new_build_system http://github.com/rianquinn/$EXT1_NAME.git $EXT1
git clone -b new_build_system http://github.com/rianquinn/$EXT2_NAME.git $EXT2

# ------------------------------------------------------------------------------
# Run Tests
# ------------------------------------------------------------------------------

test_configure_oot_defaults
test_configure_oot_defaults_custom_module_file
test_configure_oot_defaults_custom_extension
test_configure_oot_defaults_custom_extensions
test_configure_oot_defaults_custom_module_file_and_extensions

test_configure_it_defaults
test_configure_it_defaults_custom_module_file
test_configure_it_defaults_custom_extension
test_configure_it_defaults_custom_extensions
test_configure_it_defaults_custom_module_file_and_extensions

test_build_oot_hypervisor
test_root_makefile_update_all
test_root_makefile_update_scripts
test_root_makefile_update_makefiles
test_root_makefile_update_make
test_root_makefile_update_make_subdir
test_module_file_update_all
test_module_file_update_scripts
test_module_file_update_makefiles
test_module_file_update_make
test_module_file_update_make_subdir
test_extensions_update_all
test_extensions_update_scripts
test_extensions_update_makefiles
test_extensions_update_make
test_extensions_update_make_subdir
test_build_version_update_all
test_build_version_update_scripts
test_build_version_update_makefiles
test_build_version_update_make
test_build_version_update_make_subdir
test_git_working_tree_update_all
test_git_working_tree_update_scripts
test_git_working_tree_update_makefiles
test_git_working_tree_update_make
test_git_working_tree_update_make_subdir
test_build_scripts_update_all
test_build_scripts_update_scripts
test_build_scripts_update_makefiles
test_build_scripts_update_make
test_build_scripts_update_make_subdir
test_makefile_update_all
test_makefile_update_scripts
test_makefile_update_makefiles
test_makefile_update_make
test_makefile_update_make_subdir
test_remove_makefiles_update_all
test_remove_makefiles_update_scripts
test_remove_makefiles_update_makefiles
test_remove_directory_update_all
test_remove_directory_update_scripts
test_remove_directory_update_makefiles
test_remove_directory_update_make
test_remove_directory_update_make_subdir
test_remove_makefile_update_all
test_remove_makefile_update_scripts
test_remove_makefile_update_makefiles
test_remove_makefile_update_make
test_remove_makefile_update_make_subdir
test_remove_env_script_update_all
test_remove_env_script_update_scripts
test_remove_env_script_update_makefiles
test_remove_env_script_update_make
test_remove_env_script_update_make_subdir

test_move_build_dir_update_all
test_move_build_dir_update_scripts
test_move_build_dir_update_makefiles
test_move_build_dir_update_make
test_move_build_dir_update_make_subdir
test_move_build_dir_clean

test_reconfigure_extensions_to_no_extensions
test_reconfigure_no_extensions_to_extensions

test_version_change_in_root_update_all
test_version_change_in_root_update_scripts
test_version_change_in_root_update_makefiles
test_version_change_in_root_update_make
test_version_change_in_root_update_make_subdir
test_version_change_in_root_update_all_down_version

test_extenions

test_invalid_module_file
test_invalid_extension

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------

rm -Rf $BR
rm -Rf $TR
rm -Rf $EXT1
rm -Rf $EXT2
rm -Rf /tmp/new_loc
