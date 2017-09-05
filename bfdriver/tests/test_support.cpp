//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <vector>
#include <string>

#include <bffile.h>
#include <bfelf_loader.h>

file g_file;

std::vector<std::string> g_filenames_success = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main"_s,
};

std::vector<std::string> g_filenames_init_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_init_fails"_s,
};

std::vector<std::string> g_filenames_fini_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_fini_fails"_s,
};

std::vector<std::string> g_filenames_add_mdl_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_add_mdl_fails"_s,
};

std::vector<std::string> g_filenames_get_drr_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_get_drr_fails"_s,
};

std::vector<std::string> g_filenames_vmm_init_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_vmm_init_fails"_s,
};

std::vector<std::string> g_filenames_vmm_fini_fails = {
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib1.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libdummy_lib2.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++.so.1.0"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libc++abi.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libpthread.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfsyscall.so"_s,
    BAREFLANK_SYSROOT_PATH + "/lib/libbfunwind.so"_s,
    BAREFLANK_SYSROOT_PATH + "/bin/dummy_main_vmm_fini_fails"_s,
};
