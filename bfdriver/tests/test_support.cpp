//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

// TIDY_EXCLUSION=-cert-err58-cpp
//
// Reason:
//     The operator+ may throw an exception, and since these vectors
//     have static storage, tidy raises this error. This is unlikely to happen,
//     and if it does, it will only happen in the bfdriver unittests
//

#include <vector>
#include <string>

#include <bffile.h>
#include <bfelf_loader.h>

file g_file;

std::vector<std::string> g_filenames_success = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_shared"_s,
};

std::vector<std::string> g_filenames_init_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_init_fails_shared"_s,
};

std::vector<std::string> g_filenames_fini_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_fini_fails_shared"_s,
};

std::vector<std::string> g_filenames_add_mdl_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_add_mdl_fails_shared"_s,
};

std::vector<std::string> g_filenames_get_drr_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_get_drr_fails_shared"_s,
};

std::vector<std::string> g_filenames_set_rsdp_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_set_rsdp_fails_shared"_s,
};

std::vector<std::string> g_filenames_vmm_init_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_vmm_init_fails_shared"_s,
};

std::vector<std::string> g_filenames_vmm_fini_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libc.so"_s,
    VMM_PREFIX_PATH + "/lib/libc++.so.1.0"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall_shared.so"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind_shared.so"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_vmm_fini_fails_shared"_s,
};
