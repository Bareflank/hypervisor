//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main"_s,
};

std::vector<std::string> g_filenames_init_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_init_fails"_s,
};

std::vector<std::string> g_filenames_fini_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_fini_fails"_s,
};

std::vector<std::string> g_filenames_add_mdl_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_add_mdl_fails"_s,
};

std::vector<std::string> g_filenames_get_drr_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_get_drr_fails"_s,
};

std::vector<std::string> g_filenames_set_rsdp_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_set_rsdp_fails"_s,
};

std::vector<std::string> g_filenames_vmm_init_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_vmm_init_fails"_s,
};

std::vector<std::string> g_filenames_vmm_fini_fails = {
    VMM_PREFIX_PATH + "/lib/libdummy_lib1.a"_s,
    VMM_PREFIX_PATH + "/lib/libdummy_lib2.a"_s,
    VMM_PREFIX_PATH + "/lib/libc.a"_s,
    VMM_PREFIX_PATH + "/lib/libc++abi.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfpthread.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfsyscall.a"_s,
    VMM_PREFIX_PATH + "/lib/libbfunwind.a"_s,
    VMM_PREFIX_PATH + "/bin/dummy_main_vmm_fini_fails"_s,
};
