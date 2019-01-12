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

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#define NEED_GSL_LITE
#define NEED_STD_LITE

#ifdef ENABLE_BUILD_TEST
#define MAIN mock_main
#else
#define MAIN main
#endif

#ifdef ENABLE_BUILD_TEST
#define GSL_ABORT mock_abort
extern "C" void mock_abort() noexcept(false);
#endif

#include <bfgsl.h>
#include <bfexports.h>
#include <bfsupport.h>
#include <bfconstants.h>
#include <bfehframelist.h>
#include <bfdwarf.h>
#include <cstring>

using init_t = void (*)();
using fini_t = void (*)();

extern "C" int WEAK_SYM
MAIN(int argc, const char *argv[])
{
    bfignored(argc);
    bfignored(argv);

    return -1;
}

extern "C" int64_t WEAK_SYM
bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    bfignored(request);
    bfignored(arg1);
    bfignored(arg2);
    bfignored(arg3);

    return -1;
}

extern int __g_eh_frame_list_num;
extern eh_frame_t __g_eh_frame_list[MAX_NUM_MODULES];
extern int __g_dwarf_sections_num;
extern dwarf_sections_t __g_dwarf_sections[MAX_NUM_MODULES];

extern "C" void
__bareflank_init(const section_info_t *info)
{
    if (info->init_addr != nullptr) {
        reinterpret_cast<init_t>(info->init_addr)();
    }

    if (info->init_array_addr != nullptr) {
        auto n = info->init_array_size >> 3;
        auto init_array = static_cast<init_t *>(info->init_array_addr);

        for (auto i = 0U; i < n && gsl::at(init_array, n, i) != nullptr; i++) {
            gsl::at(init_array, n, i)();
        }
    }
}

extern "C" void
__bareflank_fini(const section_info_t *info)
{
    if (info->fini_array_addr != nullptr) {
        auto n = info->fini_array_size >> 3;
        auto fini_array = static_cast<fini_t *>(info->fini_array_addr);

        for (auto i = 0U; i < n && gsl::at(fini_array, n, i) != nullptr; i++) {
            gsl::at(fini_array, n, i)();
        }
    }

    if (info->fini_addr != nullptr) {
        reinterpret_cast<fini_t>(info->fini_addr)();
    }
}

extern "C" void
__bareflank_register_eh_frame(const section_info_t *info)
{
    auto elem = &gsl::at(__g_eh_frame_list, __g_eh_frame_list_num++);
    elem->addr = info->eh_frame_addr;
    elem->size = info->eh_frame_size;
}

extern "C" void
__bareflank_register_debug_info(const section_info_t *info)
{
    auto elem = &gsl::at(__g_dwarf_sections, __g_dwarf_sections_num++);
    elem->debug_info_addr = info->debug_info_addr;
    elem->debug_info_size = info->debug_info_size;
    elem->debug_abbrev_addr = info->debug_abbrev_addr;
    elem->debug_abbrev_size = info->debug_abbrev_size;
    elem->debug_line_addr = info->debug_line_addr;
    elem->debug_line_size = info->debug_line_size;
    elem->debug_str_addr = info->debug_str_addr;
    elem->debug_str_size = info->debug_str_size;
    elem->debug_ranges_addr = info->debug_ranges_addr;
    elem->debug_ranges_size = info->debug_ranges_size;
}

extern "C" int64_t
_start_c(const crt_info_t *info) noexcept
{
    int64_t ret;

    if (info == nullptr) {
        return -1;
    }

    // TODO:
    //
    // - Need to set the program break here.
    // - Need to put into the info struct whether to run exit(ret) or to
    //   actually return
    //

    if (info->arg_type == 0 || info->request == BF_REQUEST_INIT) {
        for (auto i = 0; i < info->info_num; i++) {
            auto sinfo = &gsl::at(info->info, i);

            __bareflank_init(sinfo);
            __bareflank_register_eh_frame(sinfo);
            __bareflank_register_debug_info(sinfo);
        }
    }

    if (info->arg_type == 0) {
        ret = MAIN(info->argc, info->argv);
    }
    else {
        ret = bfmain(info->request, info->arg1, info->arg2, info->arg3);
    }

    if (info->arg_type == 0 || info->request == BF_REQUEST_FINI) {
        for (auto i = 0; i < info->info_num; i++) {
            __bareflank_fini(&gsl::at(info->info, i));
        }
    }

    return ret;
}
