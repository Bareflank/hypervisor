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

#define NEED_GSL_LITE

#include <bfgsl.h>
#include <bfexports.h>
#include <bfsupport.h>
#include <bfconstants.h>
#include <bfehframelist.h>
#include <bfdwarf.h>

typedef void (*init_t)();
typedef void (*fini_t)();

int __attribute__((weak))
main(int argc, const char *argv[])
{
    bfignored(argc);
    bfignored(argv);

    return -1;
}

extern "C" int64_t __attribute__((weak))
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

EXPORT_SYM void *__dso_handle = 0;

extern "C" void
__bareflank_init(const section_info_t *info) noexcept
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
__bareflank_fini(const section_info_t *info) noexcept
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
__bareflank_register_eh_frame(const section_info_t *info) noexcept
{
    auto elem = &gsl::at(__g_eh_frame_list, __g_eh_frame_list_num++);

    elem->addr = info->eh_frame_addr;
    elem->size = info->eh_frame_size;
}

extern "C" void
__bareflank_register_debug_info(const section_info_t *info) noexcept
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
        ret = main(info->argc, info->argv);
    }
    else {
        ret = bfmain(info->request, info->arg1, info->arg2, info->arg3);
    }

    if (info->arg_type == 0 || info->request == BF_REQUEST_FINI) {
        for (auto i = 0; i < info->info_num; i++) {
            auto sinfo = &gsl::at(info->info, i);

            __bareflank_fini(sinfo);
        }
    }

    return ret;
}
