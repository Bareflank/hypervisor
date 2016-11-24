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

#include <test.h>
#include <constants.h>
#include <eh_frame_list.h>
#include <view_as_pointer.h>

#include <link.h>
#include <fstream>
#include <sys/mman.h>

// -----------------------------------------------------------------------------
// A.out Load Address
// -----------------------------------------------------------------------------

// The following code is needed to locate the load address of this application.
// If PIE is being used, the application will be relocated somewhere in memory
// and we need to use this relocation to identify were the eh_frame section
// is actually located

uintptr_t g_a_out_offset = 0;

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void) size;
    (void) data;
    static auto once = false;

    if (once) return 0;
    once = true;

    for (int i = 0; i < info->dlpi_phnum; i++)
    {
        if (info->dlpi_phdr[i].p_type == PT_LOAD)
        {
            g_a_out_offset = info->dlpi_addr;
            break;
        }
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Exception Handler Framework
// -----------------------------------------------------------------------------

section_info_t g_info;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {{nullptr, 0}};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{
    g_eh_frame_list[0].addr = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(g_info.eh_frame_addr) + g_a_out_offset);
    g_eh_frame_list[0].size = g_info.eh_frame_size;

    return static_cast<struct eh_frame_t *>(g_eh_frame_list);
}

// -----------------------------------------------------------------------------
// Test Implementation
// -----------------------------------------------------------------------------

const auto c_self_filename = "/proc/self/exe";

bfunwind_ut::bfunwind_ut() :
    m_self_length(0)
{
}

bool bfunwind_ut::init()
{
    dl_iterate_phdr(callback, nullptr);

    std::ifstream self_ifs(c_self_filename, std::ifstream::ate);
    m_self_length = static_cast<uint64_t>(self_ifs.tellg());
    m_self = std::make_unique<char[]>(m_self_length);
    self_ifs.seekg(0);
    self_ifs.read(m_self.get(), static_cast<int64_t>(m_self_length));

    auto ret = 0LL;
    bfelf_file_t self_ef;

    ret = bfelf_file_init(m_self.get(), static_cast<uint64_t>(m_self_length), &self_ef);
    this->expect_true(ret == BFELF_SUCCESS);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    loader.relocated = 1;

    ret = bfelf_loader_get_info(&loader, &self_ef, &g_info);
    this->expect_true(ret == BFELF_SUCCESS);

    return true;
}

bool bfunwind_ut::fini()
{
    return true;
}

bool bfunwind_ut::list()
{
    this->test_catch_all();
    this->test_catch_bool();
    this->test_catch_int();
    this->test_catch_cstr();
    this->test_catch_string();
    this->test_catch_exception();
    this->test_catch_custom_exception();
    this->test_catch_multiple_catches_per_function();
    this->test_catch_raii();
    this->test_catch_throw_from_stream();
    this->test_catch_nested_throw_in_catch();
    this->test_catch_nested_throw_outside_catch();
    this->test_catch_nested_throw_uncaught();
    this->test_catch_nested_throw_rethrow();
    this->test_catch_throw_with_lots_of_register_mods();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfunwind_ut);
}
