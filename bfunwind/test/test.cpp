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

#include <sys/types.h>
#include <unistd.h>

#include <link.h>
#include <string>
#include <fstream>
#include <streambuf>

// -----------------------------------------------------------------------------
// A.out Load Address
// -----------------------------------------------------------------------------

// The following code is needed to locate the load address of this application.
// If PIE is being used, the application will be relocated somewhere in memory
// and we need to use this relocation to identify were the eh_frame section
// is actually located

uintptr_t g_offs = 0;
uintptr_t g_size = 0;

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
            g_offs = info->dlpi_addr;
            break;
        }
    }

    return 0;
}
// -----------------------------------------------------------------------------
// Exception Handler Framework
// -----------------------------------------------------------------------------

eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {{nullptr, 0}};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{
    g_eh_frame_list[0].addr = reinterpret_cast<void *>(g_offs);
    g_eh_frame_list[0].size = g_size;

    return static_cast<struct eh_frame_t *>(g_eh_frame_list);
}

// -----------------------------------------------------------------------------
// Test Implementation
// -----------------------------------------------------------------------------

extern void *__eh_frame_start;
extern void *__eh_frame_end;

bfunwind_ut::bfunwind_ut()
{
    dl_iterate_phdr(callback, nullptr);

    std::stringstream eh_frame_offs_ss;
    std::stringstream eh_frame_size_ss;

    eh_frame_offs_ss << "readelf -SW /proc/" << getpid() << "/exe | grep \".eh_frame\" | grep -v \".eh_frame_hdr\" | awk '{print $4}' > offs.txt";
    eh_frame_size_ss << "readelf -SW /proc/" << getpid() << "/exe | grep \".eh_frame\" | grep -v \".eh_frame_hdr\" | awk '{print $6}' > size.txt";

    system(eh_frame_offs_ss.str().c_str());
    system(eh_frame_size_ss.str().c_str());

    auto &&offs_file = std::ifstream("offs.txt");
    auto &&size_file = std::ifstream("size.txt");

    auto &&offs_str = std::string((std::istreambuf_iterator<char>(offs_file)), std::istreambuf_iterator<char>());
    auto &&size_str = std::string((std::istreambuf_iterator<char>(size_file)), std::istreambuf_iterator<char>());

    std::remove("offs.txt");
    std::remove("size.txt");

    std::cout << view_as_pointer(std::stoull(offs_str, nullptr, 16)) << '\n';
    std::cout << view_as_pointer(std::stoull(size_str, nullptr, 16)) << '\n';

    g_offs += std::stoull(offs_str, nullptr, 16);
    g_size += std::stoull(size_str, nullptr, 16);
}

bool bfunwind_ut::init()
{
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
