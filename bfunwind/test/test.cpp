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
#include <commit_or_rollback.h>

#include <fstream>
#include <sys/mman.h>

// -----------------------------------------------------------------------------
// Exception Handler Framework
// -----------------------------------------------------------------------------

section_info_t g_info;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {{0, 0}};

extern "C" struct eh_frame_t *
get_eh_frame_list()
{
    g_eh_frame_list[0].addr = g_info.eh_frame_addr;
    g_eh_frame_list[0].size = g_info.eh_frame_size;

    return g_eh_frame_list;
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
    std::ifstream self_ifs(c_self_filename, std::ifstream::ate);

    auto cor1 = commit_or_rollback([&]
    {
        self_ifs.close();
    });

    if (self_ifs.is_open() == false)
    {
        std::cout << "unable to open one or more dummy libraries: " << std::endl;
        std::cout << "    - self: " << self_ifs.is_open() << std::endl;
        return false;
    }

    m_self_length = self_ifs.tellg();

    if (m_self_length == 0)
    {
        std::cout << "one or more of the dummy libraries is empty: " << std::endl;
        std::cout << "    - self: " << m_self_length << std::endl;
        return false;
    }

    m_self = std::shared_ptr<char>(new char[m_self_length]());

    auto cor2 = commit_or_rollback([&]
    {
        m_self.reset();
    });

    if (!m_self)
    {
        std::cout << "unable to allocate space for one or more of the dummy libraries: " << std::endl;
        std::cout << "    - self: " << (void *)m_self.get() << std::endl;
        return false;
    }

    self_ifs.seekg(0);
    self_ifs.read(m_self.get(), m_self_length);

    if (self_ifs.fail() == true)
    {
        std::cout << "unable to load one or more dummy libraries into memory: " << std::endl;
        std::cout << "    - self: " << self_ifs.fail() << std::endl;
        return false;
    }

    cor1.commit();
    cor2.commit();

    auto ret = 0;
    bfelf_file_t self_ef;

    ret = bfelf_file_init(m_self.get(), m_self_length, &self_ef);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

    bfelf_loader_t loader;
    memset(&loader, 0, sizeof(loader));

    loader.relocated = 1;
    loader.ignore_crt = 1;

    ret = bfelf_loader_get_info(&loader, &self_ef, &g_info);
    ASSERT_TRUE(ret == BFELF_SUCCESS);

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
