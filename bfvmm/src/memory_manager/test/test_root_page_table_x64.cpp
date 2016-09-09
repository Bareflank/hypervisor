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
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

extern bool g_terminate_called;

static auto
setup_mm(MockRepository &mocks)
{
    auto descriptor_list =
    {
        memory_descriptor{0x12345000, 0x54321000, MEMORY_TYPE_R | MEMORY_TYPE_W},
        memory_descriptor{0x12346000, 0x54322000, MEMORY_TYPE_R | MEMORY_TYPE_E},
        memory_descriptor{0xDEADBEEF, 0xDEADBEEF, MEMORY_TYPE_R | MEMORY_TYPE_E}
    };

    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    mocks.OnCall(mm, memory_manager_x64::descriptors).Return(descriptor_list);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);
    mocks.OnCall(mm, memory_manager_x64::add_md);
    mocks.OnCall(mm, memory_manager_x64::remove_md);

    return mm;
}

void
memory_manager_ut::test_root_page_table_x64_init_failure()
{
    MockRepository mocks;
    auto &&mm = setup_mm(mocks);

    mocks.OnCall(mm, memory_manager_x64::add_md).With(0xDEADBEEF, _, _).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { root_page_table_x64::instance(); });
        this->expect_true(g_terminate_called);
    });
}

void
memory_manager_ut::test_root_page_table_x64_init_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { root_page_table_x64::instance(); });
    });
}

void
memory_manager_ut::test_root_page_table_x64_phys_addr()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(g_pt->phys_addr() == 0x0000000ABCDEF0000);
    });
}

void
memory_manager_ut::test_root_page_table_x64_map_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { g_pt->map(0, 0x54323000, MEMORY_TYPE_R | MEMORY_TYPE_W); }, ""_ut_ffe);
        this->expect_exception([&] { g_pt->map(0x12347000, 0, MEMORY_TYPE_R | MEMORY_TYPE_W); }, ""_ut_ffe);
        this->expect_exception([&] { g_pt->map(0x12347000, 0x54323000, 0); }, ""_ut_ffe);
        this->expect_exception([&] { g_pt->map(0x12347000, 0x54323000, MEMORY_TYPE_R); }, ""_ut_lee);
    });
}

void
memory_manager_ut::test_root_page_table_x64_map_add_md_failure()
{
    MockRepository mocks;
    auto &&mm = setup_mm(mocks);

    mocks.OnCall(mm, memory_manager_x64::add_md).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { g_pt->map(0x12347000, 0x54323000, MEMORY_TYPE_R | MEMORY_TYPE_W); }, ""_ut_ree);
    });
}

void
memory_manager_ut::test_root_page_table_x64_map_unmap_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_pt->map(0x12347000, 0x54323000, MEMORY_TYPE_R | MEMORY_TYPE_W); });
        this->expect_no_exception([&] { g_pt->unmap(0x12347000); });
    });
}

void
memory_manager_ut::test_root_page_table_x64_map_unmap_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { g_pt->map(0x12347000, 0x54323000, MEMORY_TYPE_R | MEMORY_TYPE_W); });
        this->expect_no_exception([&] { g_pt->unmap(0x12347000); });
        this->expect_no_exception([&] { g_pt->unmap(0x12347000); });
    });
}
