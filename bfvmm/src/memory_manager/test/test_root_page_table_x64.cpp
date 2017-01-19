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
#include <memory_manager/pat_x64.h>
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
    };

    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    mocks.OnCall(mm, memory_manager_x64::descriptors).Return(descriptor_list);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);
    mocks.OnCall(mm, memory_manager_x64::virtint_to_physint).Return(0x0000000ABCDEF0000);
    mocks.OnCall(mm, memory_manager_x64::add_md);
    mocks.OnCall(mm, memory_manager_x64::remove_md);

    return mm;
}

void
memory_manager_ut::test_root_page_table_x64_init_failure()
{
    MockRepository mocks;
    auto &&mm = setup_mm(mocks);

    mocks.OnCall(mm, memory_manager_x64::add_md).With(0x54321000, _, _).Throw(std::runtime_error("error"));

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { root_pt(); });
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
        this->expect_no_exception([&] { root_pt(); });
    });
}

void
memory_manager_ut::test_root_page_table_x64_cr3()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_true(root_cr3.cr3() == 0x0000000ABCDEF001B);
}

void
memory_manager_ut::test_root_page_table_x64_map_1g()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    // Read / Write
    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::re_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_1g(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }
}

void
memory_manager_ut::test_root_page_table_x64_map_2m()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    // Read / Write
    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::re_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_2m(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_large() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }
}

void
memory_manager_ut::test_root_page_table_x64_map_4k()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    // Read / Write
    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::rw_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_true(entry.nx());
        this->expect_true(entry.pat_index_4k() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::re_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_false(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 0);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wc);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 1);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wt);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 2);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wp);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 5);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wb);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 3);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_uc_m);
        auto &&entry = root_cr3.virt_to_pte(0x1000UL);
        this->expect_true(entry.rw());
        this->expect_false(entry.nx());
        this->expect_true(entry.pat_index_4k() == 7);
        root_cr3.unmap(0x1000UL);
        this->expect_exception([&] { root_cr3.virt_to_pte(0x1000UL); }, ""_ut_ree);
    }
}

void
memory_manager_ut::test_root_page_table_x64_map_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_exception([&] { root_cr3.map_page(0x0, 0x0, 0x0, 0x0); }, ""_ut_lee);
    this->expect_exception([&] { root_cr3.map_page(0x0, 0x0, 0x0, x64::page_table::pt::size_bytes); }, ""_ut_lee);
}

void
memory_manager_ut::test_root_page_table_x64_map_unmap_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wb); });
        this->expect_no_exception([&] { root_cr3.map_4k(0x1000UL, 0x1000UL, x64::memory_attr::pt_wb); });
        this->expect_no_exception([&] { root_cr3.unmap(0x1000UL); });
        this->expect_no_exception([&] { root_cr3.unmap(0x1000UL); });
    });
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_1g_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_exception([&] { root_cr3.setup_identity_map_1g(0x1, 0x40000000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.setup_identity_map_1g(0x0, 0x40000001); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_1g(0x1, 0x40000000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_1g(0x0, 0x40000001); }, ""_ut_ffe);
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_1g_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_no_exception([&] { root_cr3.setup_identity_map_1g(0x0, 0x40000000); });
    this->expect_no_exception([&] { root_cr3.unmap_identity_map_1g(0x0, 0x40000000); });
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_2m_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_exception([&] { root_cr3.setup_identity_map_2m(0x1, 0x200000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.setup_identity_map_2m(0x0, 0x200001); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_2m(0x1, 0x200000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_2m(0x0, 0x200001); }, ""_ut_ffe);
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_2m_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_no_exception([&] { root_cr3.setup_identity_map_2m(0x0, 0x200000); });
    this->expect_no_exception([&] { root_cr3.unmap_identity_map_2m(0x0, 0x200000); });
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_4k_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_exception([&] { root_cr3.setup_identity_map_4k(0x1, 0x1000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.setup_identity_map_4k(0x0, 0x1001); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_4k(0x1, 0x1000); }, ""_ut_ffe);
    this->expect_exception([&] { root_cr3.unmap_identity_map_4k(0x0, 0x1001); }, ""_ut_ffe);
}

void
memory_manager_ut::test_root_page_table_x64_setup_identity_map_4k_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_no_exception([&] { root_cr3.setup_identity_map_4k(0x0, 0x1000); });
    this->expect_no_exception([&] { root_cr3.unmap_identity_map_4k(0x0, 0x1000); });
}

void
memory_manager_ut::test_root_page_table_x64_pt_to_mdl()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_cr3 = root_page_table_x64{};

    this->expect_no_exception([&] { root_cr3.pt_to_mdl(); });
}
