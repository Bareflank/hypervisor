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

#include <gsl/gsl>

#include <test.h>
#include <memory_manager/page_table_x64.h>
#include <memory_manager/memory_manager_x64.h>

bool virt_to_phys_return_nullptr = false;
constexpr page_table_x64::integer_pointer virt = 0x0000123456780000UL;

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

void
memory_manager_ut::test_page_table_x64_no_entry()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pt = std::make_unique<page_table_x64>();

        this->expect_true(pt->phys_addr() != 0);
        this->expect_true(pt->present());
        this->expect_true(pt->rw());
        this->expect_true(pt->us());
        this->expect_false(pt->pwt());
        this->expect_false(pt->pcd());
        this->expect_false(pt->accessed());
        this->expect_false(pt->dirty());
        this->expect_false(pt->pat());
        this->expect_false(pt->pat());
        this->expect_false(pt->global());
        this->expect_false(pt->nx());
    });
}

void
memory_manager_ut::test_page_table_x64_with_entry()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        page_table_x64::integer_pointer entry = 0;
        auto &&pt = std::make_unique<page_table_x64>(&entry);

        this->expect_true(pt->phys_addr() != 0);
        this->expect_true(pt->present());
        this->expect_true(pt->rw());
        this->expect_true(pt->us());
        this->expect_false(pt->pwt());
        this->expect_false(pt->pcd());
        this->expect_false(pt->accessed());
        this->expect_false(pt->dirty());
        this->expect_false(pt->pat());
        this->expect_false(pt->global());
        this->expect_false(pt->nx());
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pml4 = std::make_unique<page_table_x64>();

        pml4->add_page_x64(virt);
        this->expect_true(pml4->global_size() == 4);

        pml4->add_page_x64(virt + 0x1000);
        this->expect_true(pml4->global_size() == 5);

        pml4->add_page_x64(virt + 0x1000000);
        this->expect_true(pml4->global_size() == 7);

        pml4->remove_page_x64(virt);
        this->expect_true(pml4->global_size() == 6);

        pml4->remove_page_x64(virt + 0x1000);
        this->expect_true(pml4->global_size() == 4);

        pml4->remove_page_x64(virt + 0x1000000);
        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_many_pages_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pml4 = std::make_unique<page_table_x64>();

        for (auto i = 0U; i < 512; i++)
            pml4->add_page_x64(virt + (i * 0x1000U));

        this->expect_true(pml4->global_size() == 516);

        for (auto i = 0U; i < 512; i++)
            pml4->remove_page_x64(virt + (i * 0x1000U));

        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_twice_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pml4 = std::make_unique<page_table_x64>();

        pml4->add_page_x64(virt);
        this->expect_exception([&]{ pml4->add_page_x64(virt); }, ""_ut_ree);
    });
}

void
memory_manager_ut::test_page_table_x64_remove_page_twice_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pml4 = std::make_unique<page_table_x64>();

        pml4->add_page_x64(virt);
        pml4->add_page_x64(virt + 0x1000);

        pml4->remove_page_x64(virt);
        this->expect_exception([&]{ pml4->remove_page_x64(virt); }, ""_ut_ree);
        pml4->remove_page_x64(virt + 0x1000);

        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_remove_page_unknown_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pml4 = std::make_unique<page_table_x64>();
        this->expect_exception([&]{ pml4->remove_page_x64(virt); }, ""_ut_ree);
    });
}
