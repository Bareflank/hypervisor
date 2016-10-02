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
#include <stdlib.h>
#include <memory_manager/page_table_x64.h>
#include <memory_manager/memory_manager.h>

bool virt_to_phys_return_nullptr = false;

static uintptr_t
virtptr_to_physint(void *ptr)
{
    (void) ptr;

    if (virt_to_phys_return_nullptr)
        return 0;

    return 0x0000000ABCDEF0000;
}

void
memory_manager_ut::test_page_table_x64_no_entry()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

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
memory_manager_ut::test_page_table_x64_with_entry()
{
    uintptr_t entry = 0;

    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>(&entry);

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
memory_manager_ut::test_page_table_x64_add_page_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000ULL;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(virt);
    });
}

void
memory_manager_ut::test_page_table_x64_add_two_pages_no_added_mem_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000ULL;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(virt);
        pml4->add_page(virt + 0x1000);
    });
}

void
memory_manager_ut::test_page_table_x64_add_two_pages_with_added_mem_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000ULL;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(virt);
        pml4->add_page(virt + 0x1000000);
    });
}

void
memory_manager_ut::test_page_table_x64_add_many_pages_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000ULL;
        auto pml4 = std::make_shared<page_table_x64>();

        for (auto i = 0U; i < 4096; i++)
            pml4->add_page(virt + (i * 0x1000U));
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_twice_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000ULL;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(virt);

        auto e = std::make_shared<std::logic_error>("add_page: page mapping already exists");
        this->expect_exception([&] { pml4->add_page(virt); }, e);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        this->expect_true(pt->phys_addr() != 0);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);

    auto ___ = gsl::finally([&]
    {
        virt_to_phys_return_nullptr = false;
    });

    virt_to_phys_return_nullptr = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        this->expect_true(pt->phys_addr() == 0);
    });
}
