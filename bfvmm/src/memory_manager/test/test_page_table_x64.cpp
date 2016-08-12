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
#include <stdlib.h>
#include <memory_manager/page_table_x64.h>
#include <memory_manager/memory_manager.h>

static uintptr_t
virt_to_phys_ptr(void *ptr)
{
    (void) ptr;

    return 0x0000000ABCDEF0000;
}

void
memory_manager_ut::test_page_table_x64_no_entry()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_TRUE(pt->phys_addr() != 0);
        EXPECT_TRUE(pt->present());
        EXPECT_TRUE(pt->rw());
        EXPECT_TRUE(pt->us());
        EXPECT_FALSE(pt->pwt());
        EXPECT_FALSE(pt->pcd());
        EXPECT_FALSE(pt->accessed());
        EXPECT_FALSE(pt->dirty());
        EXPECT_FALSE(pt->pat());
        EXPECT_FALSE(pt->global());
        EXPECT_FALSE(pt->nx());
    });
}

void
memory_manager_ut::test_page_table_x64_with_entry()
{
    uintptr_t entry = 0;

    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>(&entry);

        EXPECT_TRUE(pt->phys_addr() != 0);
        EXPECT_TRUE(pt->present());
        EXPECT_TRUE(pt->rw());
        EXPECT_TRUE(pt->us());
        EXPECT_FALSE(pt->pwt());
        EXPECT_FALSE(pt->pcd());
        EXPECT_FALSE(pt->accessed());
        EXPECT_FALSE(pt->dirty());
        EXPECT_FALSE(pt->pat());
        EXPECT_FALSE(pt->global());
        EXPECT_FALSE(pt->nx());
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
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
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
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
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
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
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        for (auto i = 0; i < 4096; i++)
            pml4->add_page(virt + (i * 0x1000));
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_twice_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(virt);
        EXPECT_EXCEPTION(pml4->add_page(virt), std::logic_error);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_TRUE(pt->phys_addr() != 0);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Return(0);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_TRUE(pt->phys_addr() == 0);
    });
}
