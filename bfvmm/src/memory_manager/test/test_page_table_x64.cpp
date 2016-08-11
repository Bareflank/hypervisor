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

void *
malloc_aligned(size_t size, uint64_t alignment)
{
    void *ptr = 0;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return 0;
    return ptr;
}

void *
virt_to_phys(void *)
{
    static uintptr_t phys = 0x0000000ABCDEF0000;
    return reinterpret_cast<void *>(phys + 0x1000);
}

void
memory_manager_ut::test_page_table_x64_no_entry()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_TRUE(pt->phys_addr() == 0);
        EXPECT_TRUE(pt->present() == false);
        EXPECT_TRUE(pt->rw() == false);
        EXPECT_TRUE(pt->us() == false);
        EXPECT_TRUE(pt->pwt() == false);
        EXPECT_TRUE(pt->pcd() == false);
        EXPECT_TRUE(pt->accessed() == false);
        EXPECT_TRUE(pt->dirty() == false);
        EXPECT_TRUE(pt->pat() == false);
        EXPECT_TRUE(pt->global() == false);
        EXPECT_TRUE(pt->nx() == false);
    });
}

void
memory_manager_ut::test_page_table_x64_with_entry()
{
    uintptr_t entry = 0;

    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>(&entry);

        EXPECT_TRUE(pt->phys_addr() != 0);
        EXPECT_TRUE(pt->present() == true);
        EXPECT_TRUE(pt->rw() == true);
        EXPECT_TRUE(pt->us() == true);
        EXPECT_TRUE(pt->pwt() == false);
        EXPECT_TRUE(pt->pcd() == false);
        EXPECT_TRUE(pt->accessed() == false);
        EXPECT_TRUE(pt->dirty() == false);
        EXPECT_TRUE(pt->pat() == false);
        EXPECT_TRUE(pt->global() == false);
        EXPECT_TRUE(pt->nx() == false);
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCalls(mm, memory_manager::malloc_aligned, 4).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(reinterpret_cast<void *>(virt));
    });
}

void
memory_manager_ut::test_page_table_x64_add_two_pages_no_added_mem_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCalls(mm, memory_manager::malloc_aligned, 4).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(reinterpret_cast<void *>(virt));
        pml4->add_page(reinterpret_cast<void *>(virt + 0x1000));
    });
}

void
memory_manager_ut::test_page_table_x64_add_two_pages_with_added_mem_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCalls(mm, memory_manager::malloc_aligned, 5).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(reinterpret_cast<void *>(virt));
        pml4->add_page(reinterpret_cast<void *>(virt + 0x1000000));
    });
}

void
memory_manager_ut::test_page_table_x64_add_many_pages_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        for (auto i = 0; i < 4096; i++)
            pml4->add_page(reinterpret_cast<void *>(virt + (i * 0x1000)));
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_twice_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto virt = 0x0000123456780000;
        auto pml4 = std::make_shared<page_table_x64>();

        pml4->add_page(reinterpret_cast<void *>(virt));
        EXPECT_EXCEPTION(pml4->add_page(reinterpret_cast<void *>(virt)), std::logic_error);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_TRUE(pt->table_phys_addr() != 0);
    });
}

void
memory_manager_ut::test_page_table_x64_table_phys_addr_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    mocks.OnCallFunc(memory_manager::instance).Return(mm);

    mocks.ExpectCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Return(nullptr);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto pt = std::make_shared<page_table_x64>();

        EXPECT_EXCEPTION(pt->table_phys_addr(), std::logic_error);
    });
}

void
memory_manager_ut::test_page_table_x64_coveralls_cleanup()
{
    MockRepository mocks;
    mocks.OnCallFunc(posix_memalign).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(malloc_aligned(4096, 4096) == 0);
    });
}
