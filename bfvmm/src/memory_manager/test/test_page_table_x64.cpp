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
constexpr page_table_x64::integer_pointer virt = 0x0000100000000000UL;

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);
    mocks.OnCall(mm, memory_manager_x64::virtint_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_success_without_setting()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        pml4->add_page_4k(virt);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->add_page_4k(virt + 0x1000);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->add_page_4k(virt + 0x10000);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        pml4->remove_page(virt + 0x1000);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        pml4->remove_page(virt + 0x10000);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_1g_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        auto &&entry1 = pml4->add_page_1g(virt);
        entry1.set_present(true);
        this->expect_true(pml4->global_size() == 2);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        auto &&entry2 = pml4->add_page_1g(virt + 0x100);
        entry2.set_present(true);
        this->expect_true(pml4->global_size() == 2);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        auto &&entry3 = pml4->add_page_1g(virt + 0x40000000);
        entry3.set_present(true);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        auto &&entry4 = pml4->add_page_1g(virt + 0x400000000);
        entry4.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        pml4->remove_page(virt + 0x40000000);
        this->expect_true(pml4->global_size() == 2);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        pml4->remove_page(virt + 0x400000000);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_2m_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        auto &&entry1 = pml4->add_page_2m(virt);
        entry1.set_present(true);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        auto &&entry2 = pml4->add_page_2m(virt + 0x100);
        entry2.set_present(true);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        auto &&entry3 = pml4->add_page_2m(virt + 0x200000);
        entry3.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        auto &&entry4 = pml4->add_page_2m(virt + 0x2000000);
        entry4.set_present(true);
        this->expect_true(pml4->global_size() == 5);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        pml4->remove_page(virt + 0x200000);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        pml4->remove_page(virt + 0x2000000);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_4k_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        auto &&entry1 = pml4->add_page_4k(virt);
        entry1.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        auto &&entry2 = pml4->add_page_4k(virt + 0x100);
        entry2.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        auto &&entry3 = pml4->add_page_4k(virt + 0x1000);
        entry3.set_present(true);
        this->expect_true(pml4->global_size() == 5);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        auto &&entry4 = pml4->add_page_4k(virt + 0x10000);
        entry4.set_present(true);
        this->expect_true(pml4->global_size() == 6);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 5);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt + 0x1000);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt + 0x10000);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);
    });
}

void
memory_manager_ut::test_page_table_x64_add_remove_page_swap_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        auto &&entry1 = pml4->add_page_4k(virt);
        entry1.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        auto &&entry2 = pml4->add_page_2m(virt);
        entry2.set_present(true);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);

        auto &&entry3 = pml4->add_page_4k(virt);
        entry3.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        auto &&entry4 = pml4->add_page_2m(virt);
        entry4.set_present(true);
        this->expect_true(pml4->global_size() == 3);
        this->expect_true(pml4->global_capacity() == 512 * 2);

        auto &&entry5 = pml4->add_page_4k(virt);
        entry5.set_present(true);
        this->expect_true(pml4->global_size() == 4);
        this->expect_true(pml4->global_capacity() == 512 * 3);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
        this->expect_true(pml4->global_capacity() == 512 * 1);
    });
}

void
memory_manager_ut::test_page_table_x64_add_page_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        pml4->add_page_4k(virt);
        this->expect_no_exception([&]{ pml4->add_page_4k(virt); });
    });
}

void
memory_manager_ut::test_page_table_x64_remove_page_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        pml4->add_page_4k(virt);
        pml4->add_page_4k(virt + 0x1000);

        pml4->remove_page(virt);
        this->expect_no_exception([&]{ pml4->remove_page(virt); });
        pml4->remove_page(virt + 0x1000);

        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_remove_page_unknown_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);
        this->expect_no_exception([&]{ pml4->remove_page(virt); });
    });
}

void
memory_manager_ut::test_page_table_x64_virt_to_pte_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        pml4->add_page_4k(virt);

        this->expect_exception([&]{ pml4->virt_to_pte(virt + 0x40000000); }, ""_ut_ree);

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_virt_to_pte_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        pml4->add_page_4k(virt);
        this->expect_no_exception([&]{ pml4->virt_to_pte(virt); });

        pml4->remove_page(virt);
        this->expect_true(pml4->global_size() == 0);
    });
}

void
memory_manager_ut::test_page_table_x64_pt_to_mdl_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&pml4 = std::make_unique<page_table_x64>(&scr3);

        this->expect_true(pml4->pt_to_mdl().size() == 1);
        pml4->add_page_1g(0x1000);
        this->expect_true(pml4->pt_to_mdl().size() == 2);
        pml4->add_page_2m(0x1000);
        this->expect_true(pml4->pt_to_mdl().size() == 3);
        pml4->add_page_4k(0x1000);
        this->expect_true(pml4->pt_to_mdl().size() == 4);

        pml4->remove_page(0x1000);
        this->expect_true(pml4->global_size() == 0);
    });
}
