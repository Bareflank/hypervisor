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
#include <memory_manager/page_table_entry_x64.h>

void
memory_manager_ut::test_page_table_entry_x64_present()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_present(true);
    EXPECT_TRUE(pte->present());
    pte->set_present(false);
    EXPECT_FALSE(pte->present());
}

void
memory_manager_ut::test_page_table_entry_x64_rw()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_rw(true);
    EXPECT_TRUE(pte->rw());
    pte->set_rw(false);
    EXPECT_FALSE(pte->rw());
}

void
memory_manager_ut::test_page_table_entry_x64_us()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_us(true);
    EXPECT_TRUE(pte->us());
    pte->set_us(false);
    EXPECT_FALSE(pte->us());
}

void
memory_manager_ut::test_page_table_entry_x64_pwt()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pwt(true);
    EXPECT_TRUE(pte->pwt());
    pte->set_pwt(false);
    EXPECT_FALSE(pte->pwt());
}

void
memory_manager_ut::test_page_table_entry_x64_pcd()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pcd(true);
    EXPECT_TRUE(pte->pcd());
    pte->set_pcd(false);
    EXPECT_FALSE(pte->pcd());
}

void
memory_manager_ut::test_page_table_entry_x64_accessed()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_accessed(true);
    EXPECT_TRUE(pte->accessed());
    pte->set_accessed(false);
    EXPECT_FALSE(pte->accessed());
}

void
memory_manager_ut::test_page_table_entry_x64_dirty()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_dirty(true);
    EXPECT_TRUE(pte->dirty());
    pte->set_dirty(false);
    EXPECT_FALSE(pte->dirty());
}

void
memory_manager_ut::test_page_table_entry_x64_pat()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pat(true);
    EXPECT_TRUE(pte->pat());
    pte->set_pat(false);
    EXPECT_FALSE(pte->pat());
}

void
memory_manager_ut::test_page_table_entry_x64_global()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_global(true);
    EXPECT_TRUE(pte->global());
    pte->set_global(false);
    EXPECT_FALSE(pte->global());
}

void
memory_manager_ut::test_page_table_entry_x64_nx()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_nx(true);
    EXPECT_TRUE(pte->nx());
    pte->set_nx(false);
    EXPECT_FALSE(pte->nx());
}

void
memory_manager_ut::test_page_table_entry_x64_phys_addr()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_phys_addr(0x000ABCDEF1234000);
    EXPECT_TRUE(pte->phys_addr() == 0x000ABCDEF1234000);
    pte->set_phys_addr(0x000ABCDEF1234010);
    EXPECT_TRUE(pte->phys_addr() == 0x000ABCDEF1234000);
    pte->set_phys_addr(0x0);
    EXPECT_TRUE(pte->phys_addr() == 0x0);
}
