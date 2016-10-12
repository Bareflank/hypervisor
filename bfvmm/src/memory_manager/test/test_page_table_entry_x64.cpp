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
    this->expect_true(pte->present());
    pte->set_present(false);
    this->expect_false(pte->present());
}

void
memory_manager_ut::test_page_table_entry_x64_rw()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_rw(true);
    this->expect_true(pte->rw());
    pte->set_rw(false);
    this->expect_false(pte->rw());
}

void
memory_manager_ut::test_page_table_entry_x64_us()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_us(true);
    this->expect_true(pte->us());
    pte->set_us(false);
    this->expect_false(pte->us());
}

void
memory_manager_ut::test_page_table_entry_x64_pwt()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pwt(true);
    this->expect_true(pte->pwt());
    pte->set_pwt(false);
    this->expect_false(pte->pwt());
}

void
memory_manager_ut::test_page_table_entry_x64_pcd()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pcd(true);
    this->expect_true(pte->pcd());
    pte->set_pcd(false);
    this->expect_false(pte->pcd());
}

void
memory_manager_ut::test_page_table_entry_x64_accessed()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_accessed(true);
    this->expect_true(pte->accessed());
    pte->set_accessed(false);
    this->expect_false(pte->accessed());
}

void
memory_manager_ut::test_page_table_entry_x64_dirty()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_dirty(true);
    this->expect_true(pte->dirty());
    pte->set_dirty(false);
    this->expect_false(pte->dirty());
}

void
memory_manager_ut::test_page_table_entry_x64_pat()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_pat(true);
    this->expect_true(pte->pat());
    pte->set_pat(false);
    this->expect_false(pte->pat());
}

void
memory_manager_ut::test_page_table_entry_x64_global()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_global(true);
    this->expect_true(pte->global());
    pte->set_global(false);
    this->expect_false(pte->global());
}

void
memory_manager_ut::test_page_table_entry_x64_nx()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_nx(true);
    this->expect_true(pte->nx());
    pte->set_nx(false);
    this->expect_false(pte->nx());
}

void
memory_manager_ut::test_page_table_entry_x64_phys_addr()
{
    uintptr_t entry;
    auto pte = std::make_shared<page_table_entry_x64>(&entry);

    pte->set_phys_addr(0x000ABCDEF1234000);
    this->expect_true(pte->phys_addr() == 0x000ABCDEF1234000);
    pte->set_phys_addr(0x000ABCDEF1234010);
    this->expect_true(pte->phys_addr() == 0x000ABCDEF1234000);
    pte->set_phys_addr(0x0);
    this->expect_true(pte->phys_addr() == 0x0);
}
