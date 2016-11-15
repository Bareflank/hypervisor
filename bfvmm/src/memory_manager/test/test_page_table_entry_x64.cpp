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

#include <bitmanip.h>
#include <memory_manager/page_table_entry_x64.h>

using pte_type = page_table_entry_x64::integer_pointer;

void
memory_manager_ut::test_page_table_entry_x64_present()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_present(true);
    this->expect_true(pte->present());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 0));

    pte->set_present(false);
    this->expect_false(pte->present());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_rw()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_rw(true);
    this->expect_true(pte->rw());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 1));

    pte->set_rw(false);
    this->expect_false(pte->rw());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_us()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_us(true);
    this->expect_true(pte->us());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 2));

    pte->set_us(false);
    this->expect_false(pte->us());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_pwt()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_pwt(true);
    this->expect_true(pte->pwt());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 3));

    pte->set_pwt(false);
    this->expect_false(pte->pwt());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_pcd()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_pcd(true);
    this->expect_true(pte->pcd());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 4));

    pte->set_pcd(false);
    this->expect_false(pte->pcd());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_accessed()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_accessed(true);
    this->expect_true(pte->accessed());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 5));

    pte->set_accessed(false);
    this->expect_false(pte->accessed());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_dirty()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_dirty(true);
    this->expect_true(pte->dirty());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 6));

    pte->set_dirty(false);
    this->expect_false(pte->dirty());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_pat()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_pat(true);
    this->expect_true(pte->pat());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 7));

    pte->set_pat(false);
    this->expect_false(pte->pat());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_ps()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_ps(true);
    this->expect_true(pte->ps());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 7));

    pte->set_ps(false);
    this->expect_false(pte->ps());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_global()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_global(true);
    this->expect_true(pte->global());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 8));

    pte->set_global(false);
    this->expect_false(pte->global());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_nx()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_nx(true);
    this->expect_true(pte->nx());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 63));

    pte->set_nx(false);
    this->expect_false(pte->nx());
    this->expect_true(num_bits_set(entry) == 0);
}

void
memory_manager_ut::test_page_table_entry_x64_phys_addr()
{
    pte_type entry = 0;
    auto &&pte = std::make_unique<page_table_entry_x64>(&entry);

    pte->set_present(true);
    pte->set_nx(true);
    pte->set_phys_addr(0x000ABCDEF1234000);
    this->expect_true(pte->present());
    this->expect_true(pte->nx());
    this->expect_true(pte->phys_addr() == 0x000ABCDEF1234000);

    pte->set_phys_addr(0x000ABCDEF1234010);
    this->expect_true(pte->phys_addr() == 0x000ABCDEF1234000);
    this->expect_false(pte->pcd());

    pte->set_present(true);
    pte->set_nx(true);
    pte->set_phys_addr(0x0);
    this->expect_true(pte->present());
    this->expect_true(pte->nx());
    this->expect_true(pte->phys_addr() == 0x0);
}
