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

#include <memory_manager/page_table_entry_x64.h>

page_table_entry_x64::page_table_entry_x64(uintptr_t *entry) noexcept :
    m_entry(entry)
{
}

bool
page_table_entry_x64::present() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_P);
}

void
page_table_entry_x64::set_present(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_P : *m_entry &= ~PTE_FLAGS_P;
}

bool
page_table_entry_x64::rw() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_RW);
}

void
page_table_entry_x64::set_rw(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_RW : *m_entry &= ~PTE_FLAGS_RW;
}

bool
page_table_entry_x64::us() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_US);
}

void
page_table_entry_x64::set_us(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_US : *m_entry &= ~PTE_FLAGS_US;
}

bool
page_table_entry_x64::pwt() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_PWT);
}

void
page_table_entry_x64::set_pwt(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_PWT : *m_entry &= ~PTE_FLAGS_PWT;
}

bool
page_table_entry_x64::pcd() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_PCD);
}

void
page_table_entry_x64::set_pcd(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_PCD : *m_entry &= ~PTE_FLAGS_PCD;
}

bool
page_table_entry_x64::accessed() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_A);
}

void
page_table_entry_x64::set_accessed(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_A : *m_entry &= ~PTE_FLAGS_A;
}

bool
page_table_entry_x64::dirty() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_D);
}

void
page_table_entry_x64::set_dirty(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_D : *m_entry &= ~PTE_FLAGS_D;
}

bool
page_table_entry_x64::pat() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_PAT);
}

void
page_table_entry_x64::set_pat(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_PAT : *m_entry &= ~PTE_FLAGS_PAT;
}

bool
page_table_entry_x64::global() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_G);
}

void
page_table_entry_x64::set_global(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_G : *m_entry &= ~PTE_FLAGS_G;
}

uintptr_t
page_table_entry_x64::phys_addr() const noexcept
{
    if (m_entry == nullptr)
        return 0;

    return (*m_entry & PTE_PHYS_ADDR_MASK);
}

void
page_table_entry_x64::set_phys_addr(uintptr_t addr) noexcept
{
    if (m_entry == nullptr)
        return;

    *m_entry = (*m_entry & ~PTE_PHYS_ADDR_MASK) | (addr & PTE_PHYS_ADDR_MASK);
}

bool
page_table_entry_x64::nx() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & PTE_FLAGS_NX);
}

void
page_table_entry_x64::set_nx(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= PTE_FLAGS_NX : *m_entry &= ~PTE_FLAGS_NX;
}
