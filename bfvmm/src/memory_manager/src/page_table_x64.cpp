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

#include <memory_manager/memory_manager.h>
#include <memory_manager/page_table_x64.h>

page_table_x64::page_table_x64(uintptr_t *pte) :
    page_table_entry_x64(pte != nullptr ? pte : & m_cr3_shadow),
    m_ptes(PT_SIZE),
    m_cr3_shadow(0)
{
    m_pt_owner = std::make_unique<uintptr_t[]>(4096 / sizeof(uintptr_t));
    m_pt = gsl::span<uintptr_t>(m_pt_owner.get(), PT_SIZE);

    this->set_phys_addr(g_mm->virt_to_phys(m_pt_owner.get()));
    this->set_present(true);
    this->set_rw(true);
    this->set_us(true);
}

std::shared_ptr<page_table_entry_x64>
page_table_x64::add_page(uintptr_t virt_addr)
{
    return add_page(virt_addr, PML4_INDEX);
}

std::shared_ptr<page_table_entry_x64>
page_table_x64::add_page(uintptr_t virt_addr, uint64_t bits)
{
    auto index = (virt_addr & ((INDEX_MASK) << bits)) >> bits;

    if (bits > PT_INDEX)
    {
        auto pte = std::dynamic_pointer_cast<page_table_x64>(m_ptes[index]);

        if (pte)
            return pte->add_page(virt_addr, bits - BITS_PER_INDEX);

        pte = std::make_shared<page_table_x64>(&m_pt[index]);
        m_ptes[index] = pte;

        return pte->add_page(virt_addr, bits - BITS_PER_INDEX);
    }

    auto pte = m_ptes[index];

    if (pte)
        throw std::logic_error("add_page: page mapping already exists");

    pte = std::make_shared<page_table_entry_x64>(&m_pt[index]);
    m_ptes[index] = pte;

    return pte;
}
