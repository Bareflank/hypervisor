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

#include <memory_manager/page_table_x64.h>
#include <memory_manager/memory_manager_x64.h>

using namespace x64;

page_table_x64::page_table_x64(pointer pte) :
    page_table_entry_x64(pte != nullptr ? pte : (&m_cr3_shadow)),
    m_size(0),
    m_cr3_shadow(0),
    m_ptes(page_table::num_entries)
{
    m_pt_owner = std::make_unique<integer_pointer[]>(page_table::num_entries);
    m_pt = gsl::span<integer_pointer>(m_pt_owner, page_table::num_entries);

    this->set_phys_addr(g_mm->virtptr_to_physint(m_pt_owner.get()));
    this->set_present(true);
    this->set_rw(true);
    this->set_us(true);
}

page_table_x64::size_type
page_table_x64::global_size() const noexcept
{
    auto size = m_size;

    for (const auto &pte : m_ptes)
    {
        if (auto pt = dynamic_cast<page_table_x64 *>(pte.get()))
            size += pt->global_size();
    }

    return size;
}

gsl::not_null<page_table_entry_x64 *>
page_table_x64::add_page_x64(integer_pointer virt_addr)
{
    expects(virt_addr != 0);
    return add_page_x64(virt_addr, page_table::pml4::from);
}

void
page_table_x64::remove_page_x64(integer_pointer virt_addr)
{
    expects(virt_addr != 0);
    remove_page_x64(virt_addr, page_table::pml4::from);
}

template<class T> std::unique_ptr<T>
page_table_x64::add_pte(pointer p)
{
    m_size++;
    return std::make_unique<T>(p);
}

template<class T> std::unique_ptr<T>
page_table_x64::remove_pte()
{
    m_size--;
    return nullptr;
}

gsl::not_null<page_table_entry_x64 *>
page_table_x64::add_page_x64(integer_pointer virt_addr, integer_pointer bits)
{
    auto &&index = page_table::index(virt_addr, bits);

    if (bits > page_table::pt::from)
    {
        auto &&iter = bfn::find(m_ptes, index);
        if (!*iter)
            *iter = add_pte<page_table_x64>(&m_pt.at(index));

        if (auto pte = dynamic_cast<page_table_x64 *>(iter->get()))
            return pte->add_page_x64(virt_addr, bits - page_table::pt::size);
    }

    auto &&iter = bfn::find(m_ptes, index);
    if (*iter)
        throw std::runtime_error("add_page_x64: page mapping already exists");

    *iter = add_pte<page_table_entry_x64>(&m_pt.at(index));
    return iter->get();
}

void
page_table_x64::remove_page_x64(integer_pointer virt_addr, integer_pointer bits)
{
    auto &&index = page_table::index(virt_addr, bits);

    if (bits > page_table::pt::from)
    {
        auto &&iter = bfn::find(m_ptes, index);
        if (!*iter)
            throw std::runtime_error("remove_page_x64: invalid virtual address");

        if (auto pte = dynamic_cast<page_table_x64 *>(iter->get()))
        {
            pte->remove_page_x64(virt_addr, bits - page_table::pt::size);
            if (pte->empty())
                *iter = remove_pte<page_table_entry_x64>();

            return;
        }
    }

    auto &&iter = bfn::find(m_ptes, index);
    if (!*iter)
        throw std::runtime_error("remove_page_x64: invalid virtual address");

    *iter = remove_pte<page_table_entry_x64>();
}
