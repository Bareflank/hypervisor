//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <bfvector.h>

#include <memory_manager/memory_manager.h>
#include <memory_manager/arch/x64/page_table.h>

#include <intrinsics.h>

namespace bfvmm
{
namespace x64
{

page_table::page_table(gsl::not_null<pointer> pte)
{
    m_pt = std::make_unique<integer_pointer[]>(::x64::page_table::num_entries);

    auto entry = page_table_entry(pte);
    entry.clear();
    entry.set_phys_addr(g_mm->virtptr_to_physint(m_pt.get()));
    entry.set_present(true);
    entry.set_rw(true);
    entry.set_pat_index_4k(::x64::pat::write_back_index);
}

page_table_entry
page_table::add_page(integer_pointer addr, integer_pointer bits, integer_pointer end)
{
    auto index = ::x64::page_table::index(addr, bits);

    if (bits > end) {
        if (m_pts.empty()) {
            m_pts = std::vector<std::unique_ptr<page_table>>(::x64::page_table::num_entries);
        }

        auto iter = bfn::find(m_pts, index);
        if (!(*iter)) {
            auto view = gsl::make_span(m_pt, ::x64::page_table::num_entries);
            (*iter) = std::make_unique<page_table>(&view.at(index));
        }

        return (*iter)->add_page(addr, bits - ::x64::page_table::pt::size, end);
    }

    if (!m_pts.empty()) {
        m_pts.clear();
        m_pts.shrink_to_fit();
    }

    auto view = gsl::make_span(m_pt, ::x64::page_table::num_entries);
    return page_table_entry(&view.at(index));
}

void
page_table::remove_page(integer_pointer addr, integer_pointer bits)
{
    auto index = ::x64::page_table::index(addr, bits);

    if (!m_pts.empty()) {
        auto iter = bfn::find(m_pts, index);
        if (auto pt = (*iter).get()) {
            pt->remove_page(addr, bits - ::x64::page_table::pt::size);
            if (pt->empty()) {
                (*iter) = nullptr;

                auto view = gsl::make_span(m_pt, ::x64::page_table::num_entries);
                view.at(index) = 0;
            }
        }
    }
    else {
        auto view = gsl::make_span(m_pt, ::x64::page_table::num_entries);
        view.at(index) = 0;

        return;
    }
}

page_table_entry
page_table::virt_to_pte(integer_pointer addr, integer_pointer bits) const
{
    auto index = ::x64::page_table::index(addr, bits);

    if (!m_pts.empty()) {
        auto iter = bfn::cfind(m_pts, index);
        if (auto pt = (*iter).get()) {
            return pt->virt_to_pte(addr, bits - ::x64::page_table::pt::size);
        }

        throw std::runtime_error("unable to locate pte. invalid address");
    }

    auto view = gsl::make_span(m_pt, ::x64::page_table::num_entries);
    return page_table_entry(&view.at(index));
}

page_table::memory_descriptor_list
page_table::pt_to_mdl(memory_descriptor_list &mdl) const
{
    auto virt = reinterpret_cast<uintptr_t>(m_pt.get());
    auto phys = g_mm->virtint_to_physint(virt);
    auto type = MEMORY_TYPE_R | MEMORY_TYPE_W;

    mdl.push_back({phys, virt, type});

    for (const auto &pt : m_pts) {
        if (pt != nullptr) { pt->pt_to_mdl(mdl); }
    }

    return mdl;
}

bool
page_table::empty() const noexcept
{
    auto size = 0ULL;

    for (auto entry : gsl::make_span(m_pt, ::x64::page_table::num_entries)) {
        if (entry != 0) {
            size++;
        }
    }

    return size == 0;
}

page_table::size_type
page_table::global_size() const noexcept
{
    auto size = 0ULL;

    for (auto entry : gsl::make_span(m_pt, ::x64::page_table::num_entries)) {
        size += entry != 0 ? 1U : 0U;
    }

    for (const auto &pt : m_pts) {
        if (pt != nullptr) {
            size += pt->global_size();
        }
    }

    return size;
}

page_table::size_type
page_table::global_capacity() const noexcept
{
    auto size = m_pts.capacity();

    for (const auto &pt : m_pts) {
        if (pt != nullptr) {
            size += pt->global_capacity();
        }
    }

    return size;
}

}
}
