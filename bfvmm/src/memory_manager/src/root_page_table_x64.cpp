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

#include <debug.h>
#include <guard_exceptions.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

using namespace x64;

// -----------------------------------------------------------------------------
// Testing Seem
// -----------------------------------------------------------------------------

#ifdef CROSS_COMPILED

void root_page_table_terminate()
{ std::terminate(); }

#else

auto g_terminate_called = false;

void root_page_table_terminate()
{ g_terminate_called = true; }

#endif

// -----------------------------------------------------------------------------
// Mutexes
// -----------------------------------------------------------------------------

#include <mutex>
std::mutex g_map_mutex;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

root_page_table_x64 *
root_page_table_x64::instance() noexcept
{
    static root_page_table_x64 self;
    return &self;
}

root_page_table_x64::cr3_type
root_page_table_x64::cr3()
{ return m_root_pt->cr3_shadow(); }

void
root_page_table_x64::map(integer_pointer virt, integer_pointer phys, attr_type attr)
{ map_page(virt, phys, attr); }

void
root_page_table_x64::unmap(integer_pointer virt) noexcept
{ unmap_page(virt); }

root_page_table_x64::root_page_table_x64() noexcept :
    m_root_pt {std::make_unique<page_table_x64>()}
{
    try
    {
        for (const auto &md : g_mm->descriptors())
        {
            auto attr = memory_attr::invalid;

            if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_W))
                attr = memory_attr::rw_wb;
            if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_E))
                attr = memory_attr::re_wb;

            this->map_page(md.virt, md.phys, attr);
        }
    }
    catch (std::exception &e)
    {
        bferror << "failed to construct root page tables: " << e.what() << bfendl;
        root_page_table_terminate();
    }
}

gsl::not_null<page_table_entry_x64 *>
root_page_table_x64::add_page(integer_pointer virt)
{
    std::lock_guard<std::mutex> guard(g_map_mutex);
    return m_root_pt->add_page_x64(virt);
}

void
root_page_table_x64::remove_page(integer_pointer virt)
{
    std::lock_guard<std::mutex> guard(g_map_mutex);
    m_root_pt->remove_page_x64(virt);
}

void
root_page_table_x64::map_page(integer_pointer virt, integer_pointer phys, attr_type attr)
{
    expects(virt != 0);
    expects(phys != 0);

    auto entry = add_page(virt);

    auto ___ = gsl::on_failure([&]
    { this->remove_page(virt); });

    entry->set_phys_addr(phys);
    entry->set_present(true);
    entry->set_pat_index(pat::mem_attr_to_pat_index(attr));

    switch (attr)
    {
        case memory_attr::rw_uc:
        case memory_attr::rw_wc:
        case memory_attr::rw_wt:
        case memory_attr::rw_wp:
        case memory_attr::rw_wb:
        case memory_attr::rw_uc_m:
            entry->set_rw(true);
            entry->set_nx(true);
            break;

        case memory_attr::re_uc:
        case memory_attr::re_wc:
        case memory_attr::re_wt:
        case memory_attr::re_wp:
        case memory_attr::re_wb:
        case memory_attr::re_uc_m:
            entry->set_rw(false);
            entry->set_nx(false);
            break;

        default:
            throw std::logic_error("unsupported memory permissions");
    }

    g_mm->add_md(virt, phys, attr);
}

void
root_page_table_x64::unmap_page(integer_pointer virt) noexcept
{
    guard_exceptions([&]
    { this->remove_page(virt); });

    guard_exceptions([&]
    { g_mm->remove_md(virt); });
}
