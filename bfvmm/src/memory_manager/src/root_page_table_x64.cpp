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
// Implementation
// -----------------------------------------------------------------------------

root_page_table_x64::root_page_table_x64(bool is_vmm) :
    m_is_vmm(is_vmm),
    m_pt{std::make_unique<page_table_x64>(&m_cr3)}
{ }

root_page_table_x64::cr3_type
root_page_table_x64::cr3()
{ return m_cr3; }

void
root_page_table_x64::unmap(integer_pointer virt) noexcept
{
    std::lock_guard<std::mutex> guard(m_mutex);
    unmap_page(virt);
}

void
root_page_table_x64::setup_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pdpt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pdpt::size_bytes)
        this->map_1g(virt, virt, x64::memory_attr::pt_wb);
}

void
root_page_table_x64::setup_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pd::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pd::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pd::size_bytes)
        this->map_2m(virt, virt, x64::memory_attr::pt_wb);
}

void
root_page_table_x64::setup_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pt::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pt::size_bytes)
        this->map_4k(virt, virt, x64::memory_attr::pt_wb);
}

void
root_page_table_x64::unmap_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pdpt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pdpt::size_bytes)
        this->unmap(virt);
}

void
root_page_table_x64::unmap_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pd::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pd::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pd::size_bytes)
        this->unmap(virt);
}

void
root_page_table_x64::unmap_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (page_table::pt::size_bytes - 1)) == 0);
    expects((eaddr & (page_table::pt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += page_table::pt::size_bytes)
        this->unmap(virt);
}

page_table_entry_x64
root_page_table_x64::virt_to_pte(integer_pointer virt) const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_pt->virt_to_pte(virt);
}

root_page_table_x64::memory_descriptor_list
root_page_table_x64::pt_to_mdl() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_pt->pt_to_mdl();
}

page_table_entry_x64
root_page_table_x64::add_page(integer_pointer virt, size_type size)
{
    switch (size)
    {
        case page_table::pdpt::size_bytes:
            return m_pt->add_page_1g(virt);

        case page_table::pd::size_bytes:
            return m_pt->add_page_2m(virt);

        case page_table::pt::size_bytes:
            return m_pt->add_page_4k(virt);

        default:
            throw std::logic_error("invalid pt size");
    }
}

void
root_page_table_x64::map_page(integer_pointer virt, integer_pointer phys, attr_type attr, size_type size)
{
    std::lock_guard<std::mutex> guard(m_mutex);

    auto &&entry = add_page(virt, size);

    auto ___ = gsl::on_failure([&]
    { this->unmap_page(virt); });

    switch (size)
    {
        case page_table::pdpt::size_bytes:
            entry.clear();
            entry.set_phys_addr(phys & ~(page_table::pdpt::size_bytes - 1));
            entry.set_present(true);
            entry.set_ps(true);
            entry.set_pat_index_large(pat::mem_attr_to_pat_index(attr));
            break;

        case page_table::pd::size_bytes:
            entry.clear();
            entry.set_phys_addr(phys & ~(page_table::pd::size_bytes - 1));
            entry.set_present(true);
            entry.set_ps(true);
            entry.set_pat_index_large(pat::mem_attr_to_pat_index(attr));
            break;

        case page_table::pt::size_bytes:
            entry.clear();
            entry.set_phys_addr(phys & ~(page_table::pt::size_bytes - 1));
            entry.set_present(true);
            entry.set_pat_index_4k(pat::mem_attr_to_pat_index(attr));
            break;
    }

    switch (attr)
    {
        case memory_attr::rw_uc:
        case memory_attr::rw_wc:
        case memory_attr::rw_wt:
        case memory_attr::rw_wp:
        case memory_attr::rw_wb:
        case memory_attr::rw_uc_m:
            entry.set_rw(true);
            entry.set_nx(true);
            break;

        case memory_attr::re_uc:
        case memory_attr::re_wc:
        case memory_attr::re_wt:
        case memory_attr::re_wp:
        case memory_attr::re_wb:
        case memory_attr::re_uc_m:
            entry.set_rw(false);
            entry.set_nx(false);
            break;

        case memory_attr::pt_uc:
        case memory_attr::pt_wc:
        case memory_attr::pt_wt:
        case memory_attr::pt_wp:
        case memory_attr::pt_wb:
        case memory_attr::pt_uc_m:
            entry.set_rw(true);
            entry.set_nx(false);
            break;

        default:
            throw std::logic_error("unsupported memory permissions");
    }

    if (m_is_vmm)
        g_mm->add_md(virt, phys, attr);
}

void
root_page_table_x64::unmap_page(integer_pointer virt) noexcept
{
    guard_exceptions([&]
    { m_pt->remove_page(virt); });

    if (m_is_vmm)
    {
        guard_exceptions([&]
        { g_mm->remove_md(virt); });
    }
}

root_page_table_x64 *
root_pt() noexcept
{
    static std::unique_ptr<root_page_table_x64> rpt;

    if (!rpt)
    {
        rpt = std::make_unique<root_page_table_x64>(true);

        try
        {
            for (const auto &md : g_mm->descriptors())
            {
                auto attr = memory_attr::invalid;

                if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_W))
                    attr = memory_attr::rw_wb;
                if (md.type == (MEMORY_TYPE_R | MEMORY_TYPE_E))
                    attr = memory_attr::re_wb;

                rpt->map_4k(md.virt, md.phys, attr);
            }
        }
        catch (std::exception &e)
        {
            rpt.reset();

            bferror << "failed to construct root page tables: " << e.what() << bfendl;
            root_page_table_terminate();
        }
    }

    return rpt.get();
}
