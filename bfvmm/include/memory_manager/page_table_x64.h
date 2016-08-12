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

#ifndef PAGE_TABLE_X64_H
#define PAGE_TABLE_X64_H

#include <vector>
#include <memory>
#include <memory_manager/page_table_entry_x64.h>

#include <gsl/gsl>

class page_table_x64 : public page_table_entry_x64
{
public:

    /// Constructor
    ///
    /// Creates a page table, and stores the parent entry that points to
    /// this entry so that you can modify the properties of this page table
    /// as needed.
    ///
    /// @param pte the parent page table entry that points to this table
    ///
    page_table_x64(uintptr_t *pte = nullptr);

    /// Destructor
    ///
    ~page_table_x64() override = default;

    /// Add Page
    ///
    /// Adds a page to the page table structure. Note that this is the
    /// public function, and should only be used to add pages to the
    /// PML4 page table. This function will call a private version that
    /// will parse through the different levels making sure the virtual
    /// address provided is valid.
    ///
    /// @param virt_addr the virtual address to add to the set of page tables.
    /// @return the resulting page. Note that this page is blank, and it's
    ///     properties (like present) should be set by the caller
    ///
    virtual std::shared_ptr<page_table_entry_x64> add_page(uintptr_t virt_addr);

private:

    virtual std::shared_ptr<page_table_entry_x64> add_page(uintptr_t virt_addr, uint64_t bits);

private:

    gsl::span<uintptr_t> m_pt;
    std::unique_ptr<uintptr_t[]> m_pt_owner;

    std::vector<std::shared_ptr<page_table_entry_x64> > m_ptes;

    uintptr_t m_cr3_shadow;
};

#endif
