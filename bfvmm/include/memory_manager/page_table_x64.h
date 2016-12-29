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

#include <gsl/gsl>

#include <vector>
#include <memory>

#include <memory.h>
#include <memory_manager/page_table_entry_x64.h>

class page_table_x64
{
public:

    using pointer = uintptr_t *;
    using integer_pointer = uintptr_t;
    using size_type = std::size_t;
    using memory_descriptor_list = std::vector<memory_descriptor>;

    /// Constructor
    ///
    /// Creates a page table, and stores the parent entry that points to
    /// this entry so that you can modify the properties of this page table
    /// as needed.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param pte the parent page table entry that points to this table
    ///
    page_table_x64(gsl::not_null<pointer> pte);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~page_table_x64() = default;

    /// Add Page (1g Granularity)
    ///
    /// Adds a page to the page table structure. Note that this is the
    /// public function, and should only be used to add pages to the
    /// PML4 page table. This function will call a private version that
    /// will parse through the different levels making sure the virtual
    /// address provided is valid.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the virtual address to the page to add
    /// @return the resulting pte. Note that this pte is blank, and its
    ///     properties (like present) should be set by the caller
    ///
    page_table_entry_x64 add_page_1g(integer_pointer addr)
    { return add_page(addr, x64::page_table::pml4::from, x64::page_table::pdpt::from); }

    /// Add Page (2m Granularity)
    ///
    /// Adds a page to the page table structure. Note that this is the
    /// public function, and should only be used to add pages to the
    /// PML4 page table. This function will call a private version that
    /// will parse through the different levels making sure the virtual
    /// address provided is valid.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the virtual address to the page to add
    /// @return the resulting pte. Note that this pte is blank, and its
    ///     properties (like present) should be set by the caller
    ///
    page_table_entry_x64 add_page_2m(integer_pointer addr)
    { return add_page(addr, x64::page_table::pml4::from, x64::page_table::pd::from); }

    /// Add Page (4k Granularity)
    ///
    /// Adds a page to the page table structure. Note that this is the
    /// public function, and should only be used to add pages to the
    /// PML4 page table. This function will call a private version that
    /// will parse through the different levels making sure the virtual
    /// address provided is valid.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the virtual address to the page to add
    /// @return the resulting pte. Note that this pte is blank, and its
    ///     properties (like present) should be set by the caller
    ///
    page_table_entry_x64 add_page_4k(integer_pointer addr)
    { return add_page(addr, x64::page_table::pml4::from, x64::page_table::pt::from); }

    /// Remove Page
    ///
    /// Removes a page from the page table. Note that this function cleans
    /// up as it goes, removing empty page tables if they are detected. For
    /// this reason, this operation can be expensive if mapping / unmapping
    /// occurs side by side with addresses that are similar (page tables will
    /// be needlessly removed)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the virtual address of the page to remove
    ///
    void remove_page(integer_pointer addr)
    { remove_page(addr, x64::page_table::pml4::from); }

    /// Virt to Page Table Entry
    ///
    /// Returns the PTE associated with the provided virtual address. If no
    /// PTE exists for the virtual address provided, an exception is thrown.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the virtual address of the pte to locate
    ///
    page_table_entry_x64 virt_to_pte(integer_pointer addr) const
    { return virt_to_pte(addr, x64::page_table::pml4::from); }

    /// Page Table to Memory Descriptor List
    ///
    /// This function converts the internal page table tree structure into a
    /// linear, memory descriptor list. Page table entry information is not
    /// provide, only the page tables.
    /// pages.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return memory descriptor list
    ///
    memory_descriptor_list pt_to_mdl() const
    { memory_descriptor_list mdl; return pt_to_mdl(mdl); }

private:

    page_table_entry_x64 add_page(integer_pointer addr, integer_pointer bits, integer_pointer end);
    void remove_page(integer_pointer addr, integer_pointer bits);
    page_table_entry_x64 virt_to_pte(integer_pointer addr, integer_pointer bits) const;
    memory_descriptor_list pt_to_mdl(memory_descriptor_list &mdl) const;

    bool empty() const noexcept;
    size_type global_size() const noexcept;
    size_type global_capacity() const noexcept;

private:

    friend class memory_manager_ut;

    std::unique_ptr<integer_pointer[]> m_pt;
    std::vector<std::unique_ptr<page_table_x64>> m_pts;

public:

    page_table_x64(page_table_x64 &&) noexcept = default;
    page_table_x64 &operator=(page_table_x64 &&) noexcept = default;

    page_table_x64(const page_table_x64 &) = delete;
    page_table_x64 &operator=(const page_table_x64 &) = delete;
};

#endif
