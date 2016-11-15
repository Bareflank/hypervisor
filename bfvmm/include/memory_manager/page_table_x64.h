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
#include <memory_manager/page_table_entry_x64.h>

class page_table_x64 : public page_table_entry_x64
{
public:

    using pointer = uintptr_t *;
    using integer_pointer = uintptr_t;
    using size_type = std::size_t;

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
    page_table_x64(pointer pte = nullptr);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~page_table_x64() override = default;

    /// Global Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the number of entries in the entire page table
    ///     tree. Note that this function is expensive.
    ///
    size_type global_size() const noexcept;

    /// Add Page
    ///
    /// Adds a page to the page table structure. Note that this is the
    /// public function, and should only be used to add pages to the
    /// PML4 page table. This function will call a private version that
    /// will parse through the different levels making sure the virtual
    /// address provided is valid.
    ///
    /// @expects virt_addr != 0;
    /// @ensures none
    ///
    /// @param virt_addr the virtual address to the page to add
    /// @return the resulting pte. Note that this pte is blank, and its
    ///     properties (like present) should be set by the caller
    ///
    gsl::not_null<page_table_entry_x64 *> add_page_x64(integer_pointer virt_addr);

    /// Remove Page
    ///
    /// Removes a page from the page table. Note that this function cleans
    /// up as it goes, removing empty page tables if they are detected. For
    /// this reason, this operation can be expensive if mapping / unmapping
    /// occurs side by side with addresses that are similar (page tables will
    /// be needlessly removed)
    ///
    /// @expects virt_addr != 0;
    /// @ensures none
    ///
    /// @param virt_addr the virtual address of the page to remove
    ///
    void remove_page_x64(integer_pointer virt_addr);

private:

    template<class T> std::unique_ptr<T> add_pte(pointer p);
    template<class T> std::unique_ptr<T> remove_pte();

    gsl::not_null<page_table_entry_x64 *> add_page_x64(integer_pointer virt_addr, integer_pointer bits);
    void remove_page_x64(integer_pointer virt_addr, integer_pointer bits);

    auto empty() const noexcept
    { return m_size == 0; }

private:

    gsl::span<integer_pointer> m_pt;
    std::unique_ptr<integer_pointer[]> m_pt_owner;

    size_type m_size;
    integer_pointer m_cr3_shadow;
    std::vector<std::unique_ptr<page_table_entry_x64>> m_ptes;

public:

    page_table_x64(page_table_x64 &&) noexcept = default;
    page_table_x64 &operator=(page_table_x64 &&) noexcept = default;

    page_table_x64(const page_table_x64 &) = delete;
    page_table_x64 &operator=(const page_table_x64 &) = delete;
};

#endif
