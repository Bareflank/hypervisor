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

#ifndef ROOT_PAGE_TABLE_X64_H
#define ROOT_PAGE_TABLE_X64_H

#include <gsl/gsl>

#include <memory.h>
#include <memory_manager/page_table_x64.h>

/// Root Page Tables
///
/// The VMM has to have a set of page tables for itself to map in memory
/// for itself, but also from other guests. This class represents the root
/// page tables that the VMM will use.
///
/// Note that this class does not flush the TLB when modifications are made.
/// This needs to be done manually. In general, this class should not be used
/// directly, but instead mapping should be done via a unique_map_ptr_x64.
///
class root_page_table_x64
{
public:

    using pointer = void *;
    using integer_pointer = uintptr_t;
    using attr_type = decltype(memory_descriptor::type);

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~root_page_table_x64() = default;

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class. Note that the root page table
    /// is constructed the first time this is executed, and thus should not
    /// be called until after the driver has provided the memory manager with
    /// all of the memory descriptors for the system, as virt to phys
    /// translations are needed.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    static root_page_table_x64 *instance() noexcept;

    /// Physical Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the physical address of the root page tables.
    ///
    virtual integer_pointer phys_addr();

    /// Map Page
    ///
    /// Adds a virtual to physical map into the root page table. Note that
    /// after this action is performed, the user must manually flush the
    /// TLB, otherwise the modification to the page tables will not take
    /// effect.
    ///
    /// @note for now, this always maps a page_size page
    ///
    /// @expects virt != 0
    /// @expects phys != 0
    /// @expects attr != 0
    /// @ensures none
    ///
    /// @param virt the desired virtual address
    /// @param phys to the physical address to map to virt
    /// @param attr how to map the page
    ///
    virtual void map(integer_pointer virt, integer_pointer phys, attr_type attr);

    /// Unmap
    ///
    /// Unmaps the provided virtual address from the root page tables. Note that
    /// after this action is performed, the user must manually flush the
    /// TLB, otherwise the modification to the page tables will not take
    /// effect.
    ///
    /// @expects virt != 0
    /// @ensures none
    ///
    /// @param virt the virtual address to unmap
    ///
    virtual void unmap(integer_pointer virt) noexcept;

private:

    root_page_table_x64() noexcept;

    gsl::not_null<page_table_entry_x64 *> add_page(integer_pointer virt);
    void remove_page(integer_pointer virt);

    void map_page(integer_pointer virt, integer_pointer phys, attr_type attr);
    void unmap_page(integer_pointer virt) noexcept;

private:

    std::unique_ptr<page_table_x64> m_root_pt;

public:

    root_page_table_x64(const root_page_table_x64 &) = delete;
    root_page_table_x64 &operator=(const root_page_table_x64 &) = delete;
};

/// Root Page Table Macro
///
/// The following macro can be used to quickly call the root page table as
/// this class will likely be called by a lot of code.
///
/// @expects
/// @ensures g_pt != nullptr
///
#define g_pt root_page_table_x64::instance()

#endif
