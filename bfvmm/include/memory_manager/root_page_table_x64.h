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

#ifndef ROOT_PAGE_TABLE_X64_H
#define ROOT_PAGE_TABLE_X64_H

#include <bfgsl.h>
#include <bfmemory.h>

#include <mutex>
#include <vector>

#include "pat_x64.h"
#include "mem_attr_x64.h"
#include "page_table_x64.h"

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_MEMORY_MANAGER
#ifdef SHARED_MEMORY_MANAGER
#define EXPORT_MEMORY_MANAGER EXPORT_SYM
#else
#define EXPORT_MEMORY_MANAGER IMPORT_SYM
#endif
#else
#define EXPORT_MEMORY_MANAGER
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

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
class EXPORT_MEMORY_MANAGER root_page_table_x64
{
public:

    using pointer = void *;                                                 ///< Pointer type
    using integer_pointer = uintptr_t;                                      ///< Integer pointer type
    using cr3_type = uint64_t;                                              ///< CR3 value type
    using attr_type = x64::memory_attr::attr_type;                          ///< Attribute type
    using size_type = size_t;                                               ///< Size type
    using memory_descriptor_list = page_table_x64::memory_descriptor_list;  ///< Memory descriptor list type

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param is_vmm true if this is the root page table for the VMM
    ///
    root_page_table_x64(bool is_vmm = false);

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~root_page_table_x64() = default;

    /// CR3
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the cr3 value associated with this root
    ///     page table
    ///
    virtual cr3_type cr3();

    /// Map (1 Gigabyte)
    ///
    /// Maps 1 gigabyte of memory in the page tables given a virtual address,
    /// the physical address and a set of attributes.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual address to map
    /// @param phys the physical address to map the virt address
    /// @param attr describes how to map the virt address
    ///
    virtual void map_1g(
        integer_pointer virt, integer_pointer phys, attr_type attr)
    { this->map_page(virt, phys, attr, x64::page_table::pdpt::size_bytes); }

    /// Map (2 Megabytes)
    ///
    /// Maps 1 gigabyte of memory in the page tables given a virtual address,
    /// the physical address and a set of attributes.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual address to map
    /// @param phys the physical address to map the virt address
    /// @param attr describes how to map the virt address
    ///
    virtual void map_2m(
        integer_pointer virt, integer_pointer phys, attr_type attr)
    { this->map_page(virt, phys, attr, x64::page_table::pd::size_bytes); }

    /// Map (1 Kilobytes)
    ///
    /// Maps 1 gigabyte of memory in the page tables given a virtual address,
    /// the physical address and a set of attributes.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual address to map
    /// @param phys the physical address to map the virt address
    /// @param attr describes how to map the virt address
    ///
    virtual void map_4k(
        integer_pointer virt, integer_pointer phys, attr_type attr)
    { this->map_page(virt, phys, attr, x64::page_table::pt::size_bytes); }

    /// Unmap
    ///
    /// Unmaps memory in the page tables give a virtual address.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual address to unmap
    ///
    virtual void unmap(integer_pointer virt) noexcept;

    /// Setup Identify Map (1g Granularity)
    ///
    /// Sets up an identify map in the page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_1g(
        integer_pointer saddr, integer_pointer eaddr);

    /// Setup Identify Map (2m Granularity)
    ///
    /// Sets up an identify map in the page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_2m(
        integer_pointer saddr, integer_pointer eaddr);

    /// Setup Identify Map (4k Granularity)
    ///
    /// Sets up an identify map in the page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_4k(
        integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (1g Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_1g function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_1g(
        integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (2m Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_2m function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_2m(
        integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (4k Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_4k function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_4k(
        integer_pointer saddr, integer_pointer eaddr);

    /// Virtual Address To Page Table Entry
    ///
    /// Locates the page table entry given a virtual
    /// address. The entry is guaranteed not to be null (or an exception is
    /// thrown). This function can be used to access a PTE, enabling the
    /// user to modify any part of the PTE as desired. It should be noted
    /// that the root page table owns the PTE. Unmapping a PTE
    /// invalidates the PTE returned by this function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual address to lookup
    /// @return the resulting PTE
    ///
    page_table_entry_x64 virt_to_pte(
        integer_pointer virt) const;

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
    memory_descriptor_list pt_to_mdl() const;

private:

    page_table_entry_x64 add_page(integer_pointer virt, size_type size);

    void map_page(integer_pointer virt, integer_pointer phys, attr_type attr, size_type size);
    void unmap_page(integer_pointer virt) noexcept;

private:

    bool m_is_vmm{false};

    integer_pointer m_cr3{0};
    std::unique_ptr<page_table_x64> m_pt;

    mutable std::mutex m_mutex;

public:

    /// @cond

    root_page_table_x64(root_page_table_x64 &&) noexcept = delete;
    root_page_table_x64 &operator=(root_page_table_x64 &&) noexcept = delete;

    root_page_table_x64(const root_page_table_x64 &) = delete;
    root_page_table_x64 &operator=(const root_page_table_x64 &) = delete;

    /// @endcond
};

/// Root Page Table
///
/// Returns the VMM's root page table.
///
/// @expects
/// @ensures ret != nullptr
///
EXPORT_MEMORY_MANAGER root_page_table_x64 *root_pt() noexcept;

/// Root Page Table Macro
///
/// The following macro can be used to quickly call the root page table as
/// this class will likely be called by a lot of code.
///
/// @expects
/// @ensures ret != nullptr
///
#define g_pt root_pt()

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
