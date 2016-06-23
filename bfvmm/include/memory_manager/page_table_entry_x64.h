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

#ifndef PAGE_TABLE_ENTRY_X64_H
#define PAGE_TABLE_ENTRY_X64_H

#include <stdint.h>

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define PT_SIZE 512
#define PTE_SIZE sizeof(uintptr_t)
#define BITS_PER_INDEX 9
#define INDEX_MASK 0x1FFULL
#define PML4_INDEX 39
#define PT_INDEX 12
#define PTE_PHYS_ADDR_MASK 0x000FFFFFFFFFF000

#define PTE_FLAGS_P (0x1ULL << 0)
#define PTE_FLAGS_RW (0x1ULL << 1)
#define PTE_FLAGS_US (0x1ULL << 2)
#define PTE_FLAGS_PWT (0x1ULL << 3)
#define PTE_FLAGS_PCD (0x1ULL << 4)
#define PTE_FLAGS_A (0x1ULL << 5)
#define PTE_FLAGS_D (0x1ULL << 6)
#define PTE_FLAGS_PAT (0x1ULL << 7)
#define PTE_FLAGS_G (0x1ULL << 8)
#define PTE_FLAGS_NX (0x1ULL << 63)

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

class page_table_entry_x64
{
public:

    /// Default Constructor
    ///
    /// @param entry the entry that this page table entry encapsulates.
    page_table_entry_x64(uintptr_t *entry = nullptr) noexcept;

    /// Destructor
    ///
    virtual ~page_table_entry_x64() {}

    /// Present
    ///
    /// @return true if this entry is present, false otherwise
    ///
    virtual bool present() const noexcept;

    /// Set Present
    ///
    /// @param enabled true if the entry is present, false otherwise
    ///
    virtual void set_present(bool enabled) noexcept;

    /// Read / Write
    ///
    /// @return true if this entry is read/write, false otherwise
    ///
    virtual bool rw() const noexcept;

    /// Set Read / Write
    ///
    /// @param enabled true if the entry is read / write, false otherwise
    ///
    virtual void set_rw(bool enabled) noexcept;

    /// User / Supervisor
    ///
    /// @return true if this entry is visible to userspace, false otherwise
    ///
    virtual bool us() const noexcept;

    /// Set User / Supervisor
    ///
    /// @param enabled true if the entry is visible to userspace, false
    ///     otherwise
    ///
    virtual void set_us(bool enabled) noexcept;

    /// Write-Through
    ///
    /// @return true if this entry is write-through, false otherwise
    ///
    virtual bool pwt() const noexcept;

    /// Set Write-Through
    ///
    /// @param enabled true if the entry is write-through, false otherwise
    ///
    virtual void set_pwt(bool enabled) noexcept;

    /// Cache Disable
    ///
    /// @return true if this entry's cache is disabled, false otherwise
    ///
    virtual bool pcd() const noexcept;

    /// Set Cache Disable
    ///
    /// @param enabled true if the entry's cache is disabled, false
    ///     otherwise
    ///
    virtual void set_pcd(bool enabled) noexcept;

    /// Accessed
    ///
    /// @return true if this entry has been accessed, false otherwise
    ///
    virtual bool accessed() const noexcept;

    /// Set Accessed
    ///
    /// @param enabled true if the entry has been accessed, false
    ///     otherwise
    ///
    virtual void set_accessed(bool enabled) noexcept;

    /// Dirty
    ///
    /// @return true if this entry is dirty, false otherwise
    ///
    virtual bool dirty() const noexcept;

    /// Set Dirty
    ///
    /// @param enabled true if the entry is dirty, false otherwise
    ///
    virtual void set_dirty(bool enabled) noexcept;

    /// PAT
    ///
    /// @return true if this entry uses the PAT, false otherwise
    ///
    virtual bool pat() const noexcept;

    /// Set PAT
    ///
    /// @param enabled true if the entry uses the PAT, false
    ///     otherwise
    ///
    virtual void set_pat(bool enabled) noexcept;

    /// Global
    ///
    /// @return true if this entry is global, false otherwise
    ///
    virtual bool global() const noexcept;

    /// Set Global
    ///
    /// @param enabled true if the entry is global, false otherwise
    ///
    virtual void set_global(bool enabled) noexcept;

    /// Physical Address
    ///
    /// @return the physical address of the entry
    ///
    virtual uintptr_t phys_addr() const noexcept;

    /// Set Physical Address
    ///
    /// @param addr the physical address of the entry
    ///
    virtual void set_phys_addr(uintptr_t addr) noexcept;

    /// NX
    ///
    /// @return true if this entry is not executable, false otherwise
    ///
    virtual bool nx() const noexcept;

    /// Set NX
    ///
    /// @param enabled true if the entry is not executable, false otherwise
    ///
    virtual void set_nx(bool enabled) noexcept;

private:

    uintptr_t *m_entry;
};

#endif
