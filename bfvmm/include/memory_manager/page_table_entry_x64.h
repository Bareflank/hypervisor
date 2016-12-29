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

#include <gsl/gsl>

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace x64
{
namespace page_table
{
    constexpr const auto num_entries = 512UL;
    constexpr const auto num_bytes = num_entries * sizeof(uintptr_t);

    template<class T, class F> auto index(const T virt, const F from)
    { return (virt & ((0x1FFULL) << from)) >> from; }

    namespace pml4
    {
        constexpr const auto from = 39U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x8000000000UL;
    }

    namespace pdpt
    {
        constexpr const auto from = 30U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x40000000UL;
    }

    namespace pd
    {
        constexpr const auto from = 21U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x200000UL;
    }

    namespace pt
    {
        constexpr const auto from = 12U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x1000UL;
    }
}
}

// *INDENT-ON*

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

class page_table_entry_x64
{
public:

    using pointer = uintptr_t *;
    using integer_pointer = uintptr_t;
    using pat_index_type = uint64_t;

    /// PTE Constructor
    ///
    /// @expects pte != nullptr
    /// @ensures none
    ///
    /// @param pte the pte that this page table entry encapsulates.
    ///
    page_table_entry_x64(gsl::not_null<pointer> pte) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~page_table_entry_x64() = default;

    /// Present
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is present, false otherwise
    ///
    bool present() const noexcept;

    /// Set Present
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is present, false otherwise
    ///
    void set_present(bool enabled) noexcept;

    /// Read / Write
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is read/write, false otherwise
    ///
    bool rw() const noexcept;

    /// Set Read / Write
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is read / write, false otherwise
    ///
    void set_rw(bool enabled) noexcept;

    /// User / Supervisor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is visible to userspace, false otherwise
    ///
    bool us() const noexcept;

    /// Set User / Supervisor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is visible to userspace, false
    ///     otherwise
    ///
    void set_us(bool enabled) noexcept;

    /// Write-Through
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is write-through, false otherwise
    ///
    bool pwt() const noexcept;

    /// Set Write-Through
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is write-through, false otherwise
    ///
    void set_pwt(bool enabled) noexcept;

    /// Cache Disable
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry's cache is disabled, false otherwise
    ///
    bool pcd() const noexcept;

    /// Set Cache Disable
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry's cache is disabled, false
    ///     otherwise
    ///
    void set_pcd(bool enabled) noexcept;

    /// Accessed
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry has been accessed, false otherwise
    ///
    bool accessed() const noexcept;

    /// Set Accessed
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry has been accessed, false
    ///     otherwise
    ///
    void set_accessed(bool enabled) noexcept;

    /// Dirty
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is dirty, false otherwise
    ///
    bool dirty() const noexcept;

    /// Set Dirty
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is dirty, false otherwise
    ///
    void set_dirty(bool enabled) noexcept;

    /// Page Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is a page, false otherwise
    ///
    bool ps() const noexcept;

    /// Set Page Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is a page, false
    ///     otherwise
    ///
    void set_ps(bool enabled) noexcept;

    /// PAT (4k)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry uses the PAT, false otherwise
    ///
    bool pat_4k() const noexcept;

    /// Set PAT (4k)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry uses the PAT, false
    ///     otherwise
    ///
    void set_pat_4k(bool enabled) noexcept;

    /// PAT (Large)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry uses the PAT, false otherwise
    ///
    bool pat_large() const noexcept;

    /// Set PAT (Large)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry uses the PAT, false
    ///     otherwise
    ///
    void set_pat_large(bool enabled) noexcept;

    /// Global
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is global, false otherwise
    ///
    bool global() const noexcept;

    /// Set Global
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is global, false otherwise
    ///
    void set_global(bool enabled) noexcept;

    /// Physical Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the physical address of the entry
    ///
    integer_pointer phys_addr() const noexcept;

    /// Set Physical Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the physical address of the entry
    ///
    void set_phys_addr(integer_pointer addr) noexcept;

    /// NX
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is not executable, false otherwise
    ///
    bool nx() const noexcept;

    /// Set NX
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is not executable, false otherwise
    ///
    void set_nx(bool enabled) noexcept;

    /// PAT Index (4k)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return combines PWT, PCD and PAT to return the PAT index
    ///
    pat_index_type pat_index_4k() const noexcept;

    /// Set PAT Index (4k)
    ///
    /// @expects index >= 0 && index < 8
    /// @ensures none
    ///
    /// @param index the index of the PAT to set
    ///
    void set_pat_index_4k(pat_index_type index);

    /// PAT Index (Large)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return combines PWT, PCD and PAT to return the PAT index
    ///
    pat_index_type pat_index_large() const noexcept;

    /// Set PAT Index (Large)
    ///
    /// @expects index >= 0 && index < 8
    /// @ensures none
    ///
    /// @param index the index of the PAT to set
    ///
    void set_pat_index_large(pat_index_type index);

    /// Clear PTE
    ///
    /// @expects none
    /// @ensures none
    ///
    void clear() noexcept;

private:

    pointer m_pte;

public:

    page_table_entry_x64(page_table_entry_x64 &&) noexcept = default;
    page_table_entry_x64 &operator=(page_table_entry_x64 &&) noexcept = default;

    page_table_entry_x64(const page_table_entry_x64 &) = delete;
    page_table_entry_x64 &operator=(const page_table_entry_x64 &) = delete;
};

#endif
