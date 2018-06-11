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

#ifndef MMAP_CR3_X64_H
#define MMAP_CR3_X64_H

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC system_header
#endif

#include <vector>

#include <bfdebug.h>
#include <intrinsics.h>

#include <memory_manager/memory_manager.h>

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
// Definition
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace x64
{
namespace cr3
{

/// CR3 Memory Map
///
/// This class constructs a set of CR3 page tables, and provides the needed
/// APIs to map virtual to physical addresses to these pages. For more
/// information on how CR3 page tables work, please see the Intel SDM. This
/// implementation attempts to map directly to the SDM text.
///
class EXPORT_MEMORY_MANAGER mmap
{

public:

    using phys_addr_t = uintptr_t;                      ///< Phys Address Type (as Int)
    using virt_addr_t = uintptr_t *;                    ///< Virt Address Type (as Ptr)
    using size_type = size_t;                           ///< Size Type
    using entry_type = uintptr_t;                       ///< Entry Type
    using index_type = std::ptrdiff_t;                  ///< Index Type

    // @cond

    enum class attr_type {
        read_write,
        read_execute
    };

    struct pair {
        virt_addr_t virt_addr;
        phys_addr_t phys_addr;
    };

    // @endcond

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    mmap() :
        m_pml4{this->allocate(::x64::pml4::num_entries)}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mmap()
    {
        for (auto pml4i = 0; pml4i < ::x64::pml4::num_entries; pml4i++) {
            auto &entry = m_pml4.virt_addr[pml4i];

            if (entry == 0) {
                continue;
            }

            this->clear_pdpt(pml4i);
        }

        this->free(m_pml4.virt_addr);
    }

    /// CR3
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into CR3
    ///
    uintptr_t cr3()
    { return m_pml4.phys_addr; }

    /// PAT
    ///
    /// @note For now, the mmap functionality can only map using write-back.
    ///     For this reason, we currently set each PAT index to write-back
    ///     to prevent any bugs with caching.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into the PAT
    ///
    uint64_t pat()
    { return 0x0606060606060606; }

    /// Map 1g Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_1g(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        return this->map_pdpte(virt_addr, phys_addr, attr);
    }

    /// Map 1g Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_1g(uintptr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    { return map_1g(reinterpret_cast<virt_addr_t>(virt_addr), phys_addr, attr); }

    /// Map 2m Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_2m(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        this->map_pd(::x64::pdpt::index(virt_addr));

        return this->map_pde(virt_addr, phys_addr, attr);
    }

    /// Map 2m Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_2m(uintptr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    { return map_2m(reinterpret_cast<virt_addr_t>(virt_addr), phys_addr, attr); }

    /// Map 4k Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_4k(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        this->map_pd(::x64::pdpt::index(virt_addr));
        this->map_pt(::x64::pd::index(virt_addr));

        return this->map_pte(virt_addr, phys_addr, attr);
    }

    /// Map 4k Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    ///
    entry_type &
    map_4k(uintptr_t virt_addr, phys_addr_t phys_addr, attr_type attr = attr_type::read_write)
    { return map_4k(reinterpret_cast<virt_addr_t>(virt_addr), phys_addr, attr); }

    /// Unmap Virtual Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void
    unmap(virt_addr_t virt_addr)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr[::x64::pdpt::index(virt_addr)];

        if (pdpte == 0) {
            return;
        }

        if (::x64::pdpt::entry::ps::is_enabled(pdpte)) {
            pdpte = 0;
            return;
        }

        this->map_pd(::x64::pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr[::x64::pd::index(virt_addr)];

        if (pde == 0) {
            return;
        }

        if (::x64::pd::entry::ps::is_enabled(pde)) {
            pde = 0;
            return;
        }

        this->map_pt(::x64::pd::index(virt_addr));
        m_pt.virt_addr[::x64::pt::index(virt_addr)] = 0;
    }

    /// Unmap Virtual Address
    ///
    /// @note This function does not release any page tables associated with
    ///     mapping being unmapped by this function. As a result, if you need
    ///     to cleanup memory, or reconfigure a mapping (e.g. 2m to 4k), you
    ///     must also execute release()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void unmap(uintptr_t virt_addr)
    { unmap(reinterpret_cast<virt_addr_t>(virt_addr)); }

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void
    release(virt_addr_t virt_addr)
    {
        if (this->release_pdpte(virt_addr)) {
            m_pml4.virt_addr[::x64::pml4::index(virt_addr)] = 0;
        }
    }

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void release(uintptr_t virt_addr)
    { release(reinterpret_cast<virt_addr_t>(virt_addr)); }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    phys_addr_t
    virt_to_phys(virt_addr_t virt_addr)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr[::x64::pdpt::index(virt_addr)];

        if (::x64::pdpt::entry::ps::is_enabled(pdpte)) {
            return ::x64::pdpt::entry::phys_addr::get(pdpte);
        }

        this->map_pd(::x64::pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr[::x64::pd::index(virt_addr)];

        if (::x64::pd::entry::ps::is_enabled(pde)) {
            return ::x64::pd::entry::phys_addr::get(pde);
        }

        this->map_pt(::x64::pd::index(virt_addr));
        auto &pte = m_pt.virt_addr[::x64::pt::index(virt_addr)];

        return ::x64::pt::entry::phys_addr::get(pte);
    }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    phys_addr_t virt_to_phys(uintptr_t virt_addr)
    { return virt_to_phys(reinterpret_cast<virt_addr_t>(virt_addr)); }

    /// Memory Descriptor List
    ///
    /// @note The returned memory descriptor list does not describe memory
    /// mapped by the page tables, but rather the memory used to hold the
    /// page tables themselves.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return List of memory descriptors that describe the page tables
    ///
    const std::vector<pair> &
    mdl() const
    { return m_mdl; }

private:

    pair
    allocate(size_type num_entries)
    {
        auto virt_addr = static_cast<virt_addr_t>(alloc_page());
        auto phys_addr = g_mm->virtptr_to_physint(virt_addr);

        memset(virt_addr, 0, BAREFLANK_PAGE_SIZE);

        m_mdl.push_back({virt_addr, phys_addr});
        return {virt_addr, phys_addr};
    }

    void
    free(virt_addr_t virt_addr)
    {
        for (auto iter = m_mdl.begin(); iter != m_mdl.end(); ++iter) {
            if (iter->virt_addr == virt_addr) {
                m_mdl.erase(iter);
                break;
            }
        }

        free_page(virt_addr);
    }

private:

    void
    map_pdpt(index_type pml4i)
    {
        auto &entry = m_pml4.virt_addr[pml4i];

        if (entry != 0) {
            auto phys_addr = ::x64::pml4::entry::phys_addr::get(entry);

            if (m_pdpt.phys_addr == phys_addr) {
                return;
            }

            m_pdpt = {
                reinterpret_cast<virt_addr_t>(g_mm->physint_to_virtptr(phys_addr)),
                phys_addr
            };

            return;
        }

        m_pdpt = this->allocate(::x64::pdpt::num_entries);

        ::x64::pml4::entry::phys_addr::set(entry, m_pdpt.phys_addr);
        ::x64::pml4::entry::present::enable(entry);
        ::x64::pml4::entry::rw::enable(entry);
    }

    void
    map_pd(index_type pdpti)
    {
        auto &entry = m_pdpt.virt_addr[pdpti];

        if (entry != 0) {
            auto phys_addr = ::x64::pdpt::entry::phys_addr::get(entry);

            if (m_pd.phys_addr == phys_addr) {
                return;
            }

            m_pd = {
                reinterpret_cast<virt_addr_t>(g_mm->physint_to_virtptr(phys_addr)),
                phys_addr
            };

            return;
        }

        m_pd = this->allocate(::x64::pd::num_entries);

        ::x64::pdpt::entry::phys_addr::set(entry, m_pd.phys_addr);
        ::x64::pdpt::entry::present::enable(entry);
        ::x64::pdpt::entry::rw::enable(entry);
    }

    void
    map_pt(index_type pdi)
    {
        auto &entry = m_pd.virt_addr[pdi];

        if (entry != 0) {
            auto phys_addr = ::x64::pd::entry::phys_addr::get(entry);

            if (m_pt.phys_addr == phys_addr) {
                return;
            }

            m_pt = {
                reinterpret_cast<virt_addr_t>(g_mm->physint_to_virtptr(phys_addr)),
                phys_addr
            };

            return;
        }

        m_pt = this->allocate(::x64::pt::num_entries);

        ::x64::pd::entry::phys_addr::set(entry, m_pt.phys_addr);
        ::x64::pd::entry::present::enable(entry);
        ::x64::pd::entry::rw::enable(entry);
    }

    void
    clear_pdpt(index_type pml4i)
    {
        this->map_pdpt(pml4i);

        for (auto pdpti = 0; pdpti < ::x64::pdpt::num_entries; pdpti++) {
            auto &entry = m_pdpt.virt_addr[pdpti];

            if (entry == 0) {
                continue;
            }

            if (::x64::pdpt::entry::ps::is_disabled(entry)) {
                this->clear_pd(pdpti);
            }

            entry = 0;
        }

        this->free(m_pdpt.virt_addr);
        m_pdpt = {};
    }

    void
    clear_pd(index_type pdpti)
    {
        this->map_pd(pdpti);

        for (auto pdi = 0; pdi < ::x64::pd::num_entries; pdi++) {
            auto &entry = m_pd.virt_addr[pdi];

            if (entry == 0) {
                continue;
            }

            if (::x64::pd::entry::ps::is_disabled(entry)) {
                this->clear_pt(pdi);
            }

            entry = 0;
        }

        this->free(m_pd.virt_addr);
        m_pd = {};
    }

    void
    clear_pt(index_type pdi)
    {
        this->map_pt(pdi);

        this->free(m_pt.virt_addr);
        m_pt = {};
    }

    entry_type &
    map_pdpte(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr)
    {
        auto &entry = m_pdpt.virt_addr[::x64::pdpt::index(virt_addr)];

        if (entry != 0) {
            throw std::runtime_error(
                "map_pdpte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::x64::pdpt::entry::phys_addr::set(entry, phys_addr);
        ::x64::pdpt::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                ::x64::pdpt::entry::rw::enable(entry);
                ::x64::pdpt::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                ::x64::pdpt::entry::rw::disable(entry);
                ::x64::pdpt::entry::xd::disable(entry);
                break;
        };

        ::x64::pdpt::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pde(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr)
    {
        auto &entry = m_pd.virt_addr[::x64::pd::index(virt_addr)];

        if (entry != 0) {
            throw std::runtime_error(
                "map_pde: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::x64::pd::entry::phys_addr::set(entry, phys_addr);
        ::x64::pd::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                ::x64::pd::entry::rw::enable(entry);
                ::x64::pd::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                ::x64::pd::entry::rw::disable(entry);
                ::x64::pd::entry::xd::disable(entry);
                break;
        };

        ::x64::pd::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pte(virt_addr_t virt_addr, phys_addr_t phys_addr, attr_type attr)
    {
        auto &entry = m_pt.virt_addr[::x64::pt::index(virt_addr)];

        if (entry != 0) {
            throw std::runtime_error(
                "map_pte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::x64::pt::entry::phys_addr::set(entry, phys_addr);
        ::x64::pt::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                ::x64::pt::entry::rw::enable(entry);
                ::x64::pt::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                ::x64::pt::entry::rw::disable(entry);
                ::x64::pt::entry::xd::disable(entry);
                break;
        };

        return entry;
    }

    bool
    release_pdpte(virt_addr_t virt_addr)
    {
        this->map_pdpt(::x64::pml4::index(virt_addr));
        auto &entry = m_pdpt.virt_addr[::x64::pdpt::index(virt_addr)];

        if (::x64::pdpt::entry::ps::is_disabled(entry)) {
            if (!this->release_pde(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdpti = 0; pdpti < ::x64::pdpt::num_entries; pdpti++) {
            if (m_pdpt.virt_addr[pdpti] != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pdpt.virt_addr);
            return true;
        }

        return false;
    }

    bool
    release_pde(virt_addr_t virt_addr)
    {
        this->map_pd(::x64::pdpt::index(virt_addr));
        auto &entry = m_pd.virt_addr[::x64::pd::index(virt_addr)];

        if (::x64::pd::entry::ps::is_disabled(entry)) {
            if (!this->release_pte(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdi = 0; pdi < ::x64::pd::num_entries; pdi++) {
            if (m_pd.virt_addr[pdi] != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pd.virt_addr);
            return true;
        }

        return false;
    }

    bool
    release_pte(virt_addr_t virt_addr)
    {
        this->map_pt(::x64::pd::index(virt_addr));
        m_pt.virt_addr[::x64::pt::index(virt_addr)] = 0;

        auto empty = true;
        for (auto pti = 0; pti < ::x64::pt::num_entries; pti++) {
            if (m_pt.virt_addr[pti] != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pt.virt_addr);
            return true;
        }

        return false;
    }

private:

    std::vector<pair> m_mdl;

    pair m_pml4;
    pair m_pdpt;
    pair m_pd;
    pair m_pt;

public:

    /// @cond

    mmap(mmap &&) = default;
    mmap &operator=(mmap &&) = default;

    mmap(const mmap &) = delete;
    mmap &operator=(const mmap &) = delete;

    /// @endcond
};

}
}
}

#endif
