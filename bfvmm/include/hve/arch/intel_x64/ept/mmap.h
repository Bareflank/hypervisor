//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef EPT_MMAP_INTEL_X64_H
#define EPT_MMAP_INTEL_X64_H

#include <mutex>

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfupperlower.h>

#include <intrinsics.h>
#include "../../../../memory_manager/memory_manager.h"

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64::ept
{

/// EPT Memory Map
///
/// This class constructs a set of EPT page tables, and provides the needed
/// APIs to map virtual to physical addresses to these pages. For more
/// information on how EPT page tables work, please see the Intel SDM. This
/// implementation attempts to map directly to the SDM text.
///
class mmap
{

public:

    using phys_addr_t = uintptr_t;                      ///< Phys Address Type (as Int)
    using virt_addr_t = uintptr_t;                      ///< Virt Address Type (as Ptr)
    using size_type = size_t;                           ///< Size Type
    using entry_type = uintptr_t;                       ///< Entry Type
    using index_type = std::ptrdiff_t;                  ///< Index Type

    // @cond

    enum class attr_type {
        none,
        read_only,
        write_only,
        execute_only,
        read_write,
        read_execute,
        read_write_execute
    };

    enum class memory_type {
        uncacheable = 0,
        write_combining = 1,
        write_through = 4,
        write_protected = 5,
        write_back = 6
    };

    struct pair {
        gsl::span<virt_addr_t> virt_addr{};
        phys_addr_t phys_addr{};
    };

    // @endcond

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    mmap() :
        m_pml4{allocate_span(::intel_x64::ept::pml4::num_entries), 0}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mmap()
    {
        using namespace ::intel_x64::ept;

        for (auto pml4i = 0; pml4i < pml4::num_entries; pml4i++) {
            auto &entry = m_pml4.virt_addr.at(pml4i);

            if (entry == 0) {
                continue;
            }

            this->clear_pdpt(pml4i);
        }

        free_page(m_pml4.virt_addr.data());
    }

    /// EPTP
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into EPTP
    ///
    uintptr_t eptp()
    {
        std::lock_guard lock(m_mutex);

        if (m_pml4.phys_addr == 0) {
            m_pml4.phys_addr = g_mm->virtptr_to_physint(m_pml4.virt_addr.data());
        }

        return m_pml4.phys_addr;
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_1g(
        void *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        expects(bfn::lower(virt_addr, pdpt::from) == 0);
        expects(bfn::lower(phys_addr, pdpt::from) == 0);

        this->map_pdpt(pml4::index(virt_addr));
        return this->map_pdpte(virt_addr, phys_addr, attr, cache);
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_1g(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_1g(reinterpret_cast<void *>(virt_addr), phys_addr, attr, cache);
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_2m(
        void *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        expects(bfn::lower(virt_addr, pd::from) == 0);
        expects(bfn::lower(phys_addr, pd::from) == 0);

        this->map_pdpt(pml4::index(virt_addr));
        this->map_pd(pdpt::index(virt_addr));

        return this->map_pde(virt_addr, phys_addr, attr, cache);
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_2m(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_2m(reinterpret_cast<void *>(virt_addr), phys_addr, attr, cache);
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_4k(
        void *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        expects(bfn::lower(virt_addr, pt::from) == 0);
        expects(bfn::lower(phys_addr, pt::from) == 0);

        this->map_pdpt(pml4::index(virt_addr));
        this->map_pd(pdpt::index(virt_addr));
        this->map_pt(pd::index(virt_addr));

        return this->map_pte(virt_addr, phys_addr, attr, cache);
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
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_4k(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_4k(reinterpret_cast<void *>(virt_addr), phys_addr, attr, cache);
    }

    /// Unmap Virtual Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    /// @return the from for the address that was unmapped
    ///
    uintptr_t
    unmap(void *virt_addr)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        this->map_pdpt(pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (pdpte == 0) {
            return ::intel_x64::ept::pdpt::from;
        }

        if (pdpt::entry::ps::is_enabled(pdpte)) {
            pdpte = 0;
            return ::intel_x64::ept::pdpt::from;
        }

        this->map_pd(pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr.at(pd::index(virt_addr));

        if (pde == 0) {
            return ::intel_x64::ept::pd::from;
        }

        if (pd::entry::ps::is_enabled(pde)) {
            pde = 0;
            return ::intel_x64::ept::pd::from;
        }

        this->map_pt(pd::index(virt_addr));
        m_pt.virt_addr.at(pt::index(virt_addr)) = 0;

        return ::intel_x64::ept::pt::from;
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
    inline void unmap(virt_addr_t virt_addr)
    { unmap(reinterpret_cast<void *>(virt_addr)); }

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
    release(void *virt_addr)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        if (this->release_pdpte(virt_addr)) {
            m_pml4.virt_addr.at(pml4::index(virt_addr)) = 0;
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
    inline void release(virt_addr_t virt_addr)
    { release(reinterpret_cast<void *>(virt_addr)); }

    /// Virtual Address to Entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return returns entry for the map
    ///
    std::pair<std::reference_wrapper<entry_type>, uintptr_t>
    entry(void *virt_addr)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        this->map_pdpt(pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("entry: pdpte not mapped");
        }

        if (pdpt::entry::ps::is_enabled(pdpte)) {
            return {pdpte, pdpt::from};
        }

        this->map_pd(pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr.at(pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("entry: pde not mapped");
        }

        if (pd::entry::ps::is_enabled(pde)) {
            return {pde, pd::from};
        }

        this->map_pt(pd::index(virt_addr));
        auto &pte = m_pt.virt_addr.at(pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("entry: pte not mapped");
        }

        return {pte, pt::from};
    }

    /// Virtual Address to Entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return returns entry for the map
    ///
    inline std::pair<std::reference_wrapper<entry_type>, uintptr_t>
    entry(virt_addr_t virt_addr)
    { return entry(reinterpret_cast<void *>(virt_addr)); }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    inline std::pair<uintptr_t, uintptr_t> virt_to_phys(void *virt_addr)
    { return virt_to_phys(reinterpret_cast<uintptr_t>(virt_addr)); }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    std::pair<uintptr_t, uintptr_t>
    virt_to_phys(virt_addr_t virt_addr)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        this->map_pdpt(pml4::index(virt_addr));
        auto pdpte = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("virt_to_phys: pdpte not mapped");
        }

        if (pdpt::entry::ps::is_enabled(pdpte)) {
            return {
                pdpt::entry::phys_addr::get(pdpte) | bfn::lower(virt_addr, pdpt::from),
                pdpt::from
            };
        }

        this->map_pd(pdpt::index(virt_addr));
        auto pde = m_pd.virt_addr.at(pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("virt_to_phys: pde not mapped");
        }

        if (pd::entry::ps::is_enabled(pde)) {
            return {
                pd::entry::phys_addr::get(pde) | bfn::lower(virt_addr, pd::from),
                pd::from
            };
        }

        this->map_pt(pd::index(virt_addr));
        auto pte = m_pt.virt_addr.at(pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("virt_to_phys: pte not mapped");
        }

        return {
            pt::entry::phys_addr::get(pte) | bfn::lower(virt_addr, pt::from),
            pt::from
        };
    }

    /// Virtual Address to From
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns page size of the mapping (i.e. from)
    ///
    uintptr_t
    from(void *virt_addr)
    {
        std::lock_guard lock(m_mutex);
        using namespace ::intel_x64::ept;

        this->map_pdpt(pml4::index(virt_addr));
        auto pdpte = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("from: pdpte not mapped");
        }

        if (pdpt::entry::ps::is_enabled(pdpte)) {
            return pdpt::from;
        }

        this->map_pd(pdpt::index(virt_addr));
        auto pde = m_pd.virt_addr.at(pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("from: pde not mapped");
        }

        if (pd::entry::ps::is_enabled(pde)) {
            return pd::from;
        }

        this->map_pt(pd::index(virt_addr));
        auto pte = m_pt.virt_addr.at(pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("from: pte not mapped");
        }

        return pt::from;
    }

    /// Virtual Address to From
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns page size of the mapping (i.e. from)
    ///
    inline uintptr_t from(virt_addr_t virt_addr)
    { return from(reinterpret_cast<void *>(virt_addr)); }

    /// Is 1g
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 1g page,
    ///     false otherwise
    ///
    inline auto is_1g(void *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pdpt::from; }

    /// Is 1g
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 1g page,
    ///     false otherwise
    ///
    inline auto is_1g(virt_addr_t virt_addr)
    { return is_1g(reinterpret_cast<void *>(virt_addr)); }

    /// Is 2m
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 2m page,
    ///     false otherwise
    ///
    inline auto is_2m(void *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pd::from; }

    /// Is 2m
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 2m page,
    ///     false otherwise
    ///
    inline auto is_2m(virt_addr_t virt_addr)
    { return is_2m(reinterpret_cast<void *>(virt_addr)); }

    /// Is 4k
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 4k page,
    ///     false otherwise
    ///
    inline auto is_4k(void *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pt::from; }

    /// Is 4k
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 4k page,
    ///     false otherwise
    ///
    inline auto is_4k(virt_addr_t virt_addr)
    { return is_4k(reinterpret_cast<void *>(virt_addr)); }

private:

    gsl::span<virt_addr_t>
    allocate_span(size_type num_entries)
    {
        return
            gsl::make_span(
                static_cast<virt_addr_t *>(alloc_page()),
                num_entries
            );
    }

    pair
    allocate(size_type num_entries)
    {
        auto span =
            gsl::make_span(
                static_cast<virt_addr_t *>(alloc_page()),
                num_entries
            );

        pair ptrs = {
            span,
            g_mm->virtptr_to_physint(
                span.data()
            )
        };

        return ptrs;
    }

    void
    free(const gsl::span<virt_addr_t> &virt_addr)
    { free_page(virt_addr.data()); }

private:

    pair
    phys_to_pair(phys_addr_t phys_addr, size_type num_entries)
    {
        auto virt_addr =
            static_cast<virt_addr_t *>(
                g_mm->physint_to_virtptr(phys_addr)
            );

        return {
            gsl::make_span<virt_addr_t>(virt_addr, num_entries),
            phys_addr
        };
    }

    void
    map_pdpt(index_type pml4i)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pml4.virt_addr.at(pml4i);

        if (entry != 0) {
            auto phys_addr = pml4::entry::phys_addr::get(entry);

            if (m_pdpt.phys_addr == phys_addr) {
                return;
            }

            m_pdpt = phys_to_pair(phys_addr, pdpt::num_entries);
            return;
        }

        m_pdpt = this->allocate(pdpt::num_entries);

        pml4::entry::phys_addr::set(entry, m_pdpt.phys_addr);
        pml4::entry::read_access::enable(entry);
        pml4::entry::write_access::enable(entry);
        pml4::entry::execute_access::enable(entry);
    }

    void
    map_pd(index_type pdpti)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pdpt.virt_addr.at(pdpti);

        if (entry != 0) {
            auto phys_addr = pdpt::entry::phys_addr::get(entry);

            if (m_pd.phys_addr == phys_addr) {
                return;
            }

            m_pd = phys_to_pair(phys_addr, pd::num_entries);
            return;
        }

        m_pd = this->allocate(pd::num_entries);

        pdpt::entry::phys_addr::set(entry, m_pd.phys_addr);
        pdpt::entry::read_access::enable(entry);
        pdpt::entry::write_access::enable(entry);
        pdpt::entry::execute_access::enable(entry);
    }

    void
    map_pt(index_type pdi)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pd.virt_addr.at(pdi);

        if (entry != 0) {
            auto phys_addr = pd::entry::phys_addr::get(entry);

            if (m_pt.phys_addr == phys_addr) {
                return;
            }

            m_pt = phys_to_pair(phys_addr, pt::num_entries);
            return;
        }

        m_pt = this->allocate(pt::num_entries);

        pd::entry::phys_addr::set(entry, m_pt.phys_addr);
        pd::entry::read_access::enable(entry);
        pd::entry::write_access::enable(entry);
        pd::entry::execute_access::enable(entry);
    }

    void
    clear_pdpt(index_type pml4i)
    {
        using namespace ::intel_x64::ept;
        this->map_pdpt(pml4i);

        for (auto pdpti = 0; pdpti < pdpt::num_entries; pdpti++) {
            auto &entry = m_pdpt.virt_addr.at(pdpti);

            if (entry == 0) {
                continue;
            }

            if (pdpt::entry::ps::is_disabled(entry)) {
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
        using namespace ::intel_x64::ept;
        this->map_pd(pdpti);

        for (auto pdi = 0; pdi < pd::num_entries; pdi++) {
            auto &entry = m_pd.virt_addr.at(pdi);

            if (entry == 0) {
                continue;
            }

            if (pd::entry::ps::is_disabled(entry)) {
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
    map_pdpte(
        void *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pdpte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pdpt::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                pdpt::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                pdpt::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                pdpt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                pdpt::entry::read_access::enable(entry);
                pdpt::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                pdpt::entry::read_access::enable(entry);
                pdpt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                pdpt::entry::read_access::enable(entry);
                pdpt::entry::write_access::enable(entry);
                pdpt::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pdpt::entry::memory_type::set(
                    entry,
                    pdpt::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                pdpt::entry::memory_type::set(
                    entry,
                    pdpt::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                pdpt::entry::memory_type::set(
                    entry,
                    pdpt::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                pdpt::entry::memory_type::set(
                    entry,
                    pdpt::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                pdpt::entry::memory_type::set(
                    entry,
                    pdpt::entry::memory_type::write_back
                );
                break;
        };

        pdpt::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pde(
        void *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pd.virt_addr.at(pd::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pde: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pd::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                pd::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                pd::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                pd::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                pd::entry::read_access::enable(entry);
                pd::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                pd::entry::read_access::enable(entry);
                pd::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                pd::entry::read_access::enable(entry);
                pd::entry::write_access::enable(entry);
                pd::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pd::entry::memory_type::set(
                    entry,
                    pd::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                pd::entry::memory_type::set(
                    entry,
                    pd::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                pd::entry::memory_type::set(
                    entry,
                    pd::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                pd::entry::memory_type::set(
                    entry,
                    pd::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                pd::entry::memory_type::set(
                    entry,
                    pd::entry::memory_type::write_back
                );
                break;
        };

        pd::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pte(
        void *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        using namespace ::intel_x64::ept;
        auto &entry = m_pt.virt_addr.at(pt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pt::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                pt::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                pt::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                pt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                pt::entry::read_access::enable(entry);
                pt::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                pt::entry::read_access::enable(entry);
                pt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                pt::entry::read_access::enable(entry);
                pt::entry::write_access::enable(entry);
                pt::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pt::entry::memory_type::set(
                    entry,
                    pt::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                pt::entry::memory_type::set(
                    entry,
                    pt::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                pt::entry::memory_type::set(
                    entry,
                    pt::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                pt::entry::memory_type::set(
                    entry,
                    pt::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                pt::entry::memory_type::set(
                    entry,
                    pt::entry::memory_type::write_back
                );
                break;
        };

        return entry;
    }

    bool
    release_pdpte(void *virt_addr)
    {
        using namespace ::intel_x64::ept;

        this->map_pdpt(pml4::index(virt_addr));
        auto &entry = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (pdpt::entry::ps::is_disabled(entry)) {
            if (!this->release_pde(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdpti = 0; pdpti < pdpt::num_entries; pdpti++) {
            if (m_pdpt.virt_addr.at(pdpti) != 0) {
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
    release_pde(void *virt_addr)
    {
        using namespace ::intel_x64::ept;

        this->map_pd(pdpt::index(virt_addr));
        auto &entry = m_pd.virt_addr.at(pd::index(virt_addr));

        if (pd::entry::ps::is_disabled(entry)) {
            if (!this->release_pte(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdi = 0; pdi < pd::num_entries; pdi++) {
            if (m_pd.virt_addr.at(pdi) != 0) {
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
    release_pte(void *virt_addr)
    {
        using namespace ::intel_x64::ept;

        this->map_pt(pd::index(virt_addr));
        m_pt.virt_addr.at(pt::index(virt_addr)) = 0;

        auto empty = true;
        for (auto pti = 0; pti < pt::num_entries; pti++) {
            if (m_pt.virt_addr.at(pti) != 0) {
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

    pair m_pml4;
    pair m_pdpt;
    pair m_pd;
    pair m_pt;

    mutable std::mutex m_mutex;

public:

    /// @cond

    mmap(mmap &&) = delete;
    mmap &operator=(mmap &&) = delete;

    mmap(const mmap &) = delete;
    mmap &operator=(const mmap &) = delete;

    /// @endcond
};

}

#endif
