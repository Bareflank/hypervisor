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

#ifndef MMAP_CR3_X64_H
#define MMAP_CR3_X64_H

#include <mutex>
#include <unordered_map>

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfupperlower.h>

#include <intrinsics.h>
#include "../../../memory_manager.h"

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bfvmm::x64::cr3
{

/// CR3 Memory Map
///
/// This class constructs a set of CR3 page tables, and provides the needed
/// APIs to map virtual to physical addresses to these pages. For more
/// information on how CR3 page tables work, please see the Intel SDM. This
/// implementation attempts to map directly to the SDM text.
///
/// TODO:
///
/// Currently, we have a last lookup cache set up that helps to reduce the
/// time it takes to map. We need to implement a TLB as well, and the TLB
/// should be enabled by default.
///
/// The goal of the TLB would be to queue unmaps based on incoming maps,
/// similar to the way the hardware's TLB removes entries from the actual
/// hardware TLB. All unmaps are added to a queue. Each time an unmap occurs,
/// the unmap is added to the top of the queue. If the unmap is already in
/// the queue, it is moved to the top. Once the queue reaches a certain limit,
/// an unmap causes the unmap at the end of the queue to actually be
/// unmapped. The queue should be hand made to prevent the need for memory
/// allocations. This will provide huge increase in performance for mapping
/// operations as it will prevent the map from mapping and unmapping the same
/// addresses. Note that attemps to map an address that is in the unmap queue
/// should remove the map from the unmap queue and do nothing else.
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
        read_write,
        read_execute,
        read_write_execute
    };

    enum class memory_type {
        uncacheable,
        write_back
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
        m_pml4{allocate_span(::x64::pml4::num_entries), 0}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mmap()
    {
        using namespace ::x64;

        for (auto pml4i = 0; pml4i < pml4::num_entries; pml4i++) {
            auto &entry = m_pml4.virt_addr.at(pml4i);

            if (entry == 0) {
                continue;
            }

            this->clear_pdpt(pml4i);
        }

        free_page(m_pml4.virt_addr.data());
    }

    /// CR3
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into CR3
    ///
    uintptr_t cr3()
    {
        std::lock_guard lock(m_mutex);

        if (m_pml4.phys_addr == 0) {
            m_pml4.phys_addr = g_mm->virtptr_to_physint(m_pml4.virt_addr.data());
        }

        return m_pml4.phys_addr;
    }

    /// PAT
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into the PAT
    ///
    inline uint64_t pat()
    { return 0x0606060606060600; }

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
        attr_type attr = attr_type::read_write,
        memory_type cache = memory_type::write_back)
    {
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
        attr_type attr = attr_type::read_write,
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
        attr_type attr = attr_type::read_write,
        memory_type cache = memory_type::write_back)
    {
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
        attr_type attr = attr_type::read_write,
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
        attr_type attr = attr_type::read_write,
        memory_type cache = memory_type::write_back)
    {
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
        attr_type attr = attr_type::read_write,
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
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
    /// This function converts a virtual address to a physical address. If
    /// the map is being used for the VMM itself, this is a regular virtual
    /// address to physical address conversion, just like on any OS. If the
    /// map is used for a guest, this is a GVA to GPA conversion.
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
    /// This function converts a virtual address to a physical address. If
    /// the map is being used for the VMM itself, this is a regular virtual
    /// address to physical address conversion, just like on any OS. If the
    /// map is used for a guest, this is a GVA to GPA conversion.
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
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
    uint64_t
    from(void *virt_addr)
    {
        using namespace ::x64;
        std::lock_guard lock(m_mutex);

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
    inline uint64_t from(virt_addr_t virt_addr)
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
    inline bool is_1g(void *virt_addr)
    { return from(virt_addr) == ::x64::pdpt::from; }

    /// Is 1g
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 1g page,
    ///     false otherwise
    ///
    inline bool is_1g(virt_addr_t virt_addr)
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
    inline bool is_2m(void *virt_addr)
    { return from(virt_addr) == ::x64::pd::from; }

    /// Is 2m
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 2m page,
    ///     false otherwise
    ///
    inline bool is_2m(virt_addr_t virt_addr)
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
    inline bool is_4k(void *virt_addr)
    { return from(virt_addr) == ::x64::pt::from; }

    /// Is 4k
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 4k page,
    ///     false otherwise
    ///
    inline bool is_4k(virt_addr_t virt_addr)
    { return is_4k(reinterpret_cast<void *>(virt_addr)); }

    /// Memory Descriptor List
    ///
    /// @expects
    /// @ensures
    ///
    /// @return a list of all of the pages used to construct the mmap.
    ///     This list does not contain the mapped addressed, just the
    ///     addresses of the pages used to construct the table
    ///
    std::unordered_map<void *, phys_addr_t> &mdl()
    { return m_mdl; }

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

        m_mdl[ptrs.virt_addr.data()] = ptrs.phys_addr;
        return ptrs;
    }

    void
    free(const gsl::span<virt_addr_t> &virt_addr)
    {
        free_page(virt_addr.data());
        m_mdl.erase(virt_addr.data());
    }

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
        using namespace ::x64;
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
        pml4::entry::pat_index::set(entry, 1);
        pml4::entry::present::enable(entry);
        pml4::entry::rw::enable(entry);
    }

    void
    map_pd(index_type pdpti)
    {
        using namespace ::x64;
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
        pdpt::entry::pat_index::set(entry, 1);
        pdpt::entry::present::enable(entry);
        pdpt::entry::rw::enable(entry);
    }

    void
    map_pt(index_type pdi)
    {
        using namespace ::x64;
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
        pd::entry::pat_index::set(entry, 1);
        pd::entry::present::enable(entry);
        pd::entry::rw::enable(entry);
    }

    void
    clear_pdpt(index_type pml4i)
    {
        using namespace ::x64;
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
        using namespace ::x64;
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
        using namespace ::x64;
        auto &entry = m_pdpt.virt_addr.at(pdpt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pdpte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pdpt::entry::phys_addr::set(entry, phys_addr);
        pdpt::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                pdpt::entry::rw::enable(entry);
                pdpt::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                pdpt::entry::rw::disable(entry);
                pdpt::entry::xd::disable(entry);
                break;

            case attr_type::read_write_execute:
                pdpt::entry::rw::enable(entry);
                pdpt::entry::xd::disable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pdpt::entry::pat_index::set(entry, 0);
                break;

            case memory_type::write_back:
                pdpt::entry::pat_index::set(entry, 1);
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
        using namespace ::x64;
        auto &entry = m_pd.virt_addr.at(pd::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pde: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pd::entry::phys_addr::set(entry, phys_addr);
        pd::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                pd::entry::rw::enable(entry);
                pd::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                pd::entry::rw::disable(entry);
                pd::entry::xd::disable(entry);
                break;

            case attr_type::read_write_execute:
                pd::entry::rw::enable(entry);
                pd::entry::xd::disable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pd::entry::pat_index::set(entry, 0);
                break;

            case memory_type::write_back:
                pd::entry::pat_index::set(entry, 1);
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
        using namespace ::x64;
        auto &entry = m_pt.virt_addr.at(pt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        pt::entry::phys_addr::set(entry, phys_addr);
        pt::entry::present::enable(entry);

        switch (attr) {
            case attr_type::read_write:
                pt::entry::rw::enable(entry);
                pt::entry::xd::enable(entry);
                break;

            case attr_type::read_execute:
                pt::entry::rw::disable(entry);
                pt::entry::xd::disable(entry);
                break;

            case attr_type::read_write_execute:
                pt::entry::rw::enable(entry);
                pt::entry::xd::disable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                pt::entry::pat_index::set(entry, 0);
                break;

            case memory_type::write_back:
                pt::entry::pat_index::set(entry, 1);
                break;
        };

        return entry;
    }

    bool
    release_pdpte(void *virt_addr)
    {
        using namespace ::x64;

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
        using namespace ::x64;

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
        using namespace ::x64;

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
    std::unordered_map<void *, phys_addr_t> m_mdl;

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
