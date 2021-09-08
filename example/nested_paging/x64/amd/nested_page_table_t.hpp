/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef NESTED_PAGE_TABLE_T_HPP
#define NESTED_PAGE_TABLE_T_HPP

#include "npdpt_t.hpp"
#include "npdpte_t.hpp"
#include "npdt_t.hpp"
#include "npdte_t.hpp"
#include "npml4t_t.hpp"
#include "npml4te_t.hpp"
#include "npt_t.hpp"
#include "npte_t.hpp"

#include <lock_guard.hpp>
#include <map_page_flags.hpp>
#include <memory_type.hpp>
#include <page_pool_t.hpp>
#include <spinlock.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::nested_page_table_t
    ///
    /// <!-- description -->
    ///   @brief Implements the nested pages tables used by the extension
    ///     for mapping guest physical memory.
    ///
    class nested_page_table_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the page pool to use
        page_pool_t *m_page_pool{};
        /// @brief stores a pointer to the npml4t
        npml4t_t *m_npml4t{};
        /// @brief stores the physical address of the npml4t
        bsl::safe_umx m_npml4t_phys{bsl::safe_umx::failure()};
        /// @brief safe guards operations on the NPT.
        mutable spinlock m_npt_lock{};

        /// <!-- description -->
        ///   @brief Returns the nested page-map level-4 (NPML4T) offset given
        ///     a guest physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gpa the guest physical address to get the NPML4T offset from.
        ///   @return the NPML4T offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        npml4to(bsl::safe_umx const &gpa) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x1FF)};
            constexpr bsl::safe_umx shift{bsl::to_umx(39)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a npdpt_t to the provided npml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npml4te the npml4te_t to add a npdpt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_npdpt(npml4te_t *const npml4te) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            npml4te->phys = (table_phys >> bsl::to_umx(HYPERVISOR_PAGE_SHIFT)).get();
            npml4te->p = bsl::ONE_UMAX.get();
            npml4te->rw = bsl::ONE_UMAX.get();
            npml4te->us = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a npdpt_t to the provided npml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npml4te the npml4te_t to add a npdpt_t too
        ///
        constexpr void
        remove_npdpt(npml4te_t *const npml4te) noexcept
        {
            for (auto const elem : get_npdpt(npml4te)->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    this->remove_npdt(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_npdpt(npml4te));
        }

        /// <!-- description -->
        ///   @brief Returns the npdpt_t associated with the provided
        ///     npml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npml4te the npml4te_t to get the npdpt_t from
        ///   @return A pointer to the requested npdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_npdpt(npml4te_t *const npml4te) noexcept -> npdpt_t *
        {
            bsl::safe_umx entry_phys{npml4te->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npdpt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the npdpt_t associated with the provided
        ///     npml4te_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npml4te the npml4te_t to get the npdpt_t from
        ///   @return A pointer to the requested npdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_npdpt(npml4te_t const *const npml4te) const noexcept -> npdpt_t const *
        {
            bsl::safe_umx entry_phys{npml4te->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npdpt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the nested page-directory-pointer table (NPDPT)
        ///    offset given a guest physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gpa the guest physical address to get the NPDPT offset from.
        ///   @return the NPDPT offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        npdpto(bsl::safe_umx const &gpa) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x1FF)};
            constexpr bsl::safe_umx shift{bsl::to_umx(30)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a npdt_t to the provided npdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdpte the npdpte_t to add a npdt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_npdt(npdpte_t *const npdpte) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            npdpte->phys = (table_phys >> bsl::to_umx(HYPERVISOR_PAGE_SHIFT)).get();
            npdpte->p = bsl::ONE_UMAX.get();
            npdpte->rw = bsl::ONE_UMAX.get();
            npdpte->us = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a npdt_t to the provided npdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdpte the npdpte_t to add a npdt_t too
        ///
        constexpr void
        remove_npdt(npdpte_t *const npdpte) noexcept
        {
            for (auto const elem : get_npdt(npdpte)->entries) {
                if (elem.data->p != bsl::ZERO_UMAX) {
                    this->remove_npt(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_npdt(npdpte));
        }

        /// <!-- description -->
        ///   @brief Returns the npdt_t associated with the provided
        ///     npdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdpte the npdpte_t to get the npdt_t from
        ///   @return A pointer to the requested npdt_t
        ///
        [[nodiscard]] constexpr auto
        get_npdt(npdpte_t *const npdpte) noexcept -> npdt_t *
        {
            bsl::safe_umx entry_phys{npdpte->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npdt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the npdt_t associated with the provided
        ///     npdpte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdpte the npdpte_t to get the npdt_t from
        ///   @return A pointer to the requested npdt_t
        ///
        [[nodiscard]] constexpr auto
        get_npdt(npdpte_t const *const npdpte) const noexcept -> npdt_t const *
        {
            bsl::safe_umx entry_phys{npdpte->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npdt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the nested page-directory table (NPDT) offset
        ///     given a guest physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gpa the guest physical address to get the NPDT offset from.
        ///   @return the NPDT offset from the guest physical address.
        ///
        [[nodiscard]] static constexpr auto
        npdto(bsl::safe_umx const &gpa) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x1FF)};
            constexpr bsl::safe_umx shift{bsl::to_umx(21)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a npt_t to the provided npdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdte the npdte_t to add a npt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_npt(npdte_t *const npdte) noexcept -> bsl::errc_type
        {
            auto const *const table{m_page_pool->template allocate<void>()};
            if (bsl::unlikely(nullptr == table)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const table_phys{m_page_pool->virt_to_phys(table)};
            if (bsl::unlikely(!table_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            npdte->phys = (table_phys >> bsl::to_umx(HYPERVISOR_PAGE_SHIFT)).get();
            npdte->p = bsl::ONE_UMAX.get();
            npdte->rw = bsl::ONE_UMAX.get();
            npdte->us = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a npt_t to the provided npdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdte the npdte_t to add a npt_t too
        ///
        constexpr void
        remove_npt(npdte_t *const npdte) noexcept
        {
            m_page_pool->deallocate(get_npt(npdte));
        }

        /// <!-- description -->
        ///   @brief Returns the npt_t associated with the provided
        ///     npdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdte the npdte_t to get the npt_t from
        ///   @return A pointer to the requested npt_t
        ///
        [[nodiscard]] constexpr auto
        get_npt(npdte_t *const npdte) noexcept -> npt_t *
        {
            bsl::safe_umx entry_phys{npdte->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the npt_t associated with the provided
        ///     npdte_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param npdte the npdte_t to get the npt_t from
        ///   @return A pointer to the requested npt_t
        ///
        [[nodiscard]] constexpr auto
        get_npt(npdte_t const *const npdte) const noexcept -> npt_t const *
        {
            bsl::safe_umx entry_phys{npdte->phys};
            entry_phys <<= bsl::to_umx(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<npt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-table (NPT) offset given a
        ///     guest physical address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gpa the guest physical address to get the NPT offset from.
        ///   @return the NPT offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        npto(bsl::safe_umx const &gpa) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x1FF)};
            constexpr bsl::safe_umx shift{bsl::to_umx(12)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_aligned(bsl::safe_umx const &addr) noexcept -> bool
        {
            return (addr & (bsl::to_umx(HYPERVISOR_PAGE_SIZE) - bsl::ONE_UMAX)) == bsl::ZERO_UMAX;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated in this root page table
        ///
        constexpr void
        auto_release() noexcept
        {
            if (bsl::unlikely(nullptr == m_npml4t)) {
                return;
            }

            if (bsl::unlikely(nullptr == m_page_pool)) {
                return;
            }

            for (auto const elem : m_npml4t->entries) {
                if (elem.data->p == bsl::ZERO_UMAX) {
                    continue;
                }

                this->remove_npdpt(elem.data);
            }

            m_page_pool->deallocate(m_npml4t);
            m_npml4t = {};
            m_npml4t_phys = bsl::safe_umx::failure();
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this nested_page_table_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(page_pool_t *const page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "nested_page_table_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_page_pool = page_pool;
            if (bsl::unlikely(nullptr == page_pool)) {
                bsl::error() << "invalid page_pool\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_npml4t = m_page_pool->template allocate<npml4t_t>();
            if (bsl::unlikely(nullptr == m_npml4t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_npml4t_phys = m_page_pool->virt_to_phys(m_npml4t);
            if (bsl::unlikely(!m_npml4t_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated in this nested page tables
        ///
        constexpr void
        release() noexcept
        {
            this->auto_release();

            m_page_pool = {};
            m_initialized = false;
        }

        /// <!-- description -->
        ///   @brief Returns the physical address of the PML4
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the physical address of the PML4
        ///
        [[nodiscard]] constexpr auto
        phys() const noexcept -> bsl::safe_umx const &
        {
            return m_npml4t_phys;
        }

        /// <!-- description -->
        ///   @brief Maps a 4k page into the nested page tables being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_gpa the guest physical address to map the system
        ///     physical address to
        ///   @param page_spa the system physical address to map.
        ///   @param page_flags defines how memory should be mapped
        ///   @param page_type defines the memory type for the mapping
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_4k_page(
            bsl::safe_umx const &page_gpa,
            bsl::safe_umx const &page_spa,
            bsl::safe_umx const &page_flags,
            bsl::safe_umx const &page_type) noexcept -> bsl::errc_type
        {
            lock_guard lock{m_npt_lock};

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "nested_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_gpa)) {
                bsl::error() << "guest physical address is invalid: "    // --
                             << bsl::hex(page_gpa)                       // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_gpa))) {
                bsl::error() << "guest physical address is not page aligned: "    // --
                             << bsl::hex(page_gpa)                                // --
                             << bsl::endl                                         // --
                             << bsl::here();                                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_spa)) {
                bsl::error() << "system physical address is invalid: "    // --
                             << bsl::hex(page_spa)                        // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_spa))) {
                bsl::error() << "system physical address is not page aligned: "    // --
                             << bsl::hex(page_spa)                                 // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_flags)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_type)) {
                bsl::error() << "invalid flags: "      // --
                             << bsl::hex(page_type)    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WC)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WT)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WP)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            auto *const npml4te{m_npml4t->entries.at_if(this->npml4to(page_gpa))};
            if (npml4te->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_npdpt(npml4te))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const npdpt{this->get_npdpt(npml4te)};
            auto *const npdpte{npdpt->entries.at_if(this->npdpto(page_gpa))};
            if (npdpte->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_npdt(npdpte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const npdt{this->get_npdt(npdpte)};
            auto *const npdte{npdt->entries.at_if(this->npdto(page_gpa))};
            if (npdte->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_npt(npdte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const npt{this->get_npt(npdte)};
            auto *const npte{npt->entries.at_if(this->npto(page_gpa))};
            if (bsl::unlikely(npte->p != bsl::ZERO_UMAX)) {
                bsl::error() << "guest physical address "    // --
                             << bsl::hex(page_gpa)           // --
                             << " already mapped"            // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            npte->phys = (page_spa >> bsl::to_umx(HYPERVISOR_PAGE_SHIFT)).get();
            npte->p = bsl::ONE_UMAX.get();
            npte->us = bsl::ONE_UMAX.get();

            if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
                npte->rw = bsl::ONE_UMAX.get();
            }
            else {
                npte->rw = bsl::ZERO_UMAX.get();
            }

            if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
                npte->nx = bsl::ZERO_UMAX.get();
            }
            else {
                npte->nx = bsl::ONE_UMAX.get();
            }

            if (page_type == MEMORY_TYPE_UC) {
                npte->pwt = bsl::ONE_UMAX.get();
                npte->pcd = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Maps a 2m page into the nested page tables being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_gpa the guest physical address to map the system
        ///     physical address to
        ///   @param page_spa the system physical address to map.
        ///   @param page_flags defines how memory should be mapped
        ///   @param page_type defines the memory type for the mapping
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_2m_page(
            bsl::safe_umx const &page_gpa,
            bsl::safe_umx const &page_spa,
            bsl::safe_umx const &page_flags,
            bsl::safe_umx const &page_type) noexcept -> bsl::errc_type
        {
            lock_guard lock{m_npt_lock};

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "nested_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_gpa)) {
                bsl::error() << "guest physical address is invalid: "    // --
                             << bsl::hex(page_gpa)                       // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_gpa))) {
                bsl::error() << "guest physical address is not page aligned: "    // --
                             << bsl::hex(page_gpa)                                // --
                             << bsl::endl                                         // --
                             << bsl::here();                                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_spa)) {
                bsl::error() << "system physical address is invalid: "    // --
                             << bsl::hex(page_spa)                        // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_aligned(page_spa))) {
                bsl::error() << "system physical address is not page aligned: "    // --
                             << bsl::hex(page_spa)                                 // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_flags)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!page_type)) {
                bsl::error() << "invalid flags: "      // --
                             << bsl::hex(page_type)    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WC)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WT)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(page_type == MEMORY_TYPE_WP)) {
                bsl::error() << "invalid flags: "       // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            auto *const npml4te{m_npml4t->entries.at_if(this->npml4to(page_gpa))};
            if (npml4te->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_npdpt(npml4te))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const npdpt{this->get_npdpt(npml4te)};
            auto *const npdpte{npdpt->entries.at_if(this->npdpto(page_gpa))};
            if (npdpte->p == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_npdt(npdpte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const npdt{this->get_npdt(npdpte)};
            auto *const npdte{npdt->entries.at_if(this->npdto(page_gpa))};
            if (bsl::unlikely(npdte->p != bsl::ZERO_UMAX)) {
                bsl::error() << "guest physical address "    // --
                             << bsl::hex(page_gpa)           // --
                             << " already mapped"            // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            npdte->phys = (page_spa >> bsl::to_umx(HYPERVISOR_PAGE_SHIFT)).get();
            npdte->p = bsl::ONE_UMAX.get();
            npdte->us = bsl::ONE_UMAX.get();
            npdte->ps = bsl::ONE_UMAX.get();

            if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
                npdte->rw = bsl::ONE_UMAX.get();
            }
            else {
                npdte->rw = bsl::ZERO_UMAX.get();
            }

            if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
                npdte->nx = bsl::ZERO_UMAX.get();
            }
            else {
                npdte->nx = bsl::ONE_UMAX.get();
            }

            if (page_type == MEMORY_TYPE_UC) {
                npdte->pwt = bsl::ONE_UMAX.get();
                npdte->pcd = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }
    };
}

#endif
