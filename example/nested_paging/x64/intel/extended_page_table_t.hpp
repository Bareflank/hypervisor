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

#ifndef EXTENDED_PAGE_TABLE_T_HPP
#define EXTENDED_PAGE_TABLE_T_HPP

#include "epdpt_t.hpp"
#include "epdpte_t.hpp"
#include "epdt_t.hpp"
#include "epdte_t.hpp"
#include "epml4t_t.hpp"
#include "epml4te_t.hpp"
#include "ept_t.hpp"
#include "epte_t.hpp"

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
    /// @class example::extended_page_table_t
    ///
    /// <!-- description -->
    ///   @brief Implements the extended pages tables used by the extension
    ///     for mapping guest physical memory.
    ///
    class extended_page_table_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the page pool to use
        page_pool_t *m_page_pool{};
        /// @brief stores a pointer to the epml4t
        epml4t_t *m_epml4t{};
        /// @brief stores the physical address of the epml4t
        bsl::safe_uintmax m_epml4t_phys{bsl::safe_uintmax::failure()};
        /// @brief safe guards operations on the NPT.
        mutable spinlock m_ept_lock{};

        /// <!-- description -->
        ///   @brief Returns the extended page-map level-4 (NPML4T) offset given
        ///     a guest physical address.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param gpa the guest physical address to get the NPML4T offset from.
        ///   @return the NPML4T offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        epml4to(bsl::safe_uintmax const &gpa) noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(39)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a epdpt_t to the provided epml4te_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epml4te the epml4te_t to add a epdpt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_epdpt(epml4te_t *const epml4te) noexcept -> bsl::errc_type
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

            epml4te->phys = (table_phys >> bsl::to_umax(HYPERVISOR_PAGE_SHIFT)).get();
            epml4te->r = bsl::ONE_UMAX.get();
            epml4te->w = bsl::ONE_UMAX.get();
            epml4te->e = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a epdpt_t to the provided epml4te_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epml4te the epml4te_t to add a epdpt_t too
        ///
        constexpr void
        remove_epdpt(epml4te_t *const epml4te) noexcept
        {
            for (auto const elem : get_epdpt(epml4te)->entries) {
                if (elem.data->r != bsl::ZERO_UMAX) {
                    this->remove_epdt(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_epdpt(epml4te));
        }

        /// <!-- description -->
        ///   @brief Returns the epdpt_t associated with the provided
        ///     epml4te_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epml4te the epml4te_t to get the epdpt_t from
        ///   @return A pointer to the requested epdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_epdpt(epml4te_t *const epml4te) noexcept -> epdpt_t *
        {
            bsl::safe_uintmax entry_phys{epml4te->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<epdpt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the epdpt_t associated with the provided
        ///     epml4te_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epml4te the epml4te_t to get the epdpt_t from
        ///   @return A pointer to the requested epdpt_t
        ///
        [[nodiscard]] constexpr auto
        get_epdpt(epml4te_t const *const epml4te) const noexcept -> epdpt_t const *
        {
            bsl::safe_uintmax entry_phys{epml4te->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<epdpt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the extended page-directory-pointer table (NPDPT)
        ///    offset given a guest physical address.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param gpa the guest physical address to get the NPDPT offset from.
        ///   @return the NPDPT offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        epdpto(bsl::safe_uintmax const &gpa) noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(30)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a epdt_t to the provided epdpte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdpte the epdpte_t to add a epdt_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_epdt(epdpte_t *const epdpte) noexcept -> bsl::errc_type
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

            epdpte->phys = (table_phys >> bsl::to_umax(HYPERVISOR_PAGE_SHIFT)).get();
            epdpte->r = bsl::ONE_UMAX.get();
            epdpte->w = bsl::ONE_UMAX.get();
            epdpte->e = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a epdt_t to the provided epdpte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdpte the epdpte_t to add a epdt_t too
        ///
        constexpr void
        remove_epdt(epdpte_t *const epdpte) noexcept
        {
            for (auto const elem : get_epdt(epdpte)->entries) {
                if (elem.data->r != bsl::ZERO_UMAX) {
                    this->remove_ept(elem.data);
                }
                else {
                    bsl::touch();
                }
            }

            m_page_pool->deallocate(get_epdt(epdpte));
        }

        /// <!-- description -->
        ///   @brief Returns the epdt_t associated with the provided
        ///     epdpte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdpte the epdpte_t to get the epdt_t from
        ///   @return A pointer to the requested epdt_t
        ///
        [[nodiscard]] constexpr auto
        get_epdt(epdpte_t *const epdpte) noexcept -> epdt_t *
        {
            bsl::safe_uintmax entry_phys{epdpte->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<epdt_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the epdt_t associated with the provided
        ///     epdpte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdpte the epdpte_t to get the epdt_t from
        ///   @return A pointer to the requested epdt_t
        ///
        [[nodiscard]] constexpr auto
        get_epdt(epdpte_t const *const epdpte) const noexcept -> epdt_t const *
        {
            bsl::safe_uintmax entry_phys{epdpte->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<epdt_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the extended page-directory table (NPDT) offset
        ///     given a guest physical address.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param gpa the guest physical address to get the NPDT offset from.
        ///   @return the NPDT offset from the guest physical address.
        ///
        [[nodiscard]] static constexpr auto
        epdto(bsl::safe_uintmax const &gpa) noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(21)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Adds a ept_t to the provided epdte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdte the epdte_t to add a ept_t too
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_ept(epdte_t *const epdte) noexcept -> bsl::errc_type
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

            epdte->phys = (table_phys >> bsl::to_umax(HYPERVISOR_PAGE_SHIFT)).get();
            epdte->r = bsl::ONE_UMAX.get();
            epdte->w = bsl::ONE_UMAX.get();
            epdte->e = bsl::ONE_UMAX.get();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a ept_t to the provided epdte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdte the epdte_t to add a ept_t too
        ///
        constexpr void
        remove_ept(epdte_t *const epdte) noexcept
        {
            m_page_pool->deallocate(get_ept(epdte));
        }

        /// <!-- description -->
        ///   @brief Returns the ept_t associated with the provided
        ///     epdte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdte the epdte_t to get the ept_t from
        ///   @return A pointer to the requested ept_t
        ///
        [[nodiscard]] constexpr auto
        get_ept(epdte_t *const epdte) noexcept -> ept_t *
        {
            bsl::safe_uintmax entry_phys{epdte->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<ept_t>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the ept_t associated with the provided
        ///     epdte_t.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param epdte the epdte_t to get the ept_t from
        ///   @return A pointer to the requested ept_t
        ///
        [[nodiscard]] constexpr auto
        get_ept(epdte_t const *const epdte) const noexcept -> ept_t const *
        {
            bsl::safe_uintmax entry_phys{epdte->phys};
            entry_phys <<= bsl::to_umax(HYPERVISOR_PAGE_SHIFT);

            return m_page_pool->template phys_to_virt<ept_t const>(entry_phys);
        }

        /// <!-- description -->
        ///   @brief Returns the page-table (NPT) offset given a
        ///     guest physical address.
        ///
        /// <!-- ieputs/outputs -->
        ///   @param gpa the guest physical address to get the NPT offset from.
        ///   @return the NPT offset from the guest physical address
        ///
        [[nodiscard]] static constexpr auto
        epto(bsl::safe_uintmax const &gpa) noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x1FF)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(12)};
            return (gpa >> shift) & mask;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is page aligned
        ///
        /// <!-- ieputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_aligned(bsl::safe_uintmax const &addr) noexcept -> bool
        {
            return (addr & (bsl::to_umax(HYPERVISOR_PAGE_SIZE) - bsl::ONE_UMAX)) == bsl::ZERO_UMAX;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated in this root page table
        ///
        constexpr void
        auto_release() noexcept
        {
            if (bsl::unlikely(nullptr == m_epml4t)) {
                return;
            }

            if (bsl::unlikely(nullptr == m_page_pool)) {
                return;
            }

            for (auto const elem : m_epml4t->entries) {
                if (elem.data->r == bsl::ZERO_UMAX) {
                    continue;
                }

                this->remove_epdpt(elem.data);
            }

            m_page_pool->deallocate(m_epml4t);
            m_epml4t = {};
            m_epml4t_phys = bsl::safe_uintmax::failure();
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this extended_page_table_t
        ///
        /// <!-- ieputs/outputs -->
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(page_pool_t *const page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "extended_page_table_t already initialized\n" << bsl::here();
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

            m_epml4t = m_page_pool->template allocate<epml4t_t>();
            if (bsl::unlikely(nullptr == m_epml4t)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_epml4t_phys = m_page_pool->virt_to_phys(m_epml4t);
            if (bsl::unlikely(!m_epml4t_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases the memory allocated in this extended page tables
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
        /// <!-- ieputs/outputs -->
        ///   @return Returns the physical address of the PML4
        ///
        [[nodiscard]] constexpr auto
        phys() const noexcept -> bsl::safe_uintmax const &
        {
            return m_epml4t_phys;
        }

        /// <!-- description -->
        ///   @brief Maps a 4k page into the extended page tables being managed
        ///     by this class.
        ///
        /// <!-- ieputs/outputs -->
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
            bsl::safe_uintmax const &page_gpa,
            bsl::safe_uintmax const &page_spa,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_uintmax const &page_type) noexcept -> bsl::errc_type
        {
            lock_guard lock{m_ept_lock};

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "extended_page_table_t not initialized\n" << bsl::here();
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
                bsl::error() << "invalid type: "       // --
                             << bsl::hex(page_type)    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            auto *const epml4te{m_epml4t->entries.at_if(this->epml4to(page_gpa))};
            if (epml4te->r == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_epdpt(epml4te))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const epdpt{this->get_epdpt(epml4te)};
            auto *const epdpte{epdpt->entries.at_if(this->epdpto(page_gpa))};
            if (epdpte->r == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_epdt(epdpte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const epdt{this->get_epdt(epdpte)};
            auto *const epdte{epdt->entries.at_if(this->epdto(page_gpa))};
            if (epdte->r == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_ept(epdte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const ept{this->get_ept(epdte)};
            auto *const epte{ept->entries.at_if(this->epto(page_gpa))};
            if (bsl::unlikely(epte->r != bsl::ZERO_UMAX)) {
                bsl::error() << "guest physical address "    // --
                             << bsl::hex(page_gpa)           // --
                             << " already mapped"            // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            epte->phys = (page_spa >> bsl::to_umax(HYPERVISOR_PAGE_SHIFT)).get();
            epte->r = bsl::ONE_UMAX.get();
            epte->type = page_type.get();

            if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
                epte->w = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
                epte->e = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Maps a 2m page into the extended page tables being managed
        ///     by this class.
        ///
        /// <!-- ieputs/outputs -->
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
            bsl::safe_uintmax const &page_gpa,
            bsl::safe_uintmax const &page_spa,
            bsl::safe_uintmax const &page_flags,
            bsl::safe_uintmax const &page_type) noexcept -> bsl::errc_type
        {
            lock_guard lock{m_ept_lock};

            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "extended_page_table_t not initialized\n" << bsl::here();
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
                bsl::error() << "invalid type: "       // --
                             << bsl::hex(page_type)    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            auto *const epml4te{m_epml4t->entries.at_if(this->epml4to(page_gpa))};
            if (epml4te->r == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_epdpt(epml4te))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const epdpt{this->get_epdpt(epml4te)};
            auto *const epdpte{epdpt->entries.at_if(this->epdpto(page_gpa))};
            if (epdpte->r == bsl::ZERO_UMAX) {
                if (bsl::unlikely(!this->add_epdt(epdpte))) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto *const epdt{this->get_epdt(epdpte)};
            auto *const epdte{epdt->entries.at_if(this->epdto(page_gpa))};
            if (bsl::unlikely(epdte->r != bsl::ZERO_UMAX)) {
                bsl::error() << "guest physical address "    // --
                             << bsl::hex(page_gpa)           // --
                             << " already mapped"            // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_failure;
            }

            epdte->phys = (page_spa >> bsl::to_umax(HYPERVISOR_PAGE_SHIFT)).get();
            epdte->r = bsl::ONE_UMAX.get();
            epdte->type = page_type.get();
            epdte->ps = bsl::ONE_UMAX.get();

            if (!(page_flags & MAP_PAGE_WRITE).is_zero()) {
                epdte->w = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            if (!(page_flags & MAP_PAGE_EXECUTE).is_zero()) {
                epdte->e = bsl::ONE_UMAX.get();
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }
    };
}

#endif
