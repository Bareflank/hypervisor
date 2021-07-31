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

#ifndef MOCK_ROOT_PAGE_TABLE_T_HPP
#define MOCK_ROOT_PAGE_TABLE_T_HPP

#include <map_page_flags.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_contract.hpp>

namespace mk
{
    /// @class mk::root_page_table_t
    ///
    /// <!-- description -->
    ///   @brief Implements the root pages tables used by the microkernel
    ///     for mapping extension memory.
    ///
    class root_page_table_t final
    {
        /// @brief stores whether or not the rpt has been initialized
        bool m_initialized{};

        /// <!-- description -->
        ///   @brief Returns the page aligned version of the addr
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns the page aligned version of the addr
        ///
        [[nodiscard]] static constexpr auto
        page_aligned(bsl::safe_umx const &addr) noexcept -> bsl::safe_umx
        {
            constexpr auto one{1_umx};
            return (addr & ~(HYPERVISOR_PAGE_SIZE - one));
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
            constexpr auto one{1_umx};
            constexpr auto aligned{0_umx};
            return (addr & (HYPERVISOR_PAGE_SIZE - one)) == aligned;
        }

    public:
        ///   @brief Initializes this root_page_table_t
        /// <!-- description -->
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_contract(m_initialized)) {
                bsl::error() << "root_page_table_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(!tls.test_ret)) {
                return tls.test_ret;
            }

            m_initialized = true;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Releases all of the resources used by the RPT.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &tls, page_pool_t &page_pool) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);

            m_initialized = false;
        }

        /// <!-- description -->
        ///   @brief Returns true if this RPT is initialized.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this RPT is initialized.
        ///
        [[nodiscard]] constexpr auto
        is_initialized() const noexcept -> bool
        {
            return m_initialized;
        }

        /// <!-- description -->
        ///   @brief Sets the current root page table to this root page table.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        activate(tls_t &tls, intrinsic_t &intrinsic) const noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            if (bsl::unlikely_contract(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address
        ///     too.
        ///   @param page_phys the physical address to map.
        ///   @param page_flags defines how memory should be mapped
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_umx const &page_virt,
            bsl::safe_umx const &page_phys,
            bsl::safe_umx const &page_flags,
            bsl::safe_umx const &auto_release) noexcept -> bsl::errc_type
        {
            bsl::discard(page_pool);

            if (bsl::unlikely_contract(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(page_virt.is_zero_or_invalid())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(page_phys.is_zero_or_invalid())) {
                bsl::error() << "physical address is invalid "    // --
                             << bsl::hex(page_phys)               // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(!this->is_page_aligned(page_phys))) {
                bsl::error() << "physical address is not page aligned "    // --
                             << bsl::hex(page_phys)                        // --
                             << bsl::endl                                  // --
                             << bsl::here();                               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(page_flags.is_zero_or_invalid())) {
                bsl::error() << "invalid flags "        // --
                             << bsl::hex(page_flags)    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            if ((page_flags & MAP_PAGE_WRITE).is_pos()) {
                if (bsl::unlikely_contract((page_flags & MAP_PAGE_EXECUTE).is_pos())) {
                    bsl::error() << "invalid page_flags "    // --
                                 << bsl::hex(page_flags)     // --
                                 << bsl::endl                // --
                                 << bsl::here();             // --

                    return bsl::errc_failure;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            if (bsl::unlikely_contract(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(!(auto_release < MAP_PAGE_AUTO_RELEASE_MAX))) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Maps a page into the root page table being managed
        ///     by this class. This version allows for unaligned virtual and
        ///     physical addresses and will perform the alignment for you.
        ///     Note that you should only use this function if you actually
        ///     need unaligned support to ensure alignment mistakes are not
        ///     accidentally introduced.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the physical address
        ///     too.
        ///   @param page_phys the physical address to map. If the physical
        ///     address is set to 0, map_page will use the page_pool_t to
        ///     determine the physical address.
        ///   @param page_flags defines how memory should be mapped
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        map_page_unaligned(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_umx const &page_virt,
            bsl::safe_umx const &page_phys,
            bsl::safe_umx const &page_flags,
            bsl::safe_umx const &auto_release) noexcept -> bsl::errc_type
        {
            return this->map_page(
                tls,
                page_pool,
                this->page_aligned(page_virt),
                this->page_aligned(page_phys),
                page_flags,
                auto_release);
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool. Note that this version maps the memory in as
        ///     read/write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either page_t or ext_tls_t
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate_page_rw(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_umx const &page_virt,
            bsl::safe_umx const &auto_release) noexcept -> T *
        {
            if (bsl::unlikely_contract(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_contract(page_virt.is_zero_or_invalid())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return nullptr;
            }

            if (bsl::unlikely_contract(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return nullptr;
            }

            if (bsl::unlikely_contract(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return nullptr;
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a page from the provided page pool and maps it
        ///     into the root page table being managed by this class The page
        ///     is marked as "auto release", meaning when this root page table
        ///     is released, the pages allocated by this function will
        ///     automatically be deallocated and put back into the provided
        ///     page pool. Note that this version maps the memory in as
        ///     read/execute.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either page_t or ext_tls_t
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param page_virt the virtual address to map the allocated
        ///     page to
        ///   @param auto_release defines what auto release tag to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        allocate_page_rx(
            tls_t &tls,
            page_pool_t &page_pool,
            bsl::safe_umx const &page_virt,
            bsl::safe_umx const &auto_release) noexcept -> T *
        {
            if (bsl::unlikely_contract(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely_contract(page_virt.is_zero_or_invalid())) {
                bsl::error() << "virtual address is invalid "    // --
                             << bsl::hex(page_virt)              // --
                             << bsl::endl                        // --
                             << bsl::here();                     // --

                return nullptr;
            }

            if (bsl::unlikely_contract(!this->is_page_aligned(page_virt))) {
                bsl::error() << "virtual address is not page aligned "    // --
                             << bsl::hex(page_virt)                       // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return nullptr;
            }

            if (bsl::unlikely_contract(!auto_release)) {
                bsl::error() << "invalid auto release "    // --
                             << auto_release               // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return nullptr;
            }
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the pml4te_t enties are aliased
        ///     into this page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param pml4t the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(tls_t &tls, void const *const pml4t) noexcept -> bsl::errc_type
        {
            lock_guard_t mut_lock{tls, m_lock};

            if (bsl::unlikely_contract(!m_initialized)) {
                bsl::error() << "root_page_table_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely_contract(nullptr == pml4t)) {
                bsl::error() << "invalid rpt\n" << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Given a root page table, the pml4te_t enties are aliased
        ///     into this page table, allowing software using this root page
        ///     table to access the memory mapped into the provided root page
        ///     table. The additions are aliases only, meaning when this root
        ///     page table loses scope, aliased entries added by this function
        ///     are not returned back to the page_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param rpt the root page table to add aliases to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        add_tables(tls_t &tls, root_page_table_t const &rpt) noexcept -> bsl::errc_type
        {
            return this->add_tables(tls, rpt.m_pml4t);
        }

        /// <!-- description -->
        ///   @brief Dumps the provided pml4_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        dump(page_pool_t &page_pool) const noexcept
        {}
    };
}

#endif
