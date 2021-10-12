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

#ifndef MOCKS_VM_POOL_T_HPP
#define MOCKS_VM_POOL_T_HPP

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Defines the microkernel's vm_pool_t
    ///
    class vm_pool_t final
    {
        /// @brief stores the pool of vm_t objects
        bsl::array<vm_t, HYPERVISOR_MAX_VMS.get()> m_pool{};

        /// <!-- description -->
        ///   @brief Returns the vm_t associated with the provided vmid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the vm_t to get
        ///   @return Returns the vm_t associated with the provided vmid.
        ///
        [[nodiscard]] constexpr auto
        get_vm(bsl::safe_u16 const &vmid) noexcept -> vm_t *
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vmid));
        }

        /// <!-- description -->
        ///   @brief Returns the vm_t associated with the provided vmid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the vm_t to get
        ///   @return Returns the vm_t associated with the provided vmid.
        ///
        [[nodiscard]] constexpr auto
        get_vm(bsl::safe_u16 const &vmid) const noexcept -> vm_t const *
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vmid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_pool_t
        ///
        constexpr void
        initialize() noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vm_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t const &page_pool, ext_pool_t const &ext_pool) noexcept
        {
            for (auto &mut_vm : m_pool) {
                mut_vm.release(mut_tls, page_pool, ext_pool);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a vm_t from the vm_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @return Returns ID of the newly allocated vm_t. Returns
        ///     bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &mut_tls, page_pool_t const &page_pool, ext_pool_t const &ext_pool) noexcept
            -> bsl::safe_u16
        {
            for (auto &mut_vm : m_pool) {
                if (mut_vm.is_deallocated()) {
                    return mut_vm.allocate(mut_tls, page_pool, ext_pool);
                }

                bsl::touch();
            }

            bsl::error() << "vm_pool_t out of vms\n" << bsl::here();
            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Deallocates a vm from the vm_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @param vmid the ID of the vm_t to deallocate
        ///
        constexpr void
        deallocate(
            tls_t &mut_tls,
            page_pool_t const &page_pool,
            ext_pool_t const &ext_pool,
            bsl::safe_u16 const &vmid) noexcept
        {
            this->get_vm(vmid)->deallocate(mut_tls, page_pool, ext_pool);
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vm_t is deallocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the vm_t to query
        ///   @return Returns true if the requested vm_t is deallocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(bsl::safe_u16 const &vmid) const noexcept -> bool
        {
            return this->get_vm(vmid)->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vm_t is allocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the vm_t to query
        ///   @return Returns true if the requested vm_t is allocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated(bsl::safe_u16 const &vmid) const noexcept -> bool
        {
            return this->get_vm(vmid)->is_allocated();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vm_t as active
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param vmid the ID of the vm_t to set as active
        ///
        constexpr void
        set_active(tls_t &mut_tls, bsl::safe_u16 const &vmid) noexcept
        {
            this->get_vm(vmid)->set_active(mut_tls);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vm_t as inactive
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param vmid the ID of the vm_t to set as inactive
        ///
        constexpr void
        set_inactive(tls_t &mut_tls, bsl::safe_u16 const &vmid) noexcept
        {
            if (bsl::unlikely(vmid == syscall::BF_INVALID_ID)) {
                return;
            }

            this->get_vm(vmid)->set_inactive(mut_tls);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the first identified PP the requested
        ///     vm_t is active on. If the vm_t is not active,
        ///     bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID of the vm_t to query
        ///   @return Returns the ID of the first identified PP the requested
        ///     vm_t is active on. If the vm_t is not active,
        ///     bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t const &tls, bsl::safe_u16 const &vmid) const noexcept -> bsl::safe_u16
        {
            return this->get_vm(vmid)->is_active(tls);
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vm_t is active on the
        ///     current PP, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID of the vm_t to query
        ///   @return Returns true if the requested vm_t is active on the
        ///     current PP, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls, bsl::safe_u16 const &vmid) const noexcept -> bool
        {
            return this->get_vm(vmid)->is_active_on_this_pp(tls);
        }

        /// <!-- description -->
        ///   @brief Dumps the requested vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID of the vm_t to dump
        ///
        static constexpr void
        dump(tls_t const &tls, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(vmid);
        }
    };
}

#endif
