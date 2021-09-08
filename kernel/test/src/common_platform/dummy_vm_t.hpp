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

#ifndef VM_T_BASE_HPP
#define VM_T_BASE_HPP

#include "dummy_errc_types.hpp"

#include <allocated_status_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @class mk::dummy_vm_t
    ///
    /// <!-- description -->
    ///   @brief Provides the vm_t for testing.
    ///
    class dummy_vm_t final
    {
        /// @brief stores the ID associated with this vm_t
        bsl::safe_u16 m_id{bsl::safe_u16::failure()};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores whether or not this vm_t is active.
        bool m_active{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param i the ID for this vm_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &tls, bsl::safe_u16 const &i) noexcept -> bsl::errc_type
        {
            if (tls.test_ret == errc_fail_initialize) {
                return bsl::errc_failure;
            }

            if (tls.test_ret == errc_fail_initialize_and_release) {
                return bsl::errc_failure;
            }

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vm_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param ext_pool the ext_pool_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &tls, ext_pool_t &ext_pool, vp_pool_t &vp_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(ext_pool);
            bsl::discard(vp_pool);

            if (tls.test_ret == errc_fail_initialize_and_release) {
                return bsl::errc_failure;
            }

            if (tls.test_ret == errc_fail_release) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Allocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param ext_pool the ext_pool_t to use
        ///   @return Returns ID of the newly allocated vm
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &tls, ext_pool_t &ext_pool) noexcept -> bsl::safe_u16
        {
            bsl::discard(ext_pool);

            if (!tls.test_ret) {
                return bsl::safe_u16::failure();
            }

            m_allocated = allocated_status_t::allocated;
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param ext_pool the ext_pool_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &tls, ext_pool_t &ext_pool, vp_pool_t &vp_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(ext_pool);
            bsl::discard(vp_pool);

            m_allocated = allocated_status_t::deallocated;
            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t's status as zombified, meaning it is no
        ///     longer usable.
        ///
        constexpr void
        zombify() noexcept
        {
            m_allocated = allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &tls) noexcept -> bsl::errc_type
        {
            m_active = true;
            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &tls) noexcept -> bsl::errc_type
        {
            m_active = {};
            return tls.test_ret;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the first PP identified that this VM
        ///     is still active on. If the VM is inactive, this function
        ///     returns bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the first PP identified that this VM
        ///     is still active on. If the VM is inactive, this function
        ///     returns bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t &tls) const noexcept -> bsl::safe_u16
        {
            bsl::discard(tls);

            if (m_active) {
                return {};
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t &tls) const noexcept -> bool
        {
            bsl::discard(tls);
            return m_active;
        }

        // <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        dump(tls_t &tls) const noexcept
        {
            bsl::discard(tls);
        }
    };
}

#endif
