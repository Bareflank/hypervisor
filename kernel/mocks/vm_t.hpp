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

#ifndef MOCKS_VM_T_HPP
#define MOCKS_VM_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

namespace mk
{
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_VM_FAIL_ALLOCATE{-40001};

    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VM
    ///
    class vm_t final
    {
        /// @brief stores the ID associated with this vm_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores whether or not this vm_t is active.
        bsl::array<bool, HYPERVISOR_MAX_PPS.get()> m_active{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vm_t
        ///
        constexpr void
        initialize(bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(this->id() == syscall::BF_INVALID_ID);

            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the vm_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///
        constexpr void
        release(tls_t const &tls, page_pool_t const &page_pool, ext_pool_t const &ext_pool) noexcept
        {
            this->deallocate(tls, page_pool, ext_pool);
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vm_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///   @return Returns ID of the newly allocated vm_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t const &tls, page_pool_t const &page_pool, ext_pool_t const &ext_pool) noexcept
            -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            bsl::discard(page_pool);
            bsl::discard(ext_pool);

            if (UNIT_TEST_VM_FAIL_ALLOCATE == tls.test_ret) {
                return bsl::safe_u16::failure();
            }

            m_allocated = allocated_status_t::allocated;
            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the ext_pool_t to use
        ///
        constexpr void
        deallocate(
            tls_t const &tls, page_pool_t const &page_pool, ext_pool_t const &ext_pool) noexcept
        {
            bsl::expects(this->is_active(tls).is_invalid());

            bsl::discard(page_pool);
            bsl::discard(ext_pool);

            m_allocated = allocated_status_t::deallocated;
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
        ///   @brief Sets this vm_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_active(tls_t &mut_tls) noexcept
        {
            auto const ppid{bsl::to_idx(mut_tls.ppid)};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vmid);
            bsl::expects(ppid < m_active.size());

            *m_active.at_if(ppid) = true;
            mut_tls.active_vmid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///
        constexpr void
        set_inactive(tls_t &mut_tls) noexcept
        {
            auto const ppid{bsl::to_idx(mut_tls.ppid)};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->id() == mut_tls.active_vmid);
            bsl::expects(ppid < m_active.size());

            *m_active.at_if(ppid) = false;
            mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the first identified PP this vm_t is
        ///     active on. If the vm_t is not active, bsl::safe_u16::failure()
        ///     is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the first identified PP this vm_t is
        ///     active on. If the vm_t is not active, bsl::safe_u16::failure()
        ///     is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t const &tls) const noexcept -> bsl::safe_u16
        {
            auto const online_pps{bsl::to_umx(tls.online_pps)};
            bsl::expects(online_pps <= m_active.size());

            for (bsl::safe_idx mut_i{}; mut_i < online_pps; ++mut_i) {
                if (*m_active.at_if(mut_i)) {
                    return bsl::to_u16(mut_i);
                }

                bsl::touch();
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
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            bsl::expects(bsl::to_umx(tls.ppid) < m_active.size());
            return *m_active.at_if(bsl::to_idx(tls.ppid));
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        static constexpr void
        dump(tls_t const &tls) noexcept
        {
            bsl::discard(tls);
        }
    };
}

#endif
