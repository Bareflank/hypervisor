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

#ifndef VP_POOL_T_HPP
#define VP_POOL_T_HPP

#include <bf_constants.hpp>
#include <lock_guard_t.hpp>
#include <spinlock_t.hpp>
#include <tls_t.hpp>
#include <vp_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Defines the microkernel's vp_pool_t
    ///
    class vp_pool_t final
    {
        /// @brief stores the pool of vp_t objects
        bsl::array<vp_t, HYPERVISOR_MAX_VSS.get()> m_pool{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock{};

        /// <!-- description -->
        ///   @brief Returns the vp_t associated with the provided vpid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to get
        ///   @return Returns the vp_t associated with the provided vpid.
        ///
        [[nodiscard]] constexpr auto
        get_vp(bsl::safe_u16 const &vpid) noexcept -> vp_t *
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vpid));
        }

        /// <!-- description -->
        ///   @brief Returns the vp_t associated with the provided vpid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to get
        ///   @return Returns the vp_t associated with the provided vpid.
        ///
        [[nodiscard]] constexpr auto
        get_vp(bsl::safe_u16 const &vpid) const noexcept -> vp_t const *
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vpid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vp_pool_t
        ///
        constexpr void
        initialize() noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vp_pool_t
        ///
        constexpr void
        release() noexcept
        {
            for (auto &mut_vp : m_pool) {
                mut_vp.release();
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a vp_t from the vp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid The ID of the VM to assign the newly allocated vp_t to
        ///   @return Returns ID of the newly allocated vp_t. Returns
        ///     bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t const &tls, bsl::safe_u16 const &vmid) noexcept -> bsl::safe_u16
        {
            lock_guard_t mut_lock{tls, m_lock};

            for (auto &mut_vp : m_pool) {
                if (mut_vp.is_deallocated()) {
                    return mut_vp.allocate(vmid);
                }

                bsl::touch();
            }

            bsl::error() << "vp_pool_t out of vs\n" << bsl::here();
            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Deallocates the requested vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpid the ID of the vp_t to deallocate
        ///
        constexpr void
        deallocate(tls_t const &tls, bsl::safe_u16 const &vpid) noexcept
        {
            lock_guard_t mut_lock{tls, m_lock};
            this->get_vp(vpid)->deallocate();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vp_t is deallocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns true if the requested vp_t is deallocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(bsl::safe_u16 const &vpid) const noexcept -> bool
        {
            return this->get_vp(vpid)->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vp_t is allocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns true if the requested vp_t is allocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated(bsl::safe_u16 const &vpid) const noexcept -> bool
        {
            return this->get_vp(vpid)->is_allocated();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vp_t as active
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param vpid the ID of the vp_t to set as active
        ///
        constexpr void
        set_active(tls_t &mut_tls, bsl::safe_u16 const &vpid) noexcept
        {
            this->get_vp(vpid)->set_active(mut_tls);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vp_t as inactive
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param vpid the ID of the vp_t to set as inactive
        ///
        constexpr void
        set_inactive(tls_t &mut_tls, bsl::safe_u16 const &vpid) noexcept
        {
            if (bsl::unlikely(vpid == syscall::BF_INVALID_ID)) {
                return;
            }

            this->get_vp(vpid)->set_inactive(mut_tls);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vp_t is active on.
        ///     If the vp_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns the ID of the PP the requested vp_t is active on.
        ///     If the vp_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(bsl::safe_u16 const &vpid) const noexcept -> bsl::safe_u16
        {
            return this->get_vp(vpid)->is_active();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vp_t is active on the
        ///     current PP, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns true if the requested vp_t is active on the
        ///     current PP, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls, bsl::safe_u16 const &vpid) const noexcept -> bool
        {
            return this->get_vp(vpid)->is_active_on_this_pp(tls);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM the requested vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns the ID of the VM the requested vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vm(bsl::safe_u16 const &vpid) const noexcept -> bsl::safe_u16
        {
            return this->get_vp(vpid)->assigned_vm();
        }

        /// <!-- description -->
        ///   @brief If the requested VM is assigned to a vp_t in the pool,
        ///     the ID of the first vp_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID fo the VM to query
        ///   @return If the requested VM is assigned to a vp_t in the pool,
        ///     the ID of the first vp_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        vp_assigned_to_vm(bsl::safe_u16 const &vmid) const noexcept -> bsl::safe_u16
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);

            for (auto const &vp : m_pool) {
                if (vp.assigned_vm() == vmid) {
                    return vp.id();
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Dumps the requested vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to dump
        ///
        constexpr void
        dump(bsl::safe_u16 const &vpid) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            this->get_vp(vpid)->dump();
        }
    };
}

#endif
