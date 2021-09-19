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

#ifndef MOCKS_VP_POOL_T_HPP
#define MOCKS_VP_POOL_T_HPP

#include <allocated_status_t.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unordered_map.hpp>

namespace example
{
    /// @class example::vp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VP pool
    ///
    class vp_pool_t final
    {
        /// @brief stores the id that will be returned on allocate
        bsl::safe_u16 m_id{};
        /// @brief stores the return value of allocate()
        bsl::unordered_map<bsl::safe_u16, bool> m_allocate_fails{};
        /// @brief stores the return value of is_allocated()
        bsl::unordered_map<bsl::safe_u16, allocated_status_t> m_allocated{};
        /// @brief stores the return value of assigned_vm()
        bsl::unordered_map<bsl::safe_u16, bsl::safe_u16> m_assigned_vmid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vp_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        static constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
        }

        /// <!-- description -->
        ///   @brief Allocates a VP and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vp_t. Returns
        ///     bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid) noexcept -> bsl::safe_u16
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            if (m_allocate_fails.at(vmid)) {
                return bsl::safe_u16::failure();
            }

            auto const id{m_id};
            m_id = (m_id + bsl::safe_u16::magic_1()).checked();

            m_assigned_vmid.at(id) = vmid;
            m_allocated.at(id) = allocated_status_t::allocated;

            return id;
        }

        /// <!-- description -->
        ///   @brief Tells the allocate() function to return a failure
        ///     for the provided vmid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the VM to assign the newly created VP to
        ///
        constexpr void
        set_allocate_fails(bsl::safe_u16 const &vmid) noexcept
        {
            m_allocate_fails.at(vmid) = true;
        }

        /// <!-- description -->
        ///   @brief Deallocates the requested vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the vp_t to deallocate
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vpid) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::discard(m_assigned_vmid.erase(vpid));
            bsl::discard(m_allocated.erase(vpid));
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
            return m_allocated.at(vpid) == allocated_status_t::allocated;
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
            return m_allocated.at(vpid) == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM the requested vp_t is assigned
        ///     to. If the vp_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the vp_t to query
        ///   @return Returns the ID of the VM the requested vp_t is assigned
        ///     to. If the vp_t is not assigned, syscall::BF_INVALID_ID is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm(bsl::safe_u16 const &vpid) const noexcept -> bsl::safe_u16
        {
            if (!m_assigned_vmid.contains(vpid)) {
                return syscall::BF_INVALID_ID;
            }

            return m_assigned_vmid.at(vpid);
        }
    };
}

#endif
