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

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::vp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VP pool
    ///
    class vp_pool_t final
    {
        /// @brief stores the pool of vp_t objects
        bsl::array<vp_t, HYPERVISOR_MAX_VPS.get()> m_pool{};

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
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(gs, tls, sys, intrinsic, bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vp_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            for (auto &mut_vp : m_pool) {
                mut_vp.release(gs, tls, sys, intrinsic);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a VP and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the VM to assign the newly created VP to
        ///   @param ppid the ID of the PP to assign the newly created VP to
        ///   @return Returns the ID of the newly created VP on
        ///     success, or bsl::safe_u16::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            /// NOTE:
            /// - Ask the microkernel to create a VP and return the ID of the
            ///   newly created VP. We do not check in this function if the
            ///   provided vmid or ppid are valid as this is done by the
            ///   bf_vp_op_create_vp. We only need to check these types of
            ///   inputs at the point of use, and not when we are just passing
            ///   them to another function.
            ///

            auto const vpid{mut_sys.bf_vp_op_create_vp(vmid, ppid)};
            if (bsl::unlikely(vpid.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            /// NOTE:
            /// - The following is used in the event of an error. Basically,
            ///   whatever is in the bsl::finally will execute once the
            ///   function is returned from unless we explicitly call the
            ///   ignore() function, which we do at the end when all is good.
            ///

            bsl::finally mut_destroy_vp_on_error{[&mut_sys, &vpid]() noexcept -> void {
                bsl::discard(mut_sys.bf_vp_op_destroy_vp(vpid));
            }};

            /// NOTE:
            /// - Get the vp_t that was allocated by the microkernel.
            ///

            auto *const pmut_vp{m_pool.at_if(bsl::to_idx(vpid))};
            bsl::expects(nullptr != pmut_vp);

            /// NOTE:
            /// - Finally, we need to allocate the VP in our pool. This will
            ///   simply tell the VP which VM and PP it is assigned to. We
            ///   can use this in more complicated extensions, and it also
            ///   serves to make sure that we have not allocated the same VP
            ///   more than once.
            ///

            auto const ret{pmut_vp->allocate(gs, tls, mut_sys, intrinsic, vmid, ppid)};
            if (bsl::unlikely(ret.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            mut_destroy_vp_on_error.ignore();
            return vpid;
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
            this->get_vp(vpid)->deallocate(gs, tls, sys, intrinsic);
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
    };
}

#endif
