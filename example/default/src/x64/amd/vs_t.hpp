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

#ifndef VS_T_HPP
#define VS_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @class example::vs_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a VS
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vs_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vs_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the ID of the VP this vs_t is assigned to
        bsl::safe_u16 m_assigned_vpid{};
        /// @brief stores the ID of the PP this vs_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vs_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_id = i;
        }

        /// <!-- description -->
        ///   @brief Release the vs_t.
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
            this->deallocate(gs, tls, sys, intrinsic);
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vs_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16 const &
        {
            bsl::ensures(m_id.is_valid_and_checked());
            bsl::ensures(m_id != syscall::BF_INVALID_ID);
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates the vs_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the VP to assign the vs_t to
        ///   @param ppid the ID of the PP to assign the vs_t to
        ///   @return Returns ID of the newly allocated vs_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            /// NOTE:
            /// - Initialize the VS as a root VS. When the microkernel was
            ///   started, the loader saved the state of the root VP. This
            ///   syscall tells the microkernel to load the VS with this saved
            ///   state so that when we run the VP, it will contain the state
            ///   just before the microkernel was started.
            /// - In other words, this is what allows the microkernel to return
            ///   back to the loader once the hypervisor is running.
            /// - You only want to run this on root VPs. VPs that are being
            ///   created for guest VPs should not use this, as it would give
            ///   the guest VP the state associated with the root VP. Also
            ///   note that once the root VP has executed, this ABI is no
            ///   longer useful as the state stored in the microkernel would be
            ///   out-dated. For root VPs, that ID of the PP should always be
            ///   the same as the IP of the VP, so we added this check for
            ///   completeness just in case cut/paste is used here.
            ///

            if (ppid == m_id) {
                bsl::expects(mut_sys.bf_vs_op_init_as_root(m_id));
            }
            else {

                /// NOTE:
                /// - The call to bsl::touch is only needed if you plan to
                ///   enforce MC/DC unit testing. Feel free to remove this if
                ///   you have no plans to support MC/DC unit testing.
                ///

                bsl::touch();
            }

            /// NOTE:
            /// - Set up ASID. For this simple example, we will use "1", but
            ///   in most cases you will want to use something based on the
            ///   VMID that this VS is assigned to (which is based on which
            ///   VP the VS is assigned to, as VPs are assigned to VMs and
            ///   VSs are assigned to VPs).
            ///

            constexpr auto guest_asid_val{0x1_u64};
            constexpr auto guest_asid_idx{syscall::bf_reg_t::bf_reg_t_guest_asid};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, guest_asid_idx, guest_asid_val));

            /// NOTE:
            /// - Set up intercept controls. On AMD, we need to intercept
            ///   VMRun, and CPUID if we plan to support reporting and stopping.
            ///

            constexpr auto intercept1_val{0x00040000_u64};
            constexpr auto intercept1_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction1};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, intercept1_idx, intercept1_val));

            constexpr auto intercept2_val{0x00000001_u64};
            constexpr auto intercept2_idx{syscall::bf_reg_t::bf_reg_t_intercept_instruction2};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, intercept2_idx, intercept2_val));

            /// NOTE:
            /// - Finally, store the IDs of the VP and PP that this vs_t is
            ///   assigned to and reprot success.
            ///

            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates the vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(m_allocated != allocated_status_t::deallocated);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_allocated = allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vp_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vp_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vp_t is assigned to. If
        ///     vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vp_t is assigned to If
        ///     vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vpid.is_valid_and_checked());
            return ~m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vp_t is assigned to If
        ///     vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vp_t is assigned to If
        ///     vp_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }
    };
}

#endif
