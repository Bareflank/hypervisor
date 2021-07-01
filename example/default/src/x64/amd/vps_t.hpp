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

#ifndef VPS_T_HPP
#define VPS_T_HPP

#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// @class example::vps_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a VPS
    ///
    class vps_t final
    {
        /// @brief stores the ID associated with this vps_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores the ID of the VP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_vpid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vps_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            /// NOTE:
            /// - The following is a pedantic check to make sure we have
            ///   not already initialized ourselves. In larger extensions,
            ///   this is useful as it helps to weed out hard to find bugs.
            ///   In a small example like this, it is completely overkill,
            ///   but is added for completeness.
            ///

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vps_t already initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            /// NOTE:
            /// - The following are some pedantic checks on the input. In
            ///   larger extensions, this is useful as it helps to weed
            ///   out hard to find bugs. In a small example like this, it
            ///   is completely overkill, but is added for completeness.
            /// - We check to to make sure that we were given a valid ID,
            ///   meaning the safe integral is not storing an error, and we
            ///   also check to make sure the ID itself is not the reserved
            ///   syscall::BF_INVALID_ID as that is also not allowed.
            ///

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == i)) {
                bsl::error() << "id "                                                  // --
                             << bsl::hex(i)                                            // --
                             << " is invalid and cannot be used for initialization"    // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_invalid_argument;
            }

            /// NOTE:
            /// - Finally, store the ID assigned to this vps_t and report
            ///   success.
            ///

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vps_t.
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
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            /// NOTE:
            /// - Release functions are usually only needed in the event of
            ///   an error, or during unit testing.
            ///

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_id = bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Allocates a vps_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the VP to assign the vps_t to
        ///   @param ppid the ID of the PP to assign the vps_t to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            bsl::errc_type mut_ret{};

            /// NOTE:
            /// - The following is a pedantic check to make sure we have
            ///   been initialized by the vp_pool_t. In larger extensions,
            ///   this is useful as it helps to weed out hard to find bugs.
            ///   In a small example like this, it is completely overkill,
            ///   but is added for completeness.
            ///

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            /// NOTE:
            /// - The following is a pedantic check to make sure we have
            ///   not already allocated this vps_t. In larger extensions,
            ///   this is useful as it helps to weed out hard to find bugs.
            ///   In a small example like this, it is completely overkill,
            ///   but is added for completeness.
            ///

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != m_assigned_ppid)) {
                bsl::error() << "vp "                                            // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::errc_precondition;
            }

            /// NOTE:
            /// - The following are some pedantic checks on the input. In
            ///   larger extensions, this is useful as it helps to weed
            ///   out hard to find bugs. In a small example like this, it
            ///   is completely overkill, but is added for completeness.
            /// - We check to to make sure that we were given a valid ID,
            ///   meaning the safe integral is not storing an error, and we
            ///   also check to make sure the ID itself is not the reserved
            ///   syscall::BF_INVALID_ID as that is also not allowed.
            ///

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == vpid)) {
                bsl::error() << "vm "                                              // --
                             << bsl::hex(vpid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                              // --
                             << bsl::hex(ppid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_invalid_argument;
            }

            /// NOTE:
            /// - Initialize the VPS as a root VPS. When the microkernel was
            ///   started, the loader saved the state of the root VP. This
            ///   syscall tells the microkernel to load the VPS with this saved
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
                mut_ret = mut_sys.bf_vps_op_init_as_root(m_id);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                bsl::touch();
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
            ///   VMID that this VPS is assigned to (which is based on which
            ///   VP the VPS is assigned to, as VPs are assigned to VMs and
            ///   VPSs are assigned to VPs).
            ///

            constexpr auto guest_asid_val{0x1_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_guest_asid, guest_asid_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Set up intercept controls. On AMD, we need to intercept
            ///   VMRun, and CPUID if we plan to support reporting and stopping.
            ///

            constexpr auto intercept_instr1_val{0x00040000_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_intercept_instruction1, intercept_instr1_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            constexpr auto intercept_instr2_val{0x00000001_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_intercept_instruction2, intercept_instr2_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Finally, store the IDs of the VP and PP that this vps_t is
            ///   assigned to and reprot success.
            ///

            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;

            return bsl::errc_success;
        }
    };
}

#endif
