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

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Returns the masked version of the VMCS control fields
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value of the control fields read from the MSRs
    ///   @return The masked version of the control fields.
    ///
    [[nodiscard]] constexpr auto
    ctls_mask(bsl::safe_uint64 const &val) noexcept -> bsl::safe_uint64
    {
        constexpr auto mask{0x00000000FFFFFFFF_u64};
        constexpr auto shift{32_u64};
        return (val & mask) & (val >> shift);
    };

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
                bsl::error() << "vp "                                               // --
                             << bsl::hex(vpid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

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
            /// - Set up VPID
            ///

            constexpr auto vmcs_vpid_val{0x1_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier, vmcs_vpid_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Set up the VMCS link pointer
            ///

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer, vmcs_link_ptr_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Set up the VMCS pin based, proc based, exit and entry controls
            /// - We turn on MSR bitmaps so that we do not trap on MSR reads and
            ///   writes. If you do not configure this, or you use the bitmap
            ///   to trap to specific MSR accesses, make sure you keep the VMCS
            ///   in sync with your MSR mods. Any MSR that is in the VMCS also
            ///   needs to be written to the VMCS, otherwise, VMEntry/VMExit will
            ///   replace any values you write.
            /// - We also turn on secondary controls so that we can turn on VPID,
            ///   and turn on instructions that the OS is relying on, like
            ///   RDTSCP. Failure to do this will cause the invalid opcodes to
            ///   occur.
            /// - The lambda below performs the MSR conversion of the CTLS
            ///   registers to determine the bits that must always be set to 1,
            ///   and the bits that must always be set to 0. This allows us to
            ///   turn on as much as possible, letting the MSRs decide what is
            ///   allowed and what is not.
            /// - Also note that we do not attempt to detect support for the
            ///   secondary controls. This is because the loader ensures that
            ///   this support is present as it is a minimum requirement for the
            ///   project.
            ///

            constexpr auto ia32_vmx_true_pinbased_ctls{0x48D_u32};
            constexpr auto ia32_vmx_true_procbased_ctls{0x48E_u32};
            constexpr auto ia32_vmx_true_exit_ctls{0x48F_u32};
            constexpr auto ia32_vmx_true_entry_ctls{0x490_u32};
            constexpr auto ia32_vmx_true_procbased_ctls2{0x48B_u32};

            bsl::safe_uintmax mut_ctls{};

            /// NOTE:
            /// - Configure the pin based controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_pinbased_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Configure the proc based controls
            ///

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_procbased_ctls2{0x80000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_msr_bitmaps;
            mut_ctls |= enable_procbased_ctls2;

            mut_ret = mut_sys.bf_vps_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Configure the exit controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_exit_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmexit_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Configure the entry controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_entry_ctls);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmentry_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Configure the secondary proc controls.
            ///

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls2);
            if (bsl::unlikely_assert(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_vpid;
            mut_ctls |= enable_rdtscp;
            mut_ctls |= enable_invpcid;
            mut_ctls |= enable_xsave;
            mut_ctls |= enable_uwait;

            mut_ret = mut_sys.bf_vps_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Configure the MSR bitmaps. This ensures that we do not trap
            ///   on MSR reads and writes. Also note that in most applications,
            ///   you only need one of these, regardless of the total number of
            ///   CPUs you are running on.
            ///

            mut_ret = mut_sys.bf_vps_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps, gs.msr_bitmap_phys);
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

            return mut_ret;
        }
    };
}

#endif
