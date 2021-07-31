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
#include <bsl/unlikely.hpp>

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
    ctls_mask(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
    {
        constexpr auto mask{0x00000000FFFFFFFF_u64};
        constexpr auto shift{32_u64};
        return ((val & mask) & (val >> shift)).checked();
    };

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
            /// - Set up VPID
            ///

            constexpr auto vmcs_vpid_val{0x1_u64};
            constexpr auto vmcs_vpid_idx{syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, vmcs_vpid_idx, vmcs_vpid_val));

            /// NOTE:
            /// - Set up the VMCS link pointer
            ///

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            constexpr auto vmcs_link_ptr_idx{syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, vmcs_link_ptr_idx, vmcs_link_ptr_val));

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

            bsl::safe_umx mut_ctls{};
            syscall::bf_reg_t mut_idx{};

            /// NOTE:
            /// - Configure the pin based controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_pinbased_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(m_id, mut_idx, ctls_mask(mut_ctls)));

            /// NOTE:
            /// - Configure the proc based controls
            ///

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_procbased_ctls2{0x80000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_ctls |= enable_msr_bitmaps;
            mut_ctls |= enable_procbased_ctls2;

            mut_idx = syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(m_id, mut_idx, ctls_mask(mut_ctls)));

            /// NOTE:
            /// - Configure the exit controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_exit_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmexit_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(m_id, mut_idx, ctls_mask(mut_ctls)));

            /// NOTE:
            /// - Configure the entry controls
            ///

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_entry_ctls);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmentry_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(m_id, mut_idx, ctls_mask(mut_ctls)));

            /// NOTE:
            /// - Configure the secondary proc controls.
            ///

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_ctls = mut_sys.bf_intrinsic_op_rdmsr(ia32_vmx_true_procbased_ctls2);
            bsl::expects(mut_ctls.is_valid_and_checked());

            mut_ctls |= enable_vpid;
            mut_ctls |= enable_rdtscp;
            mut_ctls |= enable_invpcid;
            mut_ctls |= enable_xsave;
            mut_ctls |= enable_uwait;

            mut_idx = syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(m_id, mut_idx, ctls_mask(mut_ctls)));

            /// NOTE:
            /// - Configure the MSR bitmaps. This ensures that we do not trap
            ///   on MSR reads and writes. Also note that in most applications,
            ///   you only need one of these, regardless of the total number of
            ///   CPUs you are running on.
            ///

            constexpr auto msr_bitmaps_idx{syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps};
            bsl::expects(mut_sys.bf_vs_op_write(m_id, msr_bitmaps_idx, gs.msr_bitmap_phys));

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
