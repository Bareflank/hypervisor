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
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

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
            bsl::expects(this->id() == syscall::BF_INVALID_ID);
            bsl::expects(m_allocated == allocated_status_t::deallocated);

            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_id = ~i;
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
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
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
        ///   @return Returns ID of this vs_t
        ///
        [[maybe_unused]] constexpr auto
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            syscall::bf_reg_t mut_idx{};
            auto const vsid{this->id()};

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);

            auto const vmcs_vpid_val{bsl::safe_u64::magic_1()};
            constexpr auto vmcs_vpid_idx{syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, vmcs_vpid_idx, vmcs_vpid_val));

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            constexpr auto vmcs_link_ptr_idx{syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer};
            bsl::expects(mut_sys.bf_vs_op_write(vsid, vmcs_link_ptr_idx, vmcs_link_ptr_val));

            bsl::safe_u64 mut_pin_ctls{};
            bsl::safe_u64 mut_proc_ctls{};
            bsl::safe_u64 mut_exit_ctls{};
            bsl::safe_u64 mut_entry_ctls{};
            bsl::safe_u64 mut_proc2_ctls{};

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_proc2_ctls{0x80000000_u64};

            mut_proc_ctls |= enable_msr_bitmaps;
            mut_proc_ctls |= enable_proc2_ctls;

            constexpr auto enable_ia32e_mode{0x00000200_u64};

            mut_entry_ctls |= enable_ia32e_mode;

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_proc2_ctls |= enable_vpid;
            mut_proc2_ctls |= enable_rdtscp;
            mut_proc2_ctls |= enable_invpcid;
            mut_proc2_ctls |= enable_xsave;
            mut_proc2_ctls |= enable_uwait;

            mut_idx = syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mut_idx, mut_pin_ctls));

            mut_idx = syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mut_idx, mut_proc_ctls));

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmexit_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mut_idx, mut_exit_ctls));

            mut_idx = syscall::bf_reg_t::bf_reg_t_vmentry_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mut_idx, mut_entry_ctls));

            mut_idx = syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls;
            bsl::expects(mut_sys.bf_vs_op_write(vsid, mut_idx, mut_proc2_ctls));

            if (mut_sys.is_vs_a_root_vs(vsid)) {
                bsl::expects(mut_sys.bf_vs_op_init_as_root(vsid));
            }
            else {
                bsl::touch();
            }

            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            return vsid;
        }

        /// <!-- description -->
        ///   @brief Deallocates the vs_t
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
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_allocated = allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vpid.is_valid_and_checked());
            return ~m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is assigned to. If
        ///     this vs_t is not assigned, syscall::BF_INVALID_ID is returned.
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
