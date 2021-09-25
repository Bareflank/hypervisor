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
#include <bf_reg_t.hpp>
#include <general_purpose_regs_t.hpp>
#include <intrinsic_t.hpp>
#include <missing_registers_t.hpp>
#include <page_pool_t.hpp>
#include <running_status_t.hpp>
#include <tls_t.hpp>
#include <vmcb_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::vs_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VS.
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vs_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vs_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the status of the vs_t
        running_status_t m_status{};
        /// @brief stores the ID of the VP this vs_t is assigned to
        bsl::safe_u16 m_assigned_vpid{};
        /// @brief stores the ID of the PP this vs_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the ID of the PP this vs_t is active on
        bsl::safe_u16 m_active_ppid{};

        /// @brief stores a pointer to the guest VMCB being managed by this VS
        vmcb_t *m_guest_vmcb{};
        /// @brief stores the physical address of the guest VMCB
        bsl::safe_umx m_guest_vmcb_phys{};
        /// @brief stores a pointer to the host VMCB being managed by this VS
        vmcb_t *m_host_vmcb{};
        /// @brief stores the physical address of the host VMCB
        bsl::safe_umx m_host_vmcb_phys{};
        /// @brief stores the general purpose registers
        general_purpose_regs_t m_gprs{};
        /// @brief stores the VMCB missing registers
        missing_registers_t m_missing_registers{};

        /// <!-- description -->
        ///   @brief Returns the row color based on the value of "val"
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of field to query
        ///   @param val the field to query
        ///   @return Returns the row color based on the value of "val"
        ///
        template<typename T>
        [[nodiscard]] static constexpr auto
        get_row_color(bsl::safe_integral<T> const &val) noexcept -> bsl::string_view
        {
            if (val.is_zero()) {
                return bsl::blk;
            }

            return bsl::rst;
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of a field
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of field to dump
        ///   @param str the name of the field
        ///   @param val the field to dump
        ///
        template<typename T>
        static constexpr void
        dump_field(bsl::string_view const &str, bsl::safe_integral<T> const &val) noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            auto const rowcolor{get_row_color(val)};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<30s", str};
            bsl::print() << bsl::ylw << "| ";

            if constexpr (bsl::is_same<T, bsl::uint8>::value) {
                bsl::print() << rowcolor << "       " << bsl::hex(val) << "        ";
            }

            if constexpr (bsl::is_same<T, bsl::uint16>::value) {
                bsl::print() << rowcolor << "      " << bsl::hex(val) << "       ";
            }

            if constexpr (bsl::is_same<T, bsl::uint32>::value) {
                bsl::print() << rowcolor << "    " << bsl::hex(val) << "     ";
            }

            if constexpr (bsl::is_same<T, bsl::uint64>::value) {
                bsl::print() << rowcolor << bsl::hex(val) << ' ';
            }

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Converts attributes in the form 0xF0FF to the form
        ///     0x0FFF.
        ///
        /// <!-- inputs/outputs -->
        ///   @param attrib the attrib to compress
        ///   @return Returns the compressed version of attrib
        ///
        [[nodiscard]] static constexpr auto
        compress_attrib(bsl::safe_u16 const &attrib) noexcept -> bsl::safe_u16
        {
            constexpr auto mask1{0x00FF_u16};
            constexpr auto mask2{0xF000_u16};
            constexpr auto shift{4_u16};

            return (attrib & mask1) | ((attrib & mask2) >> shift);
        }

        /// <!-- description -->
        ///   @brief Converts attributes in the form 0x0FFF to the form
        ///     0xF0FF.
        ///
        /// <!-- inputs/outputs -->
        ///   @param attrib the attrib to decompress
        ///   @return Returns the decompressed version of attrib
        ///
        [[nodiscard]] static constexpr auto
        decompress_attrib(bsl::safe_u16 const &attrib) noexcept -> bsl::safe_u16
        {
            constexpr auto mask1{0x00FF_u16};
            constexpr auto mask2{0x0F00_u16};
            constexpr auto shift{4_u16};

            return (attrib & mask1) | ((attrib & mask2) << shift);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of EFER
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of EFER
        ///
        [[nodiscard]] static constexpr auto
        sanitize_efer(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
        {
            constexpr auto efer_mask{0x0000000000001000_u64};
            return val | efer_mask;
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of XCR0
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of XCR0
        ///
        [[nodiscard]] static constexpr auto
        sanitize_xcr0(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
        {
            constexpr auto efer_mask{0x0000000000000001_u64};
            return val | efer_mask;
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vs_t
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
        ///   @brief Release the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept
        {
            this->deallocate(mut_tls, mut_page_pool);
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
        ///   @brief Allocates this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid The ID of the VP to assign the newly allocated vs_t to
        ///   @param ppid The ID of the PP to assign the newly allocated vs_t to
        ///   @return Returns ID of the newly allocated vs_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::discard(intrinsic);

            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);
            bsl::expects(running_status_t::initial == m_status);

            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            bsl::finally mut_cleanup_on_error{[this, &mut_tls, &mut_page_pool]() noexcept -> void {
                this->deallocate(mut_tls, mut_page_pool);
            }};

            m_guest_vmcb = mut_page_pool.template allocate<vmcb_t>(mut_tls);
            if (bsl::unlikely(nullptr == m_guest_vmcb)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            m_guest_vmcb_phys = mut_page_pool.virt_to_phys(m_guest_vmcb);
            bsl::expects(m_guest_vmcb_phys.is_valid_and_checked());

            m_host_vmcb = mut_page_pool.template allocate<vmcb_t>(mut_tls);
            if (bsl::unlikely(nullptr == m_host_vmcb)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            m_host_vmcb_phys = mut_page_pool.virt_to_phys(m_host_vmcb);
            bsl::expects(m_host_vmcb_phys.is_valid_and_checked());

            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            mut_cleanup_on_error.ignore();
            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        deallocate(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept
        {
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->is_active().is_invalid());

            m_missing_registers = {};
            m_gprs = {};

            mut_page_pool.deallocate(mut_tls, m_host_vmcb);
            m_host_vmcb = {};
            m_host_vmcb_phys = {};

            mut_page_pool.deallocate(mut_tls, m_guest_vmcb);
            m_guest_vmcb = {};
            m_guest_vmcb_phys = {};

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_status = running_status_t::initial;
            m_allocated = allocated_status_t::deallocated;
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
        ///   @brief Sets this vs_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(m_gprs.rax));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(m_gprs.rbx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(m_gprs.rcx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(m_gprs.rdx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(m_gprs.rbp));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(m_gprs.rsi));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(m_gprs.rdi));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(m_gprs.r8));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(m_gprs.r9));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(m_gprs.r10));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(m_gprs.r11));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(m_gprs.r12));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(m_gprs.r13));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(m_gprs.r14));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(m_gprs.r15));

            m_active_ppid = ~bsl::to_u16(mut_tls.ppid);
            mut_tls.active_vsid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_inactive(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->id() == mut_tls.active_vsid);

            m_gprs.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
            m_gprs.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
            m_gprs.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
            m_gprs.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
            m_gprs.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
            m_gprs.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
            m_gprs.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
            m_gprs.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
            m_gprs.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
            m_gprs.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
            m_gprs.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
            m_gprs.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
            m_gprs.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
            m_gprs.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
            m_gprs.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();

            m_active_ppid = {};
            mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active() const noexcept -> bsl::safe_u16
        {
            if (m_active_ppid.is_pos()) {
                return ~m_active_ppid;
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            return tls.ppid == ~m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Migrates this vs_t from one PP to another
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            auto const ret{this->clear(tls, intrinsic)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_assigned_ppid = ~ppid;
            return ret;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vs_t is assigned to. If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vpid.is_valid_and_checked());
            return ~m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param state the state to set the vs_t to
        ///
        constexpr void
        state_save_to_vs(
            tls_t const &tls,
            intrinsic_t &mut_intrinsic,
            loader::state_save_t const *const state) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(nullptr != state);

            if (tls.active_vsid == this->id()) {
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(state->rax));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(state->rbx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(state->rcx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(state->rdx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(state->rbp));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(state->rsi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(state->rdi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(state->r8));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(state->r9));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(state->r10));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(state->r11));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(state->r12));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(state->r13));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(state->r14));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(state->r15));
            }
            else {
                m_gprs.rax = state->rax;
                m_gprs.rbx = state->rbx;
                m_gprs.rcx = state->rcx;
                m_gprs.rdx = state->rdx;
                m_gprs.rbp = state->rbp;
                m_gprs.rsi = state->rsi;
                m_gprs.rdi = state->rdi;
                m_gprs.r8 = state->r8;
                m_gprs.r9 = state->r9;
                m_gprs.r10 = state->r10;
                m_gprs.r11 = state->r11;
                m_gprs.r12 = state->r12;
                m_gprs.r13 = state->r13;
                m_gprs.r14 = state->r14;
                m_gprs.r15 = state->r15;
            }

            m_guest_vmcb->rsp = state->rsp;
            m_guest_vmcb->rip = state->rip;

            m_guest_vmcb->rflags = state->rflags;

            m_guest_vmcb->gdtr_limit = bsl::to_u32(state->gdtr.limit).get();
            m_guest_vmcb->gdtr_base = state->gdtr.base;
            m_guest_vmcb->idtr_limit = bsl::to_u32(state->idtr.limit).get();
            m_guest_vmcb->idtr_base = state->idtr.base;

            m_guest_vmcb->es_selector = state->es_selector;
            m_guest_vmcb->es_attrib = compress_attrib(bsl::to_u16(state->es_attrib)).get();
            m_guest_vmcb->es_limit = state->es_limit;
            m_guest_vmcb->es_base = state->es_base;

            m_guest_vmcb->cs_selector = state->cs_selector;
            m_guest_vmcb->cs_attrib = compress_attrib(bsl::to_u16(state->cs_attrib)).get();
            m_guest_vmcb->cs_limit = state->cs_limit;
            m_guest_vmcb->cs_base = state->cs_base;

            m_guest_vmcb->ss_selector = state->ss_selector;
            m_guest_vmcb->ss_attrib = compress_attrib(bsl::to_u16(state->ss_attrib)).get();
            m_guest_vmcb->ss_limit = state->ss_limit;
            m_guest_vmcb->ss_base = state->ss_base;

            m_guest_vmcb->ds_selector = state->ds_selector;
            m_guest_vmcb->ds_attrib = compress_attrib(bsl::to_u16(state->ds_attrib)).get();
            m_guest_vmcb->ds_limit = state->ds_limit;
            m_guest_vmcb->ds_base = state->ds_base;

            m_guest_vmcb->fs_selector = state->fs_selector;
            m_guest_vmcb->fs_attrib = compress_attrib(bsl::to_u16(state->fs_attrib)).get();
            m_guest_vmcb->fs_limit = state->fs_limit;
            m_guest_vmcb->fs_base = state->fs_base;

            m_guest_vmcb->gs_selector = state->gs_selector;
            m_guest_vmcb->gs_attrib = compress_attrib(bsl::to_u16(state->gs_attrib)).get();
            m_guest_vmcb->gs_limit = state->gs_limit;
            m_guest_vmcb->gs_base = state->gs_base;

            m_guest_vmcb->ldtr_selector = state->ldtr_selector;
            m_guest_vmcb->ldtr_attrib = compress_attrib(bsl::to_u16(state->ldtr_attrib)).get();
            m_guest_vmcb->ldtr_limit = state->ldtr_limit;
            m_guest_vmcb->ldtr_base = state->ldtr_base;

            m_guest_vmcb->tr_selector = state->tr_selector;
            m_guest_vmcb->tr_attrib = compress_attrib(bsl::to_u16(state->tr_attrib)).get();
            m_guest_vmcb->tr_limit = state->tr_limit;
            m_guest_vmcb->tr_base = state->tr_base;

            m_guest_vmcb->cr0 = state->cr0;
            m_guest_vmcb->cr2 = state->cr2;
            m_guest_vmcb->cr3 = state->cr3;
            m_guest_vmcb->cr4 = state->cr4;
            m_missing_registers.guest_cr8 = state->cr8;
            m_missing_registers.guest_xcr0 = sanitize_xcr0(bsl::to_u64(state->xcr0)).get();

            m_missing_registers.guest_dr0 = state->dr0;
            m_missing_registers.guest_dr1 = state->dr1;
            m_missing_registers.guest_dr2 = state->dr2;
            m_missing_registers.guest_dr3 = state->dr3;
            m_guest_vmcb->dr6 = state->dr6;
            m_guest_vmcb->dr7 = state->dr7;

            m_guest_vmcb->efer = sanitize_efer(bsl::to_u64(state->msr_efer)).get();
            m_guest_vmcb->star = state->msr_star;
            m_guest_vmcb->lstar = state->msr_lstar;
            m_guest_vmcb->cstar = state->msr_cstar;
            m_guest_vmcb->fmask = state->msr_fmask;
            m_guest_vmcb->fs_base = state->msr_fs_base;
            m_guest_vmcb->gs_base = state->msr_gs_base;
            m_guest_vmcb->sysenter_cs = state->msr_sysenter_cs;
            m_guest_vmcb->sysenter_esp = state->msr_sysenter_esp;
            m_guest_vmcb->sysenter_eip = state->msr_sysenter_eip;
            m_guest_vmcb->pat = state->msr_pat;
            m_guest_vmcb->dbgctl = state->msr_debugctl;
        }

        /// <!-- description -->
        ///   @brief Stores the vs_t state in the provided state save
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param pmut_state the state save to store the vs_t state to
        ///
        constexpr void
        vs_to_state_save(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t *const pmut_state) const noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(nullptr != pmut_state);

            if (tls.active_vsid == this->id()) {
                pmut_state->rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
                pmut_state->rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
                pmut_state->rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
                pmut_state->rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
                pmut_state->rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
                pmut_state->rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
                pmut_state->rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
                pmut_state->r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
                pmut_state->r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
                pmut_state->r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
                pmut_state->r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
                pmut_state->r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
                pmut_state->r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
                pmut_state->r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
                pmut_state->r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            }
            else {
                pmut_state->rax = m_gprs.rax;
                pmut_state->rbx = m_gprs.rbx;
                pmut_state->rcx = m_gprs.rcx;
                pmut_state->rdx = m_gprs.rdx;
                pmut_state->rbp = m_gprs.rbp;
                pmut_state->rsi = m_gprs.rsi;
                pmut_state->rdi = m_gprs.rdi;
                pmut_state->r8 = m_gprs.r8;
                pmut_state->r9 = m_gprs.r9;
                pmut_state->r10 = m_gprs.r10;
                pmut_state->r11 = m_gprs.r11;
                pmut_state->r12 = m_gprs.r12;
                pmut_state->r13 = m_gprs.r13;
                pmut_state->r14 = m_gprs.r14;
                pmut_state->r15 = m_gprs.r15;
            }

            pmut_state->rsp = m_guest_vmcb->rsp;
            pmut_state->rip = m_guest_vmcb->rip;

            pmut_state->rflags = m_guest_vmcb->rflags;

            pmut_state->gdtr.limit = bsl::to_u16(m_guest_vmcb->gdtr_limit).get();
            pmut_state->gdtr.base = m_guest_vmcb->gdtr_base;
            pmut_state->idtr.limit = bsl::to_u16(m_guest_vmcb->idtr_limit).get();
            pmut_state->idtr.base = m_guest_vmcb->idtr_base;

            pmut_state->es_selector = m_guest_vmcb->es_selector;
            pmut_state->es_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->es_attrib)).get();
            pmut_state->es_limit = m_guest_vmcb->es_limit;
            pmut_state->es_base = m_guest_vmcb->es_base;

            pmut_state->cs_selector = m_guest_vmcb->cs_selector;
            pmut_state->cs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->cs_attrib)).get();
            pmut_state->cs_limit = m_guest_vmcb->cs_limit;
            pmut_state->cs_base = m_guest_vmcb->cs_base;

            pmut_state->ss_selector = m_guest_vmcb->ss_selector;
            pmut_state->ss_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->ss_attrib)).get();
            pmut_state->ss_limit = m_guest_vmcb->ss_limit;
            pmut_state->ss_base = m_guest_vmcb->ss_base;

            pmut_state->ds_selector = m_guest_vmcb->ds_selector;
            pmut_state->ds_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->ds_attrib)).get();
            pmut_state->ds_limit = m_guest_vmcb->ds_limit;
            pmut_state->ds_base = m_guest_vmcb->ds_base;

            pmut_state->fs_selector = m_guest_vmcb->fs_selector;
            pmut_state->fs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->fs_attrib)).get();
            pmut_state->fs_limit = m_guest_vmcb->fs_limit;
            pmut_state->fs_base = m_guest_vmcb->fs_base;

            pmut_state->gs_selector = m_guest_vmcb->gs_selector;
            pmut_state->gs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->gs_attrib)).get();
            pmut_state->gs_limit = m_guest_vmcb->gs_limit;
            pmut_state->gs_base = m_guest_vmcb->gs_base;

            pmut_state->ldtr_selector = m_guest_vmcb->ldtr_selector;
            pmut_state->ldtr_attrib =
                decompress_attrib(bsl::to_u16(m_guest_vmcb->ldtr_attrib)).get();
            pmut_state->ldtr_limit = m_guest_vmcb->ldtr_limit;
            pmut_state->ldtr_base = m_guest_vmcb->ldtr_base;

            pmut_state->tr_selector = m_guest_vmcb->tr_selector;
            pmut_state->tr_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->tr_attrib)).get();
            pmut_state->tr_limit = m_guest_vmcb->tr_limit;
            pmut_state->tr_base = m_guest_vmcb->tr_base;

            pmut_state->cr0 = m_guest_vmcb->cr0;
            pmut_state->cr2 = m_guest_vmcb->cr2;
            pmut_state->cr3 = m_guest_vmcb->cr3;
            pmut_state->cr4 = m_guest_vmcb->cr4;
            pmut_state->cr8 = m_missing_registers.guest_cr8;
            pmut_state->xcr0 = m_missing_registers.guest_xcr0;

            pmut_state->dr0 = m_missing_registers.guest_dr0;
            pmut_state->dr1 = m_missing_registers.guest_dr1;
            pmut_state->dr2 = m_missing_registers.guest_dr2;
            pmut_state->dr3 = m_missing_registers.guest_dr3;
            pmut_state->dr6 = m_guest_vmcb->dr6;
            pmut_state->dr7 = m_guest_vmcb->dr7;

            pmut_state->msr_efer = m_guest_vmcb->efer;
            pmut_state->msr_star = m_guest_vmcb->star;
            pmut_state->msr_lstar = m_guest_vmcb->lstar;
            pmut_state->msr_cstar = m_guest_vmcb->cstar;
            pmut_state->msr_fmask = m_guest_vmcb->fmask;
            pmut_state->msr_fs_base = m_guest_vmcb->fs_base;
            pmut_state->msr_gs_base = m_guest_vmcb->gs_base;
            pmut_state->msr_kernel_gs_base = m_guest_vmcb->kernel_gs_base;
            pmut_state->msr_sysenter_cs = m_guest_vmcb->sysenter_cs;
            pmut_state->msr_sysenter_esp = m_guest_vmcb->sysenter_esp;
            pmut_state->msr_sysenter_eip = m_guest_vmcb->sysenter_eip;
            pmut_state->msr_pat = m_guest_vmcb->pat;
            pmut_state->msr_debugctl = m_guest_vmcb->dbgctl;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the vs_t given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to read from the vs_t
        ///   @return Returns the value of the requested field from the
        ///     vs_t or bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        read(tls_t const &tls, intrinsic_t const &intrinsic, syscall::bf_reg_t const reg)
            const noexcept -> bsl::safe_umx
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_unsupported: {
                    bsl::error() << "unsupported bf_reg_t\n" << bsl::here();
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
                    }

                    return bsl::to_u64(m_gprs.rax);
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
                    }

                    return bsl::to_u64(m_gprs.rbx);
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
                    }

                    return bsl::to_u64(m_gprs.rcx);
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
                    }

                    return bsl::to_u64(m_gprs.rdx);
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
                    }

                    return bsl::to_u64(m_gprs.rbp);
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
                    }

                    return bsl::to_u64(m_gprs.rsi);
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
                    }

                    return bsl::to_u64(m_gprs.rdi);
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
                    }

                    return bsl::to_u64(m_gprs.r8);
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
                    }

                    return bsl::to_u64(m_gprs.r9);
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
                    }

                    return bsl::to_u64(m_gprs.r10);
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
                    }

                    return bsl::to_u64(m_gprs.r11);
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
                    }

                    return bsl::to_u64(m_gprs.r12);
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
                    }

                    return bsl::to_u64(m_gprs.r13);
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
                    }

                    return bsl::to_u64(m_gprs.r14);
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
                    }

                    return bsl::to_u64(m_gprs.r15);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_read: {
                    return bsl::to_u64(m_guest_vmcb->intercept_cr_read);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_write: {
                    return bsl::to_u64(m_guest_vmcb->intercept_cr_write);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_read: {
                    return bsl::to_u64(m_guest_vmcb->intercept_dr_read);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_write: {
                    return bsl::to_u64(m_guest_vmcb->intercept_dr_write);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_exception: {
                    return bsl::to_u64(m_guest_vmcb->intercept_exception);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction1: {
                    return bsl::to_u64(m_guest_vmcb->intercept_instruction1);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction2: {
                    return bsl::to_u64(m_guest_vmcb->intercept_instruction2);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction3: {
                    return bsl::to_u64(m_guest_vmcb->intercept_instruction3);
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_threshold: {
                    return bsl::to_u64(m_guest_vmcb->pause_filter_threshold);
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_count: {
                    return bsl::to_u64(m_guest_vmcb->pause_filter_count);
                }

                case syscall::bf_reg_t::bf_reg_t_iopm_base_pa: {
                    return bsl::to_u64(m_guest_vmcb->iopm_base_pa);
                }

                case syscall::bf_reg_t::bf_reg_t_msrpm_base_pa: {
                    return bsl::to_u64(m_guest_vmcb->msrpm_base_pa);
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    return bsl::to_u64(m_guest_vmcb->tsc_offset);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_asid: {
                    return bsl::to_u64(m_guest_vmcb->guest_asid);
                }

                case syscall::bf_reg_t::bf_reg_t_tlb_control: {
                    return bsl::to_u64(m_guest_vmcb->tlb_control);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_a: {
                    return bsl::to_u64(m_guest_vmcb->virtual_interrupt_a);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_b: {
                    return bsl::to_u64(m_guest_vmcb->virtual_interrupt_b);
                }

                case syscall::bf_reg_t::bf_reg_t_exitcode: {
                    return bsl::to_u64(m_guest_vmcb->exitcode);
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo1: {
                    return bsl::to_u64(m_guest_vmcb->exitinfo1);
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo2: {
                    return bsl::to_u64(m_guest_vmcb->exitinfo2);
                }

                case syscall::bf_reg_t::bf_reg_t_exitininfo: {
                    return bsl::to_u64(m_guest_vmcb->exitininfo);
                }

                case syscall::bf_reg_t::bf_reg_t_ctls1: {
                    return bsl::to_u64(m_guest_vmcb->ctls1);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_bar: {
                    return bsl::to_u64(m_guest_vmcb->avic_apic_bar);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pa_of_ghcb: {
                    return bsl::to_u64(m_guest_vmcb->guest_pa_of_ghcb);
                }

                case syscall::bf_reg_t::bf_reg_t_eventinj: {
                    return bsl::to_u64(m_guest_vmcb->eventinj);
                }

                case syscall::bf_reg_t::bf_reg_t_n_cr3: {
                    return bsl::to_u64(m_guest_vmcb->n_cr3);
                }

                case syscall::bf_reg_t::bf_reg_t_ctls2: {
                    return bsl::to_u64(m_guest_vmcb->ctls2);
                }

                case syscall::bf_reg_t::bf_reg_t_vmcb_clean_bits: {
                    return bsl::to_u64(m_guest_vmcb->vmcb_clean_bits);
                }

                case syscall::bf_reg_t::bf_reg_t_nrip: {
                    return bsl::to_u64(m_guest_vmcb->nrip);
                }

                case syscall::bf_reg_t::bf_reg_t_number_of_bytes_fetched: {
                    return bsl::to_u64(m_guest_vmcb->number_of_bytes_fetched);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_backing_page_ptr: {
                    return bsl::to_u64(m_guest_vmcb->avic_apic_backing_page_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_logical_table_ptr: {
                    return bsl::to_u64(m_guest_vmcb->avic_logical_table_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_physical_table_ptr: {
                    return bsl::to_u64(m_guest_vmcb->avic_physical_table_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_vmsa_ptr: {
                    return bsl::to_u64(m_guest_vmcb->vmsa_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_es_selector: {
                    return bsl::to_u64(m_guest_vmcb->es_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->es_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    return bsl::to_u64(m_guest_vmcb->es_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    return bsl::to_u64(m_guest_vmcb->es_base);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    return bsl::to_u64(m_guest_vmcb->cs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->cs_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    return bsl::to_u64(m_guest_vmcb->cs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    return bsl::to_u64(m_guest_vmcb->cs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    return bsl::to_u64(m_guest_vmcb->ss_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->ss_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    return bsl::to_u64(m_guest_vmcb->ss_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    return bsl::to_u64(m_guest_vmcb->ss_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    return bsl::to_u64(m_guest_vmcb->ds_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->ds_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    return bsl::to_u64(m_guest_vmcb->ds_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    return bsl::to_u64(m_guest_vmcb->ds_base);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    return bsl::to_u64(m_guest_vmcb->fs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->fs_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    return bsl::to_u64(m_guest_vmcb->fs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    return bsl::to_u64(m_guest_vmcb->fs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    return bsl::to_u64(m_guest_vmcb->gs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->gs_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    return bsl::to_u64(m_guest_vmcb->gs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    return bsl::to_u64(m_guest_vmcb->gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_selector: {
                    return bsl::to_u64(m_guest_vmcb->gdtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->gdtr_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    return bsl::to_u64(m_guest_vmcb->gdtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    return bsl::to_u64(m_guest_vmcb->gdtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    return bsl::to_u64(m_guest_vmcb->ldtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->ldtr_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    return bsl::to_u64(m_guest_vmcb->ldtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    return bsl::to_u64(m_guest_vmcb->ldtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_selector: {
                    return bsl::to_u64(m_guest_vmcb->idtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->idtr_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    return bsl::to_u64(m_guest_vmcb->idtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    return bsl::to_u64(m_guest_vmcb->idtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    return bsl::to_u64(m_guest_vmcb->tr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    return bsl::to_u64(decompress_attrib(bsl::to_u16(m_guest_vmcb->tr_attrib)));
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    return bsl::to_u64(m_guest_vmcb->tr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    return bsl::to_u64(m_guest_vmcb->tr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_cpl: {
                    return bsl::to_u64(m_guest_vmcb->cpl);
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    return bsl::to_u64(m_guest_vmcb->efer);
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    return bsl::to_u64(m_guest_vmcb->cr4);
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    return bsl::to_u64(m_guest_vmcb->cr3);
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    return bsl::to_u64(m_guest_vmcb->cr0);
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    return bsl::to_u64(m_guest_vmcb->dr7);
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    return bsl::to_u64(m_guest_vmcb->dr6);
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    return bsl::to_u64(m_guest_vmcb->rflags);
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    return bsl::to_u64(m_guest_vmcb->rip);
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    return bsl::to_u64(m_guest_vmcb->rsp);
                }

                case syscall::bf_reg_t::bf_reg_t_star: {
                    return bsl::to_u64(m_guest_vmcb->star);
                }

                case syscall::bf_reg_t::bf_reg_t_lstar: {
                    return bsl::to_u64(m_guest_vmcb->lstar);
                }

                case syscall::bf_reg_t::bf_reg_t_cstar: {
                    return bsl::to_u64(m_guest_vmcb->cstar);
                }

                case syscall::bf_reg_t::bf_reg_t_fmask: {
                    return bsl::to_u64(m_guest_vmcb->fmask);
                }

                case syscall::bf_reg_t::bf_reg_t_kernel_gs_base: {
                    return bsl::to_u64(m_guest_vmcb->kernel_gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_cs: {
                    return bsl::to_u64(m_guest_vmcb->sysenter_cs);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_esp: {
                    return bsl::to_u64(m_guest_vmcb->sysenter_esp);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_eip: {
                    return bsl::to_u64(m_guest_vmcb->sysenter_eip);
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    return bsl::to_u64(m_guest_vmcb->cr2);
                }

                case syscall::bf_reg_t::bf_reg_t_pat: {
                    return bsl::to_u64(m_guest_vmcb->pat);
                }

                case syscall::bf_reg_t::bf_reg_t_dbgctl: {
                    return bsl::to_u64(m_guest_vmcb->dbgctl);
                }

                case syscall::bf_reg_t::bf_reg_t_br_from: {
                    return bsl::to_u64(m_guest_vmcb->br_from);
                }

                case syscall::bf_reg_t::bf_reg_t_br_to: {
                    return bsl::to_u64(m_guest_vmcb->br_to);
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpfrom: {
                    return bsl::to_u64(m_guest_vmcb->lastexcpfrom);
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpto: {
                    return bsl::to_u64(m_guest_vmcb->lastexcpto);
                }

                case syscall::bf_reg_t::bf_reg_t_cr8: {
                    return bsl::to_u64(m_missing_registers.guest_cr8);
                }

                case syscall::bf_reg_t::bf_reg_t_dr0: {
                    return bsl::to_u64(m_missing_registers.guest_dr0);
                }

                case syscall::bf_reg_t::bf_reg_t_dr1: {
                    return bsl::to_u64(m_missing_registers.guest_dr1);
                }

                case syscall::bf_reg_t::bf_reg_t_dr2: {
                    return bsl::to_u64(m_missing_registers.guest_dr2);
                }

                case syscall::bf_reg_t::bf_reg_t_dr3: {
                    return bsl::to_u64(m_missing_registers.guest_dr3);
                }

                case syscall::bf_reg_t::bf_reg_t_xcr0: {
                    return bsl::to_u64(m_missing_registers.guest_xcr0);
                }

                case syscall::bf_reg_t::bf_reg_t_invalid: {
                    bsl::error() << "invalid bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            return bsl::safe_umx::failure();
        }

        /// <!-- description -->
        ///   @brief Writes a field to the vs_t given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to write to the vs_t
        ///   @param val the value to write to the vs_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t const &tls,
            intrinsic_t &mut_intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_umx const &val) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(val.is_valid_and_checked());

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_unsupported: {
                    ret = bsl::errc_unsupported;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    }
                    else {
                        m_gprs.rax = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    }
                    else {
                        m_gprs.rbx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    }
                    else {
                        m_gprs.rcx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    }
                    else {
                        m_gprs.rdx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    }
                    else {
                        m_gprs.rbp = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    }
                    else {
                        m_gprs.rsi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    }
                    else {
                        m_gprs.rdi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    }
                    else {
                        m_gprs.r8 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    }
                    else {
                        m_gprs.r9 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    }
                    else {
                        m_gprs.r10 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    }
                    else {
                        m_gprs.r11 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    }
                    else {
                        m_gprs.r12 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    }
                    else {
                        m_gprs.r13 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    }
                    else {
                        m_gprs.r14 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
                    }
                    else {
                        m_gprs.r15 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_read: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_cr_read = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_write: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_cr_write = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_read: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_dr_read = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_write: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_dr_write = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_exception: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_exception = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction1: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_instruction1 = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction2: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_instruction2 = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction3: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->intercept_instruction3 = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_threshold: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->pause_filter_threshold = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_count: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->pause_filter_count = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_iopm_base_pa: {
                    m_guest_vmcb->iopm_base_pa = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_msrpm_base_pa: {
                    m_guest_vmcb->msrpm_base_pa = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    m_guest_vmcb->tsc_offset = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_asid: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->guest_asid = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tlb_control: {
                    auto const val8{bsl::to_u8(val)};
                    if (bsl::unlikely(val8.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->tlb_control = val8.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_a: {
                    m_guest_vmcb->virtual_interrupt_a = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_b: {
                    m_guest_vmcb->virtual_interrupt_b = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_exitcode: {
                    m_guest_vmcb->exitcode = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo1: {
                    m_guest_vmcb->exitinfo1 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo2: {
                    m_guest_vmcb->exitinfo2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_exitininfo: {
                    m_guest_vmcb->exitininfo = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ctls1: {
                    m_guest_vmcb->ctls1 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_bar: {
                    m_guest_vmcb->avic_apic_bar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pa_of_ghcb: {
                    m_guest_vmcb->guest_pa_of_ghcb = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_eventinj: {
                    m_guest_vmcb->eventinj = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_n_cr3: {
                    m_guest_vmcb->n_cr3 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ctls2: {
                    m_guest_vmcb->ctls2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_vmcb_clean_bits: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->vmcb_clean_bits = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_nrip: {
                    m_guest_vmcb->nrip = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_number_of_bytes_fetched: {
                    auto const val8{bsl::to_u8(val)};
                    if (bsl::unlikely(val8.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->number_of_bytes_fetched = val8.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_backing_page_ptr: {
                    m_guest_vmcb->avic_apic_backing_page_ptr = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_avic_logical_table_ptr: {
                    m_guest_vmcb->avic_logical_table_ptr = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_avic_physical_table_ptr: {
                    m_guest_vmcb->avic_physical_table_ptr = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_vmsa_ptr: {
                    m_guest_vmcb->vmsa_ptr = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->es_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->es_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->es_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    m_guest_vmcb->es_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->cs_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->cs_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->cs_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    m_guest_vmcb->cs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ss_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ss_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ss_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    m_guest_vmcb->ss_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ds_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ds_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ds_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    m_guest_vmcb->ds_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->fs_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->fs_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->fs_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    m_guest_vmcb->fs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gs_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gs_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gs_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    m_guest_vmcb->gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gdtr_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gdtr_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->gdtr_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    m_guest_vmcb->gdtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ldtr_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ldtr_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->ldtr_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    m_guest_vmcb->ldtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->idtr_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->idtr_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->idtr_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    m_guest_vmcb->idtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->tr_selector = val16.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    auto const val16{bsl::to_u16(val)};
                    if (bsl::unlikely(val16.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->tr_attrib = compress_attrib(val16).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    auto const val32{bsl::to_u32(val)};
                    if (bsl::unlikely(val32.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->tr_limit = val32.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    m_guest_vmcb->tr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cpl: {
                    auto const val8{bsl::to_u8(val)};
                    if (bsl::unlikely(val8.is_invalid())) {
                        ret = bsl::errc_narrow_overflow;
                        break;
                    }

                    m_guest_vmcb->cpl = bsl::to_u8(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    m_guest_vmcb->efer = sanitize_efer(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    m_guest_vmcb->cr4 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    m_guest_vmcb->cr3 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    m_guest_vmcb->cr0 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    m_guest_vmcb->dr7 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    m_guest_vmcb->dr6 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    m_guest_vmcb->rflags = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    m_guest_vmcb->rip = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    m_guest_vmcb->rsp = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_star: {
                    m_guest_vmcb->star = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_lstar: {
                    m_guest_vmcb->lstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cstar: {
                    m_guest_vmcb->cstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fmask: {
                    m_guest_vmcb->fmask = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_kernel_gs_base: {
                    m_guest_vmcb->kernel_gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_cs: {
                    m_guest_vmcb->sysenter_cs = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_esp: {
                    m_guest_vmcb->sysenter_esp = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_eip: {
                    m_guest_vmcb->sysenter_eip = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    m_guest_vmcb->cr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_pat: {
                    m_guest_vmcb->pat = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dbgctl: {
                    m_guest_vmcb->dbgctl = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_br_from: {
                    m_guest_vmcb->br_from = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_br_to: {
                    m_guest_vmcb->br_to = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpfrom: {
                    m_guest_vmcb->lastexcpfrom = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpto: {
                    m_guest_vmcb->lastexcpto = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr8: {
                    m_missing_registers.guest_cr8 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr0: {
                    m_missing_registers.guest_dr0 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr1: {
                    m_missing_registers.guest_dr1 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr2: {
                    m_missing_registers.guest_dr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr3: {
                    m_missing_registers.guest_dr3 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_xcr0: {
                    m_missing_registers.guest_xcr0 = sanitize_xcr0(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_invalid: {
                    ret = bsl::errc_unsupported;
                    break;
                }
            }

            if (bsl::errc_narrow_overflow == ret) {
                bsl::error() << "vs "                                // --
                             << bsl::hex(this->id())                 // --
                             << " attempted to write to regiter "    // --
                             << static_cast<bsl::uint64>(reg)        // --
                             << " with val "                         // --
                             << bsl::hex(val)                        // --
                             << "which resulted in data loss"        // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return ret;
            }

            bsl::error() << "vs "                                        // --
                         << bsl::hex(this->id())                         // --
                         << " attempted to write to unknown regiter "    // --
                         << static_cast<bsl::uint64>(reg)                // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return ret;
        }

        /// <!-- description -->
        ///   @brief Runs the vs_t. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param mut_log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t const &tls, intrinsic_t &mut_intrinsic, vmexit_log_t &mut_log) noexcept
            -> bsl::safe_umx
        {
            bsl::discard(mut_intrinsic);
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());

            m_status = running_status_t::running;
            auto const exit_reason{mut_intrinsic.vmrun(
                m_guest_vmcb,
                m_guest_vmcb_phys,
                m_host_vmcb,
                m_host_vmcb_phys,
                &m_missing_registers)};
            m_status = running_status_t::handling_vmexit;

            if constexpr (BSL_DEBUG_LEVEL >= bsl::VV) {
                mut_log.add(
                    bsl::to_u16(tls.ppid),
                    {bsl::to_u16(tls.active_vmid),
                     bsl::to_u16(tls.active_vpid),
                     bsl::to_u16(tls.active_vsid),
                     bsl::to_umx(exit_reason),
                     bsl::to_umx(m_guest_vmcb->exitinfo1),
                     bsl::to_umx(m_guest_vmcb->exitinfo2),
                     bsl::to_umx(m_guest_vmcb->exitininfo),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RAX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RBX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RCX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RDX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RBP),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RSI),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RDI),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R8),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R9),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R10),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R11),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R12),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R13),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R14),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R15),
                     bsl::to_umx(m_guest_vmcb->rsp),
                     bsl::to_umx(m_guest_vmcb->rip)});
            }

            return exit_reason;
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        advance_ip(tls_t const &tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(intrinsic);
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(tls.ppid == this->assigned_pp());

            m_guest_vmcb->rip = m_guest_vmcb->nrip;
        }

        /// <!-- description -->
        ///   @brief Clears the vs_t's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::expects(allocated_status_t::allocated == m_allocated);

            if (bsl::unlikely(running_status_t::running == m_status)) {
                bsl::error() << "vs "                                                 // --
                             << bsl::hex(this->id())                                  // --
                             << " is still running and cannot be cleared/migrated"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::errc_failure;
            }

            m_guest_vmcb->vmcb_clean_bits = {};
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        dump(tls_t const &tls, intrinsic_t const &intrinsic) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            // clang-format off

            constexpr auto guest_instruction_bytes_0{0x0_idx};
            constexpr auto guest_instruction_bytes_1{0x1_idx};
            constexpr auto guest_instruction_bytes_2{0x2_idx};
            constexpr auto guest_instruction_bytes_3{0x3_idx};
            constexpr auto guest_instruction_bytes_4{0x4_idx};
            constexpr auto guest_instruction_bytes_5{0x5_idx};
            constexpr auto guest_instruction_bytes_6{0x6_idx};
            constexpr auto guest_instruction_bytes_7{0x7_idx};
            constexpr auto guest_instruction_bytes_8{0x8_idx};
            constexpr auto guest_instruction_bytes_9{0x9_idx};
            constexpr auto guest_instruction_bytes_a{0xA_idx};
            /// NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto guest_instruction_bytes_b{0xB_idx};
            constexpr auto guest_instruction_bytes_c{0xC_idx};
            constexpr auto guest_instruction_bytes_d{0xD_idx};
            constexpr auto guest_instruction_bytes_e{0xE_idx};

            bsl::print() << bsl::mag << "vs [";
            bsl::print() << bsl::rst << bsl::hex(this->id());
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^30s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^19s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Allocated
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<30s", "allocated "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_allocated()) {
                bsl::print() << bsl::grn << bsl::fmt{"^19s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned VP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<30s", "assigned vp "};
            bsl::print() << bsl::ylw << "| ";
            if (this->assigned_vp() != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(this->assigned_vp()) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(this->assigned_vp()) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned PP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<30s", "assigned pp "};
            bsl::print() << bsl::ylw << "| ";
            if (this->assigned_pp() != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(this->assigned_pp()) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(this->assigned_pp()) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Guest Missing Fields
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            if (!this->is_allocated()) {
                return;
            }

            if (tls.active_vsid == this->id()) {
                this->dump_field("rax ", intrinsic.tls_reg(syscall::TLS_OFFSET_RAX));
                this->dump_field("rbx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBX));
                this->dump_field("rcx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RCX));
                this->dump_field("rdx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDX));
                this->dump_field("rbp ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBP));
                this->dump_field("rsi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RSI));
                this->dump_field("rdi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDI));
                this->dump_field("r8 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R8));
                this->dump_field("r9 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R9));
                this->dump_field("r10 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R10));
                this->dump_field("r11 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R11));
                this->dump_field("r12 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R12));
                this->dump_field("r13 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R13));
                this->dump_field("r14 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R14));
                this->dump_field("r15 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R15));
            }
            else {
                this->dump_field("rax ", bsl::make_safe(m_gprs.rax));
                this->dump_field("rbx ", bsl::make_safe(m_gprs.rbx));
                this->dump_field("rcx ", bsl::make_safe(m_gprs.rcx));
                this->dump_field("rdx ", bsl::make_safe(m_gprs.rdx));
                this->dump_field("rbp ", bsl::make_safe(m_gprs.rbp));
                this->dump_field("rsi ", bsl::make_safe(m_gprs.rsi));
                this->dump_field("rdi ", bsl::make_safe(m_gprs.rdi));
                this->dump_field("r8 ", bsl::make_safe(m_gprs.r8));
                this->dump_field("r9 ", bsl::make_safe(m_gprs.r9));
                this->dump_field("r10 ", bsl::make_safe(m_gprs.r10));
                this->dump_field("r11 ", bsl::make_safe(m_gprs.r11));
                this->dump_field("r12 ", bsl::make_safe(m_gprs.r12));
                this->dump_field("r13 ", bsl::make_safe(m_gprs.r13));
                this->dump_field("r14 ", bsl::make_safe(m_gprs.r14));
                this->dump_field("r15 ", bsl::make_safe(m_gprs.r15));
            }

            /// Guest Control Area Fields
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("intercept_cr_read ", bsl::make_safe(m_guest_vmcb->intercept_cr_read));
            this->dump_field("intercept_cr_write ", bsl::make_safe(m_guest_vmcb->intercept_cr_write));
            this->dump_field("intercept_dr_read ", bsl::make_safe(m_guest_vmcb->intercept_dr_read));
            this->dump_field("intercept_dr_write ", bsl::make_safe(m_guest_vmcb->intercept_dr_write));
            this->dump_field("intercept_exception ", bsl::make_safe(m_guest_vmcb->intercept_exception));
            this->dump_field("intercept_instruction1 ", bsl::make_safe(m_guest_vmcb->intercept_instruction1));
            this->dump_field("intercept_instruction2 ", bsl::make_safe(m_guest_vmcb->intercept_instruction2));
            this->dump_field("intercept_instruction3 ", bsl::make_safe(m_guest_vmcb->intercept_instruction3));
            this->dump_field("pause_filter_threshold ", bsl::make_safe(m_guest_vmcb->pause_filter_threshold));
            this->dump_field("pause_filter_count ", bsl::make_safe(m_guest_vmcb->pause_filter_count));
            this->dump_field("iopm_base_pa ", bsl::make_safe(m_guest_vmcb->iopm_base_pa));
            this->dump_field("msrpm_base_pa ", bsl::make_safe(m_guest_vmcb->msrpm_base_pa));
            this->dump_field("tsc_offset ", bsl::make_safe(m_guest_vmcb->tsc_offset));
            this->dump_field("guest_asid ", bsl::make_safe(m_guest_vmcb->guest_asid));
            this->dump_field("tlb_control ", bsl::make_safe(m_guest_vmcb->tlb_control));
            this->dump_field("virtual_interrupt_a ", bsl::make_safe(m_guest_vmcb->virtual_interrupt_a));
            this->dump_field("virtual_interrupt_b ", bsl::make_safe(m_guest_vmcb->virtual_interrupt_b));
            this->dump_field("exitcode ", bsl::make_safe(m_guest_vmcb->exitcode));
            this->dump_field("exitinfo1 ", bsl::make_safe(m_guest_vmcb->exitinfo1));
            this->dump_field("exitinfo2 ", bsl::make_safe(m_guest_vmcb->exitinfo2));
            this->dump_field("exitininfo ", bsl::make_safe(m_guest_vmcb->exitininfo));
            this->dump_field("ctls1 ", bsl::make_safe(m_guest_vmcb->ctls1));
            this->dump_field("avic_apic_bar ", bsl::make_safe(m_guest_vmcb->avic_apic_bar));
            this->dump_field("guest_pa_of_ghcb ", bsl::make_safe(m_guest_vmcb->guest_pa_of_ghcb));
            this->dump_field("eventinj ", bsl::make_safe(m_guest_vmcb->eventinj));
            this->dump_field("n_cr3 ", bsl::make_safe(m_guest_vmcb->n_cr3));
            this->dump_field("ctls2 ", bsl::make_safe(m_guest_vmcb->ctls2));
            this->dump_field("vmcb_clean_bits ", bsl::make_safe(m_guest_vmcb->vmcb_clean_bits));
            this->dump_field("nrip ", bsl::make_safe(m_guest_vmcb->nrip));
            this->dump_field("number_of_bytes_fetched ", bsl::make_safe(m_guest_vmcb->number_of_bytes_fetched));

            auto const &gib{m_guest_vmcb->guest_instruction_bytes};
            this->dump_field("guest_instruction_bytes[0]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_0)));
            this->dump_field("guest_instruction_bytes[1]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_1)));
            this->dump_field("guest_instruction_bytes[2]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_2)));
            this->dump_field("guest_instruction_bytes[3]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_3)));
            this->dump_field("guest_instruction_bytes[4]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_4)));
            this->dump_field("guest_instruction_bytes[5]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_5)));
            this->dump_field("guest_instruction_bytes[6]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_6)));
            this->dump_field("guest_instruction_bytes[7]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_7)));
            this->dump_field("guest_instruction_bytes[8]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_8)));
            this->dump_field("guest_instruction_bytes[9]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_9)));
            this->dump_field("guest_instruction_bytes[a]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_a)));
            this->dump_field("guest_instruction_bytes[b]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_b)));
            this->dump_field("guest_instruction_bytes[c]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_c)));
            this->dump_field("guest_instruction_bytes[d]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_d)));
            this->dump_field("guest_instruction_bytes[e]", bsl::make_safe(*gib.at_if(guest_instruction_bytes_e)));

            this->dump_field("avic_apic_backing_page_ptr ", bsl::make_safe(m_guest_vmcb->avic_apic_backing_page_ptr));
            this->dump_field("avic_logical_table_ptr ", bsl::make_safe(m_guest_vmcb->avic_logical_table_ptr));
            this->dump_field("avic_physical_table_ptr ", bsl::make_safe(m_guest_vmcb->avic_physical_table_ptr));
            this->dump_field("vmsa_ptr ", bsl::make_safe(m_guest_vmcb->vmsa_ptr));

            /// Guest State Save Area Fields
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("es_selector ", bsl::make_safe(m_guest_vmcb->es_selector));
            this->dump_field("es_attrib ", bsl::make_safe(m_guest_vmcb->es_attrib));
            this->dump_field("es_limit ", bsl::make_safe(m_guest_vmcb->es_limit));
            this->dump_field("es_base ", bsl::make_safe(m_guest_vmcb->es_base));
            this->dump_field("cs_selector ", bsl::make_safe(m_guest_vmcb->cs_selector));
            this->dump_field("cs_attrib ", bsl::make_safe(m_guest_vmcb->cs_attrib));
            this->dump_field("cs_limit ", bsl::make_safe(m_guest_vmcb->cs_limit));
            this->dump_field("cs_base ", bsl::make_safe(m_guest_vmcb->cs_base));
            this->dump_field("ss_selector ", bsl::make_safe(m_guest_vmcb->ss_selector));
            this->dump_field("ss_attrib ", bsl::make_safe(m_guest_vmcb->ss_attrib));
            this->dump_field("ss_limit ", bsl::make_safe(m_guest_vmcb->ss_limit));
            this->dump_field("ss_base ", bsl::make_safe(m_guest_vmcb->ss_base));
            this->dump_field("ds_selector ", bsl::make_safe(m_guest_vmcb->ds_selector));
            this->dump_field("ds_attrib ", bsl::make_safe(m_guest_vmcb->ds_attrib));
            this->dump_field("ds_limit ", bsl::make_safe(m_guest_vmcb->ds_limit));
            this->dump_field("ds_base ", bsl::make_safe(m_guest_vmcb->ds_base));
            this->dump_field("fs_selector ", bsl::make_safe(m_guest_vmcb->fs_selector));
            this->dump_field("fs_attrib ", bsl::make_safe(m_guest_vmcb->fs_attrib));
            this->dump_field("fs_limit ", bsl::make_safe(m_guest_vmcb->fs_limit));
            this->dump_field("fs_base ", bsl::make_safe(m_guest_vmcb->fs_base));
            this->dump_field("gs_selector ", bsl::make_safe(m_guest_vmcb->gs_selector));
            this->dump_field("gs_attrib ", bsl::make_safe(m_guest_vmcb->gs_attrib));
            this->dump_field("gs_limit ", bsl::make_safe(m_guest_vmcb->gs_limit));
            this->dump_field("gs_base ", bsl::make_safe(m_guest_vmcb->gs_base));
            this->dump_field("gdtr_selector ", bsl::make_safe(m_guest_vmcb->gdtr_selector));
            this->dump_field("gdtr_attrib ", bsl::make_safe(m_guest_vmcb->gdtr_attrib));
            this->dump_field("gdtr_limit ", bsl::make_safe(m_guest_vmcb->gdtr_limit));
            this->dump_field("gdtr_base ", bsl::make_safe(m_guest_vmcb->gdtr_base));
            this->dump_field("ldtr_selector ", bsl::make_safe(m_guest_vmcb->ldtr_selector));
            this->dump_field("ldtr_attrib ", bsl::make_safe(m_guest_vmcb->ldtr_attrib));
            this->dump_field("ldtr_limit ", bsl::make_safe(m_guest_vmcb->ldtr_limit));
            this->dump_field("ldtr_base ", bsl::make_safe(m_guest_vmcb->ldtr_base));
            this->dump_field("idtr_selector ", bsl::make_safe(m_guest_vmcb->idtr_selector));
            this->dump_field("idtr_attrib ", bsl::make_safe(m_guest_vmcb->idtr_attrib));
            this->dump_field("idtr_limit ", bsl::make_safe(m_guest_vmcb->idtr_limit));
            this->dump_field("idtr_base ", bsl::make_safe(m_guest_vmcb->idtr_base));
            this->dump_field("tr_selector ", bsl::make_safe(m_guest_vmcb->tr_selector));
            this->dump_field("tr_attrib ", bsl::make_safe(m_guest_vmcb->tr_attrib));
            this->dump_field("tr_limit ", bsl::make_safe(m_guest_vmcb->tr_limit));
            this->dump_field("tr_base ", bsl::make_safe(m_guest_vmcb->tr_base));
            this->dump_field("cpl ", bsl::make_safe(m_guest_vmcb->cpl));
            this->dump_field("efer ", bsl::make_safe(m_guest_vmcb->efer));
            this->dump_field("cr4 ", bsl::make_safe(m_guest_vmcb->cr4));
            this->dump_field("cr3 ", bsl::make_safe(m_guest_vmcb->cr3));
            this->dump_field("cr0 ", bsl::make_safe(m_guest_vmcb->cr0));
            this->dump_field("dr7 ", bsl::make_safe(m_guest_vmcb->dr7));
            this->dump_field("dr6 ", bsl::make_safe(m_guest_vmcb->dr6));
            this->dump_field("rflags ", bsl::make_safe(m_guest_vmcb->rflags));
            this->dump_field("rip ", bsl::make_safe(m_guest_vmcb->rip));
            this->dump_field("rsp ", bsl::make_safe(m_guest_vmcb->rsp));
            this->dump_field("rax ", bsl::make_safe(m_guest_vmcb->rax));
            this->dump_field("star ", bsl::make_safe(m_guest_vmcb->star));
            this->dump_field("lstar ", bsl::make_safe(m_guest_vmcb->lstar));
            this->dump_field("cstar ", bsl::make_safe(m_guest_vmcb->cstar));
            this->dump_field("fmask ", bsl::make_safe(m_guest_vmcb->fmask));
            this->dump_field("kernel_gs_base ", bsl::make_safe(m_guest_vmcb->kernel_gs_base));
            this->dump_field("sysenter_cs ", bsl::make_safe(m_guest_vmcb->sysenter_cs));
            this->dump_field("sysenter_esp ", bsl::make_safe(m_guest_vmcb->sysenter_esp));
            this->dump_field("sysenter_eip ", bsl::make_safe(m_guest_vmcb->sysenter_eip));
            this->dump_field("cr2 ", bsl::make_safe(m_guest_vmcb->cr2));
            this->dump_field("pat ", bsl::make_safe(m_guest_vmcb->pat));
            this->dump_field("dbgctl ", bsl::make_safe(m_guest_vmcb->dbgctl));
            this->dump_field("br_from ", bsl::make_safe(m_guest_vmcb->br_from));
            this->dump_field("br_to ", bsl::make_safe(m_guest_vmcb->br_to));
            this->dump_field("lastexcpfrom ", bsl::make_safe(m_guest_vmcb->lastexcpfrom));
            this->dump_field("lastexcpto ", bsl::make_safe(m_guest_vmcb->lastexcpto));
            this->dump_field("cr8 ", bsl::make_safe(m_missing_registers.guest_cr8));
            this->dump_field("dr0 ", bsl::make_safe(m_missing_registers.guest_dr0));
            this->dump_field("dr1 ", bsl::make_safe(m_missing_registers.guest_dr1));
            this->dump_field("dr2 ", bsl::make_safe(m_missing_registers.guest_dr2));
            this->dump_field("dr3 ", bsl::make_safe(m_missing_registers.guest_dr3));
            this->dump_field("xcr0 ", bsl::make_safe(m_missing_registers.guest_xcr0));

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
