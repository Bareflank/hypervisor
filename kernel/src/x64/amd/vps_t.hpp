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

#include <allocate_tags.hpp>
#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <general_purpose_regs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
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
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Converts attributes in the form 0xF0FF to the form
    ///     0x0FFF.
    ///
    /// <!-- inputs/outputs -->
    ///   @param attrib the attrib to compress
    ///   @return Returns the compressed version of attrib
    ///
    [[nodiscard]] constexpr auto
    compress_attrib(bsl::safe_uint16 const &attrib) noexcept -> bsl::safe_uint16
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
    [[nodiscard]] constexpr auto
    decompress_attrib(bsl::safe_uint16 const &attrib) noexcept -> bsl::safe_uint16
    {
        constexpr auto mask1{0x00FF_u16};
        constexpr auto mask2{0x0F00_u16};
        constexpr auto shift{4_u16};

        return (attrib & mask1) | ((attrib & mask2) << shift);
    }

    /// @class mk::vps_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VPS.
    ///
    class vps_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores the ID of the VP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_vpid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is active on
        bsl::safe_uint16 m_active_ppid{bsl::safe_uint16::failure()};

        /// @brief stores a pointer to the guest VMCB being managed by this VPS
        vmcb_t *m_guest_vmcb{};
        /// @brief stores the physical address of the guest VMCB
        bsl::safe_uintmax m_guest_vmcb_phys{bsl::safe_uintmax::failure()};
        /// @brief stores a pointer to the host VMCB being managed by this VPS
        vmcb_t *m_host_vmcb{};
        /// @brief stores the physical address of the host VMCB
        bsl::safe_uintmax m_host_vmcb_phys{bsl::safe_uintmax::failure()};
        /// @brief stores the general purpose registers
        general_purpose_regs_t m_gprs{};

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

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vps_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vps_t already initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == i)) {
                bsl::error() << "id "                                                  // --
                             << bsl::hex(i)                                            // --
                             << " is invalid and cannot be used for initialization"    // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_precondition;
            }

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vp_t. Note that if this function fails,
        ///     the microkernel is left in a corrupt state and all use of the
        ///     vp_t after calling this function will results in UB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> bsl::errc_type
        {
            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            bsl::finally mut_zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vp "                      // --
                             << bsl::hex(m_id)             // --
                             << " is active on pp "        // --
                             << bsl::hex(m_active_ppid)    // --
                             << " and therefore vp "       // --
                             << bsl::hex(m_id)             // --
                             << " cannot be destroyed"     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            m_gprs = {};

            m_host_vmcb_phys = bsl::safe_uintmax::failure();
            mut_page_pool.deallocate(mut_tls, m_host_vmcb, ALLOCATE_TAG_HOST_VMCB);
            m_host_vmcb = {};

            m_guest_vmcb_phys = bsl::safe_uintmax::failure();
            mut_page_pool.deallocate(mut_tls, m_guest_vmcb, ALLOCATE_TAG_GUEST_VMCB);
            m_guest_vmcb = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            mut_zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vps_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param mut_page_pool the page pool to use
        ///   @param vpid The ID of the VP to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vps
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &mut_tls,
            intrinsic_t const &intrinsic,
            page_pool_t &mut_page_pool,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
                bsl::error() << "vp "                                               // --
                             << bsl::hex(vpid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::safe_uint16::failure();
            }

            // if (bsl::unlikely(vp_pool.is_zombie(mut_tls, vpid))) {
            //     bsl::error() << "vp "                                                // --
            //                  << bsl::hex(vpid)                                       // --
            //                  << " is a zombie and a vps cannot be assigned to it"    // --
            //                  << bsl::endl                                            // --
            //                  << bsl::here();                                         // --

            //     return bsl::safe_uint16::failure();
            // }

            // if (bsl::unlikely(vp_pool.is_deallocated(mut_tls, vpid))) {
            //     bsl::error() << "vp "                                                         // --
            //                  << bsl::hex(vpid)                                                // --
            //                  << " has not been created and a vps cannot be assigned to it"    // --
            //                  << bsl::endl                                                     // --
            //                  << bsl::here();                                                  // --

            //     return bsl::safe_uint16::failure();
            // }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                               // --
                             << bsl::hex(ppid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(!(ppid < mut_tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(mut_tls.online_pps)                           // --
                             << " and a vps cannot be assigned to it"                  // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vps "                                           // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::safe_uint16::failure();
            }

            bsl::finally mut_cleanup_on_error{[this, &mut_tls, &mut_page_pool]() noexcept -> void {
                m_host_vmcb_phys = bsl::safe_uintmax::failure();
                mut_page_pool.deallocate(mut_tls, m_host_vmcb, ALLOCATE_TAG_HOST_VMCB);
                m_host_vmcb = {};

                m_guest_vmcb_phys = bsl::safe_uintmax::failure();
                mut_page_pool.deallocate(mut_tls, m_guest_vmcb, ALLOCATE_TAG_GUEST_VMCB);
                m_guest_vmcb = {};
            }};

            m_guest_vmcb =
                mut_page_pool.template allocate<vmcb_t>(mut_tls, ALLOCATE_TAG_GUEST_VMCB);
            if (bsl::unlikely(nullptr == m_guest_vmcb)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_guest_vmcb_phys = mut_page_pool.virt_to_phys(m_guest_vmcb);
            if (bsl::unlikely_assert(!m_guest_vmcb_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_host_vmcb = mut_page_pool.template allocate<vmcb_t>(mut_tls, ALLOCATE_TAG_HOST_VMCB);
            if (bsl::unlikely(nullptr == m_host_vmcb)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_host_vmcb_phys = mut_page_pool.virt_to_phys(m_host_vmcb);
            if (bsl::unlikely_assert(!m_host_vmcb_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;
            m_allocated = allocated_status_t::allocated;

            mut_cleanup_on_error.ignore();
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                               // --
                             << bsl::hex(m_id)                                       // --
                             << " is already deallocated and cannot be destroyed"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_precondition;
            }

            bsl::finally mut_zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is active on pp "        // --
                             << bsl::hex(m_active_ppid)    // --
                             << " and therefore vps "      // --
                             << bsl::hex(m_id)             // --
                             << " cannot be destroyed"     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            m_gprs = {};

            m_host_vmcb_phys = bsl::safe_uintmax::failure();
            mut_page_pool.deallocate(mut_tls, m_host_vmcb, ALLOCATE_TAG_HOST_VMCB);
            m_host_vmcb = {};

            m_guest_vmcb_phys = bsl::safe_uintmax::failure();
            mut_page_pool.deallocate(mut_tls, m_guest_vmcb, ALLOCATE_TAG_GUEST_VMCB);
            m_guest_vmcb = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;

            mut_zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t's status as zombified, meaning it is no
        ///     longer usable.
        ///
        constexpr void
        zombify() noexcept
        {
            if (bsl::unlikely_assert(!m_id)) {
                return;
            }

            if (m_allocated == allocated_status_t::zombie) {
                return;
            }

            bsl::alert() << "vps "                   // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(mut_tls.active_vpid != m_assigned_vpid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to vp "                  // --
                             << bsl::hex(m_assigned_vpid)              // --
                             << " and cannot be activated with vp "    // --
                             << bsl::hex(mut_tls.active_vpid)          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vps "                               // --
                             << bsl::hex(m_id)                       // --
                             << " is assigned to pp "                // --
                             << bsl::hex(m_assigned_ppid)            // --
                             << " and cannot be activated on pp "    // --
                             << bsl::hex(mut_tls.ppid)               // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != mut_tls.active_vpsid)) {
                bsl::error() << "vps "                            // --
                             << bsl::hex(mut_tls.active_vpsid)    // --
                             << " is still active on pp "         // --
                             << bsl::hex(mut_tls.ppid)            // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is already the active vps on pp "    // --
                             << bsl::hex(m_active_ppid)                // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

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

            mut_tls.active_vpsid = m_id.get();
            m_active_ppid = mut_tls.ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::deallocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == mut_tls.active_vpsid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(mut_tls.ppid)     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(mut_tls.active_vpsid != m_id)) {
                bsl::error() << "vps "                            // --
                             << bsl::hex(mut_tls.active_vpsid)    // --
                             << " is still active on pp "         // --
                             << bsl::hex(mut_tls.ppid)            // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!m_active_ppid)) {
                bsl::error() << "vps "               // --
                             << bsl::hex(m_id)       // --
                             << " is not active "    // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(mut_tls.ppid != m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(mut_tls.ppid)     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

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

            mut_tls.active_vpsid = syscall::BF_INVALID_ID.get();
            m_active_ppid = bsl::safe_uint16::failure();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP that this vps_t is still active
        ///     on. If the vps_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the PP that this vps_t is still active
        ///     on. If the vps_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t const &tls) const noexcept -> bsl::safe_uint16
        {
            bsl::discard(tls);
            return m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vps_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t const &tls) const noexcept -> bool
        {
            return tls.ppid == m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Migrates this vps_t from one PP to another. This should
        ///     only be called by the run ABI when the VP and VPS's assigned
        ///     ppids do not match. The VPS should always match the assigned
        ///     VP's ID. If it doesn't we need to migrate the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        migrate(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_uint16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(ppid);

            // if (bsl::unlikely_assert(!m_id)) {
            //     bsl::error() << "vps_t not initialized\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!m_allocated)) {
            //     bsl::error() << "vps "                    // --
            //                  << bsl::hex(m_id)            // --
            //                  << " was never allocated"    // --
            //                  << bsl::endl                 // --
            //                  << bsl::here();              // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!ppid)) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!(ppid < tls.online_pps))) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(tls.ppid != ppid)) {
            //     bsl::error() << "vps "                         // --
            //                  << bsl::hex(m_id)                 // --
            //                  << " is being migrated to pp "    // --
            //                  << bsl::hex(ppid)                 // --
            //                  << " by pp "                      // --
            //                  << bsl::hex(tls.ppid)             // --
            //                  << " which is not allowed "       // --
            //                  << bsl::endl                      // --
            //                  << bsl::here();                   // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(ppid == m_assigned_ppid)) {
            //     bsl::error() << "vps "                             // --
            //                  << bsl::hex(m_id)                     // --
            //                  << " is already assigned to a pp "    // --
            //                  << bsl::hex(m_assigned_ppid)          // --
            //                  << bsl::endl                          // --
            //                  << bsl::here();                       // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(syscall::BF_INVALID_ID != m_active_ppid)) {
            //     bsl::error() << "vps "                       // --
            //                  << bsl::hex(m_id)               // --
            //                  << " is still active on pp "    // --
            //                  << bsl::hex(m_active_ppid)      // --
            //                  << bsl::endl                    // --
            //                  << bsl::here();                 // --

            //     return bsl::errc_failure;
            // }

            // m_guest_vmcb->vmcb_clean_bits = bsl::ZERO_U32.get();
            // m_assigned_ppid = ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(syscall::BF_INVALID_ID == m_assigned_vpid)) {
                return bsl::safe_uint16::failure();
            }

            return m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(syscall::BF_INVALID_ID == m_assigned_ppid)) {
                return bsl::safe_uint16::failure();
            }

            return m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            tls_t const &tls,
            intrinsic_t &mut_intrinsic,
            loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (tls.active_vpsid == m_id) {
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(state.rax));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(state.rbx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(state.rcx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(state.rdx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(state.rbp));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(state.rsi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(state.rdi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(state.r8));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(state.r9));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(state.r10));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(state.r11));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(state.r12));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(state.r13));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(state.r14));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(state.r15));
            }
            else {
                m_gprs.rax = state.rax;
                m_gprs.rbx = state.rbx;
                m_gprs.rcx = state.rcx;
                m_gprs.rdx = state.rdx;
                m_gprs.rbp = state.rbp;
                m_gprs.rsi = state.rsi;
                m_gprs.rdi = state.rdi;
                m_gprs.r8 = state.r8;
                m_gprs.r9 = state.r9;
                m_gprs.r10 = state.r10;
                m_gprs.r11 = state.r11;
                m_gprs.r12 = state.r12;
                m_gprs.r13 = state.r13;
                m_gprs.r14 = state.r14;
                m_gprs.r15 = state.r15;
            }

            m_guest_vmcb->rsp = state.rsp;
            m_guest_vmcb->rip = state.rip;

            m_guest_vmcb->rflags = state.rflags;

            m_guest_vmcb->gdtr_limit = bsl::to_u32(state.gdtr.limit).get();
            m_guest_vmcb->gdtr_base = state.gdtr.base;
            m_guest_vmcb->idtr_limit = bsl::to_u32(state.idtr.limit).get();
            m_guest_vmcb->idtr_base = state.idtr.base;

            m_guest_vmcb->es_selector = state.es_selector;
            m_guest_vmcb->es_attrib = compress_attrib(bsl::to_u16(state.es_attrib)).get();
            m_guest_vmcb->es_limit = state.es_limit;
            m_guest_vmcb->es_base = state.es_base;

            m_guest_vmcb->cs_selector = state.cs_selector;
            m_guest_vmcb->cs_attrib = compress_attrib(bsl::to_u16(state.cs_attrib)).get();
            m_guest_vmcb->cs_limit = state.cs_limit;
            m_guest_vmcb->cs_base = state.cs_base;

            m_guest_vmcb->ss_selector = state.ss_selector;
            m_guest_vmcb->ss_attrib = compress_attrib(bsl::to_u16(state.ss_attrib)).get();
            m_guest_vmcb->ss_limit = state.ss_limit;
            m_guest_vmcb->ss_base = state.ss_base;

            m_guest_vmcb->ds_selector = state.ds_selector;
            m_guest_vmcb->ds_attrib = compress_attrib(bsl::to_u16(state.ds_attrib)).get();
            m_guest_vmcb->ds_limit = state.ds_limit;
            m_guest_vmcb->ds_base = state.ds_base;

            m_guest_vmcb->fs_selector = state.fs_selector;
            m_guest_vmcb->fs_attrib = compress_attrib(bsl::to_u16(state.fs_attrib)).get();
            m_guest_vmcb->fs_limit = state.fs_limit;

            m_guest_vmcb->gs_selector = state.gs_selector;
            m_guest_vmcb->gs_attrib = compress_attrib(bsl::to_u16(state.gs_attrib)).get();
            m_guest_vmcb->gs_limit = state.gs_limit;

            m_guest_vmcb->ldtr_selector = state.ldtr_selector;
            m_guest_vmcb->ldtr_attrib = compress_attrib(bsl::to_u16(state.ldtr_attrib)).get();
            m_guest_vmcb->ldtr_limit = state.ldtr_limit;
            m_guest_vmcb->ldtr_base = state.ldtr_base;

            m_guest_vmcb->tr_selector = state.tr_selector;
            m_guest_vmcb->tr_attrib = compress_attrib(bsl::to_u16(state.tr_attrib)).get();
            m_guest_vmcb->tr_limit = state.tr_limit;
            m_guest_vmcb->tr_base = state.tr_base;

            m_guest_vmcb->cr0 = state.cr0;
            m_guest_vmcb->cr2 = state.cr2;
            m_guest_vmcb->cr3 = state.cr3;
            m_guest_vmcb->cr4 = state.cr4;

            m_guest_vmcb->dr6 = state.dr6;
            m_guest_vmcb->dr7 = state.dr7;

            m_guest_vmcb->efer = state.ia32_efer;
            m_guest_vmcb->star = state.ia32_star;
            m_guest_vmcb->lstar = state.ia32_lstar;
            m_guest_vmcb->cstar = state.ia32_cstar;
            m_guest_vmcb->sfmask = state.ia32_fmask;
            m_guest_vmcb->fs_base = state.ia32_fs_base;
            m_guest_vmcb->gs_base = state.ia32_gs_base;
            m_guest_vmcb->kernel_gs_base = state.ia32_kernel_gs_base;
            m_guest_vmcb->sysenter_cs = state.ia32_sysenter_cs;
            m_guest_vmcb->sysenter_esp = state.ia32_sysenter_esp;
            m_guest_vmcb->sysenter_eip = state.ia32_sysenter_eip;
            m_guest_vmcb->g_pat = state.ia32_pat;
            m_guest_vmcb->dbgctl = state.ia32_debugctl;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param mut_state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vps_to_state_save(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t &mut_state) const noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (tls.active_vpsid == m_id) {
                mut_state.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
                mut_state.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
                mut_state.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
                mut_state.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
                mut_state.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
                mut_state.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
                mut_state.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
                mut_state.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
                mut_state.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
                mut_state.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
                mut_state.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
                mut_state.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
                mut_state.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
                mut_state.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
                mut_state.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            }
            else {
                mut_state.rax = m_gprs.rax;
                mut_state.rbx = m_gprs.rbx;
                mut_state.rcx = m_gprs.rcx;
                mut_state.rdx = m_gprs.rdx;
                mut_state.rbp = m_gprs.rbp;
                mut_state.rsi = m_gprs.rsi;
                mut_state.rdi = m_gprs.rdi;
                mut_state.r8 = m_gprs.r8;
                mut_state.r9 = m_gprs.r9;
                mut_state.r10 = m_gprs.r10;
                mut_state.r11 = m_gprs.r11;
                mut_state.r12 = m_gprs.r12;
                mut_state.r13 = m_gprs.r13;
                mut_state.r14 = m_gprs.r14;
                mut_state.r15 = m_gprs.r15;
            }

            mut_state.rsp = m_guest_vmcb->rsp;
            mut_state.rip = m_guest_vmcb->rip;

            mut_state.rflags = m_guest_vmcb->rflags;

            mut_state.gdtr.limit = bsl::to_u16(m_guest_vmcb->gdtr_limit).get();
            mut_state.gdtr.base = m_guest_vmcb->gdtr_base;
            mut_state.idtr.limit = bsl::to_u16(m_guest_vmcb->idtr_limit).get();
            mut_state.idtr.base = m_guest_vmcb->idtr_base;

            mut_state.es_selector = m_guest_vmcb->es_selector;
            mut_state.es_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->es_attrib)).get();
            mut_state.es_limit = m_guest_vmcb->es_limit;
            mut_state.es_base = m_guest_vmcb->es_base;

            mut_state.cs_selector = m_guest_vmcb->cs_selector;
            mut_state.cs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->cs_attrib)).get();
            mut_state.cs_limit = m_guest_vmcb->cs_limit;
            mut_state.cs_base = m_guest_vmcb->cs_base;

            mut_state.ss_selector = m_guest_vmcb->ss_selector;
            mut_state.ss_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->ss_attrib)).get();
            mut_state.ss_limit = m_guest_vmcb->ss_limit;
            mut_state.ss_base = m_guest_vmcb->ss_base;

            mut_state.ds_selector = m_guest_vmcb->ds_selector;
            mut_state.ds_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->ds_attrib)).get();
            mut_state.ds_limit = m_guest_vmcb->ds_limit;
            mut_state.ds_base = m_guest_vmcb->ds_base;

            mut_state.fs_selector = m_guest_vmcb->fs_selector;
            mut_state.fs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->fs_attrib)).get();
            mut_state.fs_limit = m_guest_vmcb->fs_limit;

            mut_state.gs_selector = m_guest_vmcb->gs_selector;
            mut_state.gs_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->gs_attrib)).get();
            mut_state.gs_limit = m_guest_vmcb->gs_limit;

            mut_state.ldtr_selector = m_guest_vmcb->ldtr_selector;
            mut_state.ldtr_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->ldtr_attrib)).get();
            mut_state.ldtr_limit = m_guest_vmcb->ldtr_limit;
            mut_state.ldtr_base = m_guest_vmcb->ldtr_base;

            mut_state.tr_selector = m_guest_vmcb->tr_selector;
            mut_state.tr_attrib = decompress_attrib(bsl::to_u16(m_guest_vmcb->tr_attrib)).get();
            mut_state.tr_limit = m_guest_vmcb->tr_limit;
            mut_state.tr_base = m_guest_vmcb->tr_base;

            mut_state.cr0 = m_guest_vmcb->cr0;
            mut_state.cr2 = m_guest_vmcb->cr2;
            mut_state.cr3 = m_guest_vmcb->cr3;
            mut_state.cr4 = m_guest_vmcb->cr4;

            mut_state.dr6 = m_guest_vmcb->dr6;
            mut_state.dr7 = m_guest_vmcb->dr7;

            mut_state.ia32_efer = m_guest_vmcb->efer;
            mut_state.ia32_star = m_guest_vmcb->star;
            mut_state.ia32_lstar = m_guest_vmcb->lstar;
            mut_state.ia32_cstar = m_guest_vmcb->cstar;
            mut_state.ia32_fmask = m_guest_vmcb->sfmask;
            mut_state.ia32_fs_base = m_guest_vmcb->fs_base;
            mut_state.ia32_gs_base = m_guest_vmcb->gs_base;
            mut_state.ia32_kernel_gs_base = m_guest_vmcb->kernel_gs_base;
            mut_state.ia32_sysenter_cs = m_guest_vmcb->sysenter_cs;
            mut_state.ia32_sysenter_esp = m_guest_vmcb->sysenter_esp;
            mut_state.ia32_sysenter_eip = m_guest_vmcb->sysenter_eip;
            mut_state.ia32_pat = m_guest_vmcb->g_pat;
            mut_state.ia32_debugctl = m_guest_vmcb->dbgctl;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_uintmax::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        read(tls_t const &tls, intrinsic_t const &intrinsic, syscall::bf_reg_t const reg)
            const noexcept -> bsl::safe_uintmax
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_uintmax::failure();
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
                    }

                    return bsl::to_umax(m_gprs.rax);
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
                    }

                    return bsl::to_umax(m_gprs.rbx);
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
                    }

                    return bsl::to_umax(m_gprs.rcx);
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
                    }

                    return bsl::to_umax(m_gprs.rdx);
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
                    }

                    return bsl::to_umax(m_gprs.rbp);
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
                    }

                    return bsl::to_umax(m_gprs.rsi);
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
                    }

                    return bsl::to_umax(m_gprs.rdi);
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
                    }

                    return bsl::to_umax(m_gprs.r8);
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
                    }

                    return bsl::to_umax(m_gprs.r9);
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
                    }

                    return bsl::to_umax(m_gprs.r10);
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
                    }

                    return bsl::to_umax(m_gprs.r11);
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
                    }

                    return bsl::to_umax(m_gprs.r12);
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
                    }

                    return bsl::to_umax(m_gprs.r13);
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
                    }

                    return bsl::to_umax(m_gprs.r14);
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
                    }

                    return bsl::to_umax(m_gprs.r15);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_read: {
                    return bsl::to_umax(m_guest_vmcb->intercept_cr_read);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_write: {
                    return bsl::to_umax(m_guest_vmcb->intercept_cr_write);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_read: {
                    return bsl::to_umax(m_guest_vmcb->intercept_dr_read);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_write: {
                    return bsl::to_umax(m_guest_vmcb->intercept_dr_write);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_exception: {
                    return bsl::to_umax(m_guest_vmcb->intercept_exception);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction1: {
                    return bsl::to_umax(m_guest_vmcb->intercept_instruction1);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction2: {
                    return bsl::to_umax(m_guest_vmcb->intercept_instruction2);
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction3: {
                    return bsl::to_umax(m_guest_vmcb->intercept_instruction3);
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_threshold: {
                    return bsl::to_umax(m_guest_vmcb->pause_filter_threshold);
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_count: {
                    return bsl::to_umax(m_guest_vmcb->pause_filter_count);
                }

                case syscall::bf_reg_t::bf_reg_t_iopm_base_pa: {
                    return bsl::to_umax(m_guest_vmcb->iopm_base_pa);
                }

                case syscall::bf_reg_t::bf_reg_t_msrpm_base_pa: {
                    return bsl::to_umax(m_guest_vmcb->msrpm_base_pa);
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    return bsl::to_umax(m_guest_vmcb->tsc_offset);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_asid: {
                    return bsl::to_umax(m_guest_vmcb->guest_asid);
                }

                case syscall::bf_reg_t::bf_reg_t_tlb_control: {
                    return bsl::to_umax(m_guest_vmcb->tlb_control);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_a: {
                    return bsl::to_umax(m_guest_vmcb->virtual_interrupt_a);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_interrupt_b: {
                    return bsl::to_umax(m_guest_vmcb->virtual_interrupt_b);
                }

                case syscall::bf_reg_t::bf_reg_t_exitcode: {
                    return bsl::to_umax(m_guest_vmcb->exitcode);
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo1: {
                    return bsl::to_umax(m_guest_vmcb->exitinfo1);
                }

                case syscall::bf_reg_t::bf_reg_t_exitinfo2: {
                    return bsl::to_umax(m_guest_vmcb->exitinfo2);
                }

                case syscall::bf_reg_t::bf_reg_t_exitininfo: {
                    return bsl::to_umax(m_guest_vmcb->exitininfo);
                }

                case syscall::bf_reg_t::bf_reg_t_ctls1: {
                    return bsl::to_umax(m_guest_vmcb->ctls1);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_bar: {
                    return bsl::to_umax(m_guest_vmcb->avic_apic_bar);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pa_of_ghcb: {
                    return bsl::to_umax(m_guest_vmcb->guest_pa_of_ghcb);
                }

                case syscall::bf_reg_t::bf_reg_t_eventinj: {
                    return bsl::to_umax(m_guest_vmcb->eventinj);
                }

                case syscall::bf_reg_t::bf_reg_t_n_cr3: {
                    return bsl::to_umax(m_guest_vmcb->n_cr3);
                }

                case syscall::bf_reg_t::bf_reg_t_ctls2: {
                    return bsl::to_umax(m_guest_vmcb->ctls2);
                }

                case syscall::bf_reg_t::bf_reg_t_vmcb_clean_bits: {
                    return bsl::to_umax(m_guest_vmcb->vmcb_clean_bits);
                }

                case syscall::bf_reg_t::bf_reg_t_nrip: {
                    return bsl::to_umax(m_guest_vmcb->nrip);
                }

                case syscall::bf_reg_t::bf_reg_t_number_of_bytes_fetched: {
                    return bsl::to_umax(m_guest_vmcb->number_of_bytes_fetched);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_apic_backing_page_ptr: {
                    return bsl::to_umax(m_guest_vmcb->avic_apic_backing_page_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_logical_table_ptr: {
                    return bsl::to_umax(m_guest_vmcb->avic_logical_table_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_avic_physical_table_ptr: {
                    return bsl::to_umax(m_guest_vmcb->avic_physical_table_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_vmsa_ptr: {
                    return bsl::to_umax(m_guest_vmcb->vmsa_ptr);
                }

                case syscall::bf_reg_t::bf_reg_t_es_selector: {
                    return bsl::to_umax(m_guest_vmcb->es_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    return bsl::to_umax(m_guest_vmcb->es_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    return bsl::to_umax(m_guest_vmcb->es_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    return bsl::to_umax(m_guest_vmcb->es_base);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    return bsl::to_umax(m_guest_vmcb->cs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    return bsl::to_umax(m_guest_vmcb->cs_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    return bsl::to_umax(m_guest_vmcb->cs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    return bsl::to_umax(m_guest_vmcb->cs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    return bsl::to_umax(m_guest_vmcb->ss_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    return bsl::to_umax(m_guest_vmcb->ss_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    return bsl::to_umax(m_guest_vmcb->ss_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    return bsl::to_umax(m_guest_vmcb->ss_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    return bsl::to_umax(m_guest_vmcb->ds_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    return bsl::to_umax(m_guest_vmcb->ds_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    return bsl::to_umax(m_guest_vmcb->ds_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    return bsl::to_umax(m_guest_vmcb->ds_base);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    return bsl::to_umax(m_guest_vmcb->fs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    return bsl::to_umax(m_guest_vmcb->fs_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    return bsl::to_umax(m_guest_vmcb->fs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    return bsl::to_umax(m_guest_vmcb->fs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    return bsl::to_umax(m_guest_vmcb->gs_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    return bsl::to_umax(m_guest_vmcb->gs_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    return bsl::to_umax(m_guest_vmcb->gs_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    return bsl::to_umax(m_guest_vmcb->gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_selector: {
                    return bsl::to_umax(m_guest_vmcb->gdtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_attrib: {
                    return bsl::to_umax(m_guest_vmcb->gdtr_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    return bsl::to_umax(m_guest_vmcb->gdtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    return bsl::to_umax(m_guest_vmcb->gdtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    return bsl::to_umax(m_guest_vmcb->ldtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    return bsl::to_umax(m_guest_vmcb->ldtr_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    return bsl::to_umax(m_guest_vmcb->ldtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    return bsl::to_umax(m_guest_vmcb->ldtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_selector: {
                    return bsl::to_umax(m_guest_vmcb->idtr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_attrib: {
                    return bsl::to_umax(m_guest_vmcb->idtr_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    return bsl::to_umax(m_guest_vmcb->idtr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    return bsl::to_umax(m_guest_vmcb->idtr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    return bsl::to_umax(m_guest_vmcb->tr_selector);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    return bsl::to_umax(m_guest_vmcb->tr_attrib);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    return bsl::to_umax(m_guest_vmcb->tr_limit);
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    return bsl::to_umax(m_guest_vmcb->tr_base);
                }

                case syscall::bf_reg_t::bf_reg_t_cpl: {
                    return bsl::to_umax(m_guest_vmcb->cpl);
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    return bsl::to_umax(m_guest_vmcb->efer);
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    return bsl::to_umax(m_guest_vmcb->cr4);
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    return bsl::to_umax(m_guest_vmcb->cr3);
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    return bsl::to_umax(m_guest_vmcb->cr0);
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    return bsl::to_umax(m_guest_vmcb->dr7);
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    return bsl::to_umax(m_guest_vmcb->dr6);
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    return bsl::to_umax(m_guest_vmcb->rflags);
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    return bsl::to_umax(m_guest_vmcb->rip);
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    return bsl::to_umax(m_guest_vmcb->rsp);
                }

                case syscall::bf_reg_t::bf_reg_t_star: {
                    return bsl::to_umax(m_guest_vmcb->star);
                }

                case syscall::bf_reg_t::bf_reg_t_lstar: {
                    return bsl::to_umax(m_guest_vmcb->lstar);
                }

                case syscall::bf_reg_t::bf_reg_t_cstar: {
                    return bsl::to_umax(m_guest_vmcb->cstar);
                }

                case syscall::bf_reg_t::bf_reg_t_sfmask: {
                    return bsl::to_umax(m_guest_vmcb->sfmask);
                }

                case syscall::bf_reg_t::bf_reg_t_kernel_gs_base: {
                    return bsl::to_umax(m_guest_vmcb->kernel_gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_cs: {
                    return bsl::to_umax(m_guest_vmcb->sysenter_cs);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_esp: {
                    return bsl::to_umax(m_guest_vmcb->sysenter_esp);
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_eip: {
                    return bsl::to_umax(m_guest_vmcb->sysenter_eip);
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    return bsl::to_umax(m_guest_vmcb->cr2);
                }

                case syscall::bf_reg_t::bf_reg_t_g_pat: {
                    return bsl::to_umax(m_guest_vmcb->g_pat);
                }

                case syscall::bf_reg_t::bf_reg_t_dbgctl: {
                    return bsl::to_umax(m_guest_vmcb->dbgctl);
                }

                case syscall::bf_reg_t::bf_reg_t_br_from: {
                    return bsl::to_umax(m_guest_vmcb->br_from);
                }

                case syscall::bf_reg_t::bf_reg_t_br_to: {
                    return bsl::to_umax(m_guest_vmcb->br_to);
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpfrom: {
                    return bsl::to_umax(m_guest_vmcb->lastexcpfrom);
                }

                case syscall::bf_reg_t::bf_reg_t_lastexcpto: {
                    return bsl::to_umax(m_guest_vmcb->lastexcpto);
                }

                default: {
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            return bsl::safe_uintmax::failure();
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t const &tls,
            intrinsic_t &mut_intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_uintmax const &val) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!val)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    }
                    else {
                        m_gprs.rax = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    }
                    else {
                        m_gprs.rbx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    }
                    else {
                        m_gprs.rcx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    }
                    else {
                        m_gprs.rdx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    }
                    else {
                        m_gprs.rbp = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    }
                    else {
                        m_gprs.rsi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    }
                    else {
                        m_gprs.rdi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    }
                    else {
                        m_gprs.r8 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    }
                    else {
                        m_gprs.r9 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    }
                    else {
                        m_gprs.r10 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    }
                    else {
                        m_gprs.r11 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    }
                    else {
                        m_gprs.r12 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    }
                    else {
                        m_gprs.r13 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    }
                    else {
                        m_gprs.r14 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
                    }
                    else {
                        m_gprs.r15 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_read: {
                    m_guest_vmcb->intercept_cr_read = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_cr_write: {
                    m_guest_vmcb->intercept_cr_write = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_read: {
                    m_guest_vmcb->intercept_dr_read = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_dr_write: {
                    m_guest_vmcb->intercept_dr_write = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_exception: {
                    m_guest_vmcb->intercept_exception = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction1: {
                    m_guest_vmcb->intercept_instruction1 = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction2: {
                    m_guest_vmcb->intercept_instruction2 = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_intercept_instruction3: {
                    m_guest_vmcb->intercept_instruction3 = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_threshold: {
                    m_guest_vmcb->pause_filter_threshold = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_pause_filter_count: {
                    m_guest_vmcb->pause_filter_count = bsl::to_u16(val).get();
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
                    m_guest_vmcb->guest_asid = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tlb_control: {
                    m_guest_vmcb->tlb_control = bsl::to_u8(val).get();
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
                    m_guest_vmcb->vmcb_clean_bits = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_nrip: {
                    m_guest_vmcb->nrip = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_number_of_bytes_fetched: {
                    m_guest_vmcb->number_of_bytes_fetched = bsl::to_u8(val).get();
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
                    m_guest_vmcb->es_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    m_guest_vmcb->es_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    m_guest_vmcb->es_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    m_guest_vmcb->es_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    m_guest_vmcb->cs_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    m_guest_vmcb->cs_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    m_guest_vmcb->cs_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    m_guest_vmcb->cs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    m_guest_vmcb->ss_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    m_guest_vmcb->ss_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    m_guest_vmcb->ss_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    m_guest_vmcb->ss_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    m_guest_vmcb->ds_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    m_guest_vmcb->ds_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    m_guest_vmcb->ds_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    m_guest_vmcb->ds_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    m_guest_vmcb->fs_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    m_guest_vmcb->fs_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    m_guest_vmcb->fs_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    m_guest_vmcb->fs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    m_guest_vmcb->gs_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    m_guest_vmcb->gs_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    m_guest_vmcb->gs_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    m_guest_vmcb->gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_selector: {
                    m_guest_vmcb->gdtr_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_attrib: {
                    m_guest_vmcb->gdtr_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    m_guest_vmcb->gdtr_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    m_guest_vmcb->gdtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    m_guest_vmcb->ldtr_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    m_guest_vmcb->ldtr_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    m_guest_vmcb->ldtr_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    m_guest_vmcb->ldtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_selector: {
                    m_guest_vmcb->idtr_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_attrib: {
                    m_guest_vmcb->idtr_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    m_guest_vmcb->idtr_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    m_guest_vmcb->idtr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    m_guest_vmcb->tr_selector = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    m_guest_vmcb->tr_attrib = bsl::to_u16(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    m_guest_vmcb->tr_limit = bsl::to_u32(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    m_guest_vmcb->tr_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cpl: {
                    m_guest_vmcb->cpl = bsl::to_u8(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    m_guest_vmcb->efer = val.get();
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

                case syscall::bf_reg_t::bf_reg_t_sfmask: {
                    m_guest_vmcb->sfmask = val.get();
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

                case syscall::bf_reg_t::bf_reg_t_g_pat: {
                    m_guest_vmcb->g_pat = val.get();
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

                default: {
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Runs the VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param mut_log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_uintmax::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t const &tls, intrinsic_t &mut_intrinsic, vmexit_log_t &mut_log) noexcept
            -> bsl::safe_uintmax
        {
            bsl::discard(mut_intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely_assert(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely_assert(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(m_id)               // --
                             << " is assigned to pp "        // --
                             << bsl::hex(m_assigned_ppid)    // --
                             << " and cannot run by pp "     // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::safe_uintmax::failure();
            }

            bsl::safe_uintmax const exit_reason{intrinsic_vmrun(
                m_guest_vmcb, m_guest_vmcb_phys.get(), m_host_vmcb, m_host_vmcb_phys.get())};

            if constexpr (BSL_DEBUG_LEVEL >= bsl::VV) {
                mut_log.add(
                    bsl::to_u16(tls.ppid),
                    {bsl::to_u16(tls.active_vmid),
                     bsl::to_u16(tls.active_vpid),
                     bsl::to_u16(tls.active_vpsid),
                     bsl::to_umax(exit_reason),
                     bsl::to_umax(m_guest_vmcb->exitinfo1),
                     bsl::to_umax(m_guest_vmcb->exitinfo2),
                     bsl::to_umax(m_guest_vmcb->exitininfo),
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
                     bsl::to_umax(m_guest_vmcb->rsp),
                     bsl::to_umax(m_guest_vmcb->rip)});
            }

            /// TODO:
            /// - Add check logic to if an entry failure occurs and output
            ///   what the error was and why.
            ///

            return exit_reason;
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        advance_ip(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            m_guest_vmcb->rip = m_guest_vmcb->nrip;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Clears the VPS's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t const &tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            constexpr auto reset{0_u32};
            m_guest_vmcb->vmcb_clean_bits = reset.get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///
        constexpr void
        dump(tls_t const &tls, intrinsic_t const &intrinsic) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            // clang-format off

            constexpr auto guest_instruction_bytes_0{0x0_umax};
            constexpr auto guest_instruction_bytes_1{0x1_umax};
            constexpr auto guest_instruction_bytes_2{0x2_umax};
            constexpr auto guest_instruction_bytes_3{0x3_umax};
            constexpr auto guest_instruction_bytes_4{0x4_umax};
            constexpr auto guest_instruction_bytes_5{0x5_umax};
            constexpr auto guest_instruction_bytes_6{0x6_umax};
            constexpr auto guest_instruction_bytes_7{0x7_umax};
            constexpr auto guest_instruction_bytes_8{0x8_umax};
            constexpr auto guest_instruction_bytes_9{0x9_umax};
            constexpr auto guest_instruction_bytes_a{0xA_umax};
            /// NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
            constexpr auto guest_instruction_bytes_b{0xB_umax};
            constexpr auto guest_instruction_bytes_c{0xC_umax};
            constexpr auto guest_instruction_bytes_d{0xD_umax};
            constexpr auto guest_instruction_bytes_e{0xE_umax};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            bsl::print() << bsl::mag << "vps [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
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
            if (m_assigned_vpid != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(m_assigned_vpid) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(m_assigned_vpid) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned PP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<30s", "assigned pp "};
            bsl::print() << bsl::ylw << "| ";
            if (m_assigned_ppid != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(m_assigned_ppid) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(m_assigned_ppid) << "       ";
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

            if (tls.active_vpsid == m_id) {
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
            this->dump_field("sfmask ", bsl::make_safe(m_guest_vmcb->sfmask));
            this->dump_field("kernel_gs_base ", bsl::make_safe(m_guest_vmcb->kernel_gs_base));
            this->dump_field("sysenter_cs ", bsl::make_safe(m_guest_vmcb->sysenter_cs));
            this->dump_field("sysenter_esp ", bsl::make_safe(m_guest_vmcb->sysenter_esp));
            this->dump_field("sysenter_eip ", bsl::make_safe(m_guest_vmcb->sysenter_eip));
            this->dump_field("cr2 ", bsl::make_safe(m_guest_vmcb->cr2));
            this->dump_field("g_pat ", bsl::make_safe(m_guest_vmcb->g_pat));
            this->dump_field("dbgctl ", bsl::make_safe(m_guest_vmcb->dbgctl));
            this->dump_field("br_from ", bsl::make_safe(m_guest_vmcb->br_from));
            this->dump_field("br_to ", bsl::make_safe(m_guest_vmcb->br_to));
            this->dump_field("lastexcpfrom ", bsl::make_safe(m_guest_vmcb->lastexcpfrom));
            this->dump_field("lastexcpto ", bsl::make_safe(m_guest_vmcb->lastexcpto));

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
