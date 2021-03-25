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

        /// @brief stores the general purpose registers
        general_purpose_regs_t m_gprs{};

        /// <!-- description -->
        ///   @brief Dumps the contents of a field
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of field to dump
        ///   @param str the name of the field
        ///   @param val the field to dump
        ///
        template<typename T>
        constexpr void
        dump_field(bsl::string_view const &str, bsl::safe_integral<T> const &val) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            auto const *rowcolor{bsl::rst};

            if (val.is_zero()) {
                rowcolor = bsl::blk;
            }
            else {
                bsl::touch();
            }

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(page_pool);

            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
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

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            zombify_on_error.ignore();
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
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @param vp_pool the VP pool to use
        ///   @param vpid The ID of the VP to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vps
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &tls,
            intrinsic_t &intrinsic,
            page_pool_t &page_pool,
            vp_pool_t &vp_pool,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            bsl::discard(intrinsic);
            bsl::discard(page_pool);

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

            if (bsl::unlikely(vp_pool.is_zombie(tls, vpid))) {
                bsl::error() << "vp "                                                // --
                             << bsl::hex(vpid)                                       // --
                             << " is a zombie and a vps cannot be assigned to it"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(vp_pool.is_deallocated(tls, vpid))) {
                bsl::error() << "vp "                                                         // --
                             << bsl::hex(vpid)                                                // --
                             << " has not been created and a vps cannot be assigned to it"    // --
                             << bsl::endl                                                     // --
                             << bsl::here();                                                  // --

                return bsl::safe_uint16::failure();
            }

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

            if (bsl::unlikely(!(ppid < tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(tls.online_pps)                               // --
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

            tls.state_reversal_required = true;
            tls.log_vpsid = m_id.get();

            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;
            m_allocated = allocated_status_t::allocated;

            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(page_pool);

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

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
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

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;

            zombify_on_error.ignore();
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
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
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

            if (bsl::unlikely(tls.active_vpid != m_assigned_vpid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to vp "                  // --
                             << bsl::hex(m_assigned_vpid)              // --
                             << " and cannot be activated with vp "    // --
                             << bsl::hex(tls.active_vpid)              // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vps "                               // --
                             << bsl::hex(m_id)                       // --
                             << " is assigned to pp "                // --
                             << bsl::hex(m_assigned_ppid)            // --
                             << " and cannot be activated on pp "    // --
                             << bsl::hex(tls.ppid)                   // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vpsid)) {
                bsl::error() << "vps "                        // --
                             << bsl::hex(tls.active_vpsid)    // --
                             << " is still active on pp "     // --
                             << bsl::hex(tls.ppid)            // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

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

            bsl::discard(intrinsic);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, m_gprs.rax);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, m_gprs.rbx);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, m_gprs.rcx);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, m_gprs.rdx);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, m_gprs.rbp);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, m_gprs.rsi);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, m_gprs.rdi);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, m_gprs.r8);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, m_gprs.r9);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, m_gprs.r10);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, m_gprs.r11);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, m_gprs.r12);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, m_gprs.r13);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, m_gprs.r14);
            // intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, m_gprs.r15);

            tls.active_vpsid = m_id.get();
            m_active_ppid = tls.ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
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

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vpsid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.active_vpsid != m_id)) {
                bsl::error() << "vps "                        // --
                             << bsl::hex(tls.active_vpsid)    // --
                             << " is still active on pp "     // --
                             << bsl::hex(tls.ppid)            // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

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

            if (bsl::unlikely_assert(tls.ppid != m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            bsl::discard(intrinsic);
            // m_gprs.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
            // m_gprs.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
            // m_gprs.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
            // m_gprs.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
            // m_gprs.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
            // m_gprs.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
            // m_gprs.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
            // m_gprs.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
            // m_gprs.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
            // m_gprs.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
            // m_gprs.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
            // m_gprs.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
            // m_gprs.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
            // m_gprs.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
            // m_gprs.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();

            tls.active_vpsid = syscall::BF_INVALID_ID.get();
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
        is_active(tls_t &tls) const noexcept -> bsl::safe_uint16
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
        is_active_on_current_pp(tls_t &tls) const noexcept -> bool
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
        [[nodiscard]] constexpr auto
        migrate(tls_t &tls, intrinsic_t &intrinsic, bsl::safe_uint16 const &ppid) noexcept
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
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            tls_t &tls, intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept
            -> bsl::errc_type
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

            bsl::discard(intrinsic);
            bsl::discard(state);
            // if (tls.active_vpsid == m_id) {
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, state.rax);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, state.rbx);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, state.rcx);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, state.rdx);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, state.rbp);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, state.rsi);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, state.rdi);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, state.r8);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, state.r9);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, state.r10);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, state.r11);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, state.r12);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, state.r13);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, state.r14);
            //     intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, state.r15);
            // }
            // else {
            //     m_gprs.rax = state.rax;
            //     m_gprs.rbx = state.rbx;
            //     m_gprs.rcx = state.rcx;
            //     m_gprs.rdx = state.rdx;
            //     m_gprs.rbp = state.rbp;
            //     m_gprs.rsi = state.rsi;
            //     m_gprs.rdi = state.rdi;
            //     m_gprs.r8 = state.r8;
            //     m_gprs.r9 = state.r9;
            //     m_gprs.r10 = state.r10;
            //     m_gprs.r11 = state.r11;
            //     m_gprs.r12 = state.r12;
            //     m_gprs.r13 = state.r13;
            //     m_gprs.r14 = state.r14;
            //     m_gprs.r15 = state.r15;
            // }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vps_to_state_save(tls_t &tls, intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
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

            bsl::discard(intrinsic);
            bsl::discard(state);
            // if (tls.active_vpsid == m_id) {
            //     state.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
            //     state.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
            //     state.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
            //     state.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
            //     state.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
            //     state.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
            //     state.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
            //     state.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
            //     state.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
            //     state.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
            //     state.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
            //     state.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
            //     state.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
            //     state.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
            //     state.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            // }
            // else {
            //     state.rax = m_gprs.rax;
            //     state.rbx = m_gprs.rbx;
            //     state.rcx = m_gprs.rcx;
            //     state.rdx = m_gprs.rdx;
            //     state.rbp = m_gprs.rbp;
            //     state.rsi = m_gprs.rsi;
            //     state.rdi = m_gprs.rdi;
            //     state.r8 = m_gprs.r8;
            //     state.r9 = m_gprs.r9;
            //     state.r10 = m_gprs.r10;
            //     state.r11 = m_gprs.r11;
            //     state.r12 = m_gprs.r12;
            //     state.r13 = m_gprs.r13;
            //     state.r14 = m_gprs.r14;
            //     state.r15 = m_gprs.r15;
            // }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given the index of
        ///     the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to read
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param index the index of the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_integral<FIELD_TYPE>::failure()
        ///     on failure.
        ///
        template<typename FIELD_TYPE>
        [[nodiscard]] constexpr auto
        read(tls_t &tls, intrinsic_t &intrinsic, bsl::safe_uintmax const &index) noexcept
            -> bsl::safe_integral<FIELD_TYPE>
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(index);

            bsl::error() << "read not supported on aarch64\n" << bsl::here();
            return bsl::safe_integral<FIELD_TYPE>::failure();
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given the index of
        ///     the field and the value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to write
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param index the index of the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        template<typename FIELD_TYPE>
        [[nodiscard]] constexpr auto
        write(
            tls_t &tls,
            intrinsic_t &intrinsic,
            bsl::safe_uintmax const &index,
            bsl::safe_integral<FIELD_TYPE> const &val) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(index);
            bsl::discard(val);

            bsl::error() << "write not supported on aarch64\n" << bsl::here();
            return bsl::errc_failure;
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
        read_reg(tls_t &tls, intrinsic_t &intrinsic, syscall::bf_reg_t const reg) noexcept
            -> bsl::safe_uintmax
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

            bsl::discard(intrinsic);
            bsl::discard(reg);
            // switch (reg) {
            //     // case syscall::bf_reg_t::bf_reg_t_rax: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
            //     //     }

            //     //     return m_gprs.rax;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rbx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
            //     //     }

            //     //     return m_gprs.rbx;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rcx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
            //     //     }

            //     //     return m_gprs.rcx;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rdx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
            //     //     }

            //     //     return m_gprs.rdx;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rbp: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
            //     //     }

            //     //     return m_gprs.rbp;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rsi: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
            //     //     }

            //     //     return m_gprs.rsi;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rdi: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
            //     //     }

            //     //     return m_gprs.rdi;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r8: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
            //     //     }

            //     //     return m_gprs.r8;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r9: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
            //     //     }

            //     //     return m_gprs.r9;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r10: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
            //     //     }

            //     //     return m_gprs.r10;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r11: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
            //     //     }

            //     //     return m_gprs.r11;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r12: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
            //     //     }

            //     //     return m_gprs.r12;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r13: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
            //     //     }

            //     //     return m_gprs.r13;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r14: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
            //     //     }

            //     //     return m_gprs.r14;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r15: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
            //     //     }

            //     //     return m_gprs.r15;
            //     // }

            //     default: {
            //         bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
            //         break;
            //     }
            // }

            return bsl::safe_uintmax::failure();
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write_reg(
            tls_t &tls,
            intrinsic_t &intrinsic,
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

            bsl::discard(intrinsic);
            bsl::discard(reg);
            // switch (reg) {
            //     // case syscall::bf_reg_t::bf_reg_t_rax: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rax = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rbx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rbx = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rcx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rcx = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rdx: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rdx = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rbp: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rbp = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rsi: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rsi = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_rdi: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.rdi = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r8: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r8 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r9: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r9 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r10: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r10 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r11: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r11 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r12: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r12 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r13: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r13 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r14: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r14 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     // case syscall::bf_reg_t::bf_reg_t_r15: {
            //     //     if (tls.active_vpsid == m_id) {
            //     //         intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
            //     //     }
            //     //     else {
            //     //         m_gprs.r15 = val.get();
            //     //     }
            //     //     return bsl::errc_success;
            //     // }

            //     default: {
            //         bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
            //         break;
            //     }
            // }

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Runs the VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_uintmax::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t &tls, intrinsic_t &intrinsic, vmexit_log_t &log) noexcept -> bsl::safe_uintmax
        {
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

            bsl::discard(intrinsic);
            bsl::discard(log);
            // bsl::safe_uintmax const exit_reason{intrinsic_vmrun(
            //     m_guest_vmcb, m_guest_vmcb_phys.get(), m_host_vmcb, m_host_vmcb_phys.get())};

            // if constexpr (!(BSL_DEBUG_LEVEL < bsl::VV)) {
            //     log.add(
            //         tls.ppid,
            //         {tls.active_vmid,
            //          tls.active_vpid,
            //          tls.active_vpsid,
            //          exit_reason,
            //          m_guest_vmcb->exitinfo1,
            //          m_guest_vmcb->exitinfo2,
            //          m_guest_vmcb->exitininfo,
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RAX),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RBX),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RCX),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RDX),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RBP),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RSI),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_RDI),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R8),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R9),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R10),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R11),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R12),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R13),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R14),
            //          intrinsic.tls_reg(syscall::TLS_OFFSET_R15),
            //          m_guest_vmcb->rsp,
            //          m_guest_vmcb->rip});
            // }

            /// TODO:
            /// - Add check logic to if an entry failure occurs and output
            ///   what the error was and why.
            ///

            return bsl::safe_uintmax::failure();
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
        advance_ip(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
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
        clear(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
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
        dump(tls_t &tls, intrinsic_t &intrinsic) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            // clang-format off

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

            bsl::discard(intrinsic);
            bsl::discard(tls);

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+----------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
