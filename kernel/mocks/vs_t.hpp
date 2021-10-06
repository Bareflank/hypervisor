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

#ifndef MOCKS_VS_T_HPP
#define MOCKS_VS_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ensures.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unordered_map.hpp>

namespace mk
{
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_VS_FAIL_READ{-60001};
    /// @brief defines a unit testing specific error code
    constexpr bsl::errc_type UNIT_TEST_VS_FAIL_WRITE{-60002};

    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VS.
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vs_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vs_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the ID of the VM this vs_t is assigned to
        bsl::safe_u16 m_assigned_vmid{};
        /// @brief stores the ID of the VP this vs_t is assigned to
        bsl::safe_u16 m_assigned_vpid{};
        /// @brief stores the ID of the PP this vs_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the ID of the PP this vs_t is active on
        bsl::safe_u16 m_active_ppid{};

        /// @brief stores the ID of the PP this vs_t is active on
        bsl::unordered_map<syscall::bf_reg_t, bsl::safe_u64> m_regs{};

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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t const &tls, page_pool_t const &page_pool) noexcept
        {
            this->deallocate(tls, page_pool);
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
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid The ID of the VM to assign the newly allocated vs_t to
        ///   @param vpid The ID of the VP to assign the newly allocated vs_t to
        ///   @param ppid The ID of the PP to assign the newly allocated vs_t to
        ///   @return Returns ID of the newly allocated vs_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t const &tls,
            page_pool_t const &page_pool,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(page_pool);

            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            m_assigned_vmid = ~vmid;
            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        deallocate(tls_t const &tls, page_pool_t const &page_pool) noexcept
        {
            bsl::discard(tls);
            bsl::discard(page_pool);

            bsl::expects(this->is_active().is_invalid());

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_assigned_vmid = {};
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
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

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
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->id() == mut_tls.active_vsid);

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
        ///
        constexpr void
        migrate(tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &ppid) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            this->clear(tls, intrinsic);
            m_assigned_ppid = ~ppid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM this vs_t is assigned to. If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
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
        ///   @param intrinsic the intrinsic_t to use
        ///   @param state the state to set the vs_t to
        ///
        constexpr void
        state_save_to_vs(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t const *const state) noexcept
        {
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(nullptr != state);
        }

        /// <!-- description -->
        ///   @brief Stores the vs_t state in the provided state save
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param state the state save to store the vs_t state to
        ///
        constexpr void
        vs_to_state_save(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t const *const state) const noexcept
        {
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(nullptr != state);
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
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());

            if (UNIT_TEST_VS_FAIL_READ == tls.test_ret) {
                return bsl::safe_umx::failure();
            }

            if (reg == syscall::bf_reg_t::bf_reg_t_unsupported) {
                return bsl::safe_umx::failure();
            }

            if (reg == syscall::bf_reg_t::bf_reg_t_invalid) {
                return bsl::safe_umx::failure();
            }

            return m_regs.at(reg);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the vs_t given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to write to the vs_t
        ///   @param val the value to write to the vs_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_umx const &val) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());
            bsl::expects(val.is_valid_and_checked());

            if (UNIT_TEST_VS_FAIL_WRITE == tls.test_ret) {
                return bsl::errc_failure;
            }

            if (reg == syscall::bf_reg_t::bf_reg_t_unsupported) {
                return bsl::errc_failure;
            }

            if (reg == syscall::bf_reg_t::bf_reg_t_invalid) {
                return bsl::errc_failure;
            }

            m_regs.at(reg) = val;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Runs the vs_t. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t const &tls, intrinsic_t const &intrinsic, vmexit_log_t const &log) noexcept
            -> bsl::safe_umx
        {
            bsl::discard(intrinsic);
            bsl::discard(log);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());

            if (tls.test_ret) {
                if (bsl::safe_u64::magic_0() != tls.first_launch_succeeded) {
                    return bsl::safe_umx::failure();
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            return {};
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
            bsl::expects(tls.ppid == this->assigned_pp());
        }

        /// <!-- description -->
        ///   @brief Clears the vs_t's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        clear(tls_t const &tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(this->is_active().is_invalid());
        }

        /// <!-- description -->
        ///   @brief Flushes any TLB entries associated with this VS on
        ///     the current PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        tlb_flush(tls_t const &tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(intrinsic);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());
        }

        /// <!-- description -->
        ///   @brief Given a GLA, invalidates any TLB entries on this PP
        ///     associated with this VS for the provided GLA.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param gla the guest linear address to invalidate
        ///
        constexpr void
        tlb_flush(tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u64 const &gla) noexcept
        {
            bsl::discard(intrinsic);
            bsl::discard(gla);

            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(tls.ppid == this->assigned_pp());
        }

        /// <!-- description -->
        ///   @brief Dumps the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        static constexpr void
        dump(tls_t const &tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
        }
    };
}

#endif
