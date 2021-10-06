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

#ifndef MOCKS_VS_POOL_T_HPP
#define MOCKS_VS_POOL_T_HPP

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>
#include <vs_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Defines the microkernel's vs_pool_t
    ///
    class vs_pool_t final
    {
        /// @brief stores the pool of vs_t objects
        bsl::array<vs_t, HYPERVISOR_MAX_VSS.get()> m_pool{};

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) noexcept -> vs_t *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

        /// <!-- description -->
        ///   @brief Returns the vs_t associated with the provided vsid.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to get
        ///   @return Returns the vs_t associated with the provided vsid.
        ///
        [[nodiscard]] constexpr auto
        get_vs(bsl::safe_u16 const &vsid) const noexcept -> vs_t const *
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid < bsl::to_u16(m_pool.size()));
            return m_pool.at_if(bsl::to_idx(vsid));
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_pool_t
        ///
        constexpr void
        initialize() noexcept
        {
            for (bsl::safe_idx mut_i{}; mut_i < m_pool.size(); ++mut_i) {
                m_pool.at_if(mut_i)->initialize(bsl::to_u16(mut_i));
            }
        }

        /// <!-- description -->
        ///   @brief Release the vs_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t const &tls, page_pool_t const &page_pool) noexcept
        {
            for (auto &mut_vs : m_pool) {
                mut_vs.release(tls, page_pool);
            }
        }

        /// <!-- description -->
        ///   @brief Allocates a vs from the vs_pool_t.
        ///
        /// <!-- inputs/outputs -->
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
            for (auto &mut_vs : m_pool) {
                if (mut_vs.is_deallocated()) {
                    return mut_vs.allocate(tls, page_pool, intrinsic, vmid, vpid, ppid);
                }

                bsl::touch();
            }

            bsl::error() << "vs_pool_t out of vss\n" << bsl::here();
            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns a vs previously allocated using the allocate
        ///     function to the vs_pool_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vsid the ID of the vs_t to deallocate
        ///
        constexpr void
        deallocate(
            tls_t const &tls, page_pool_t const &page_pool, bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->deallocate(tls, page_pool);
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is deallocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is allocated,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_allocated();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t as active
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to set as active
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->set_active(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vs_t as inactive
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to set as inactive
        ///
        constexpr void
        set_inactive(
            tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            if (bsl::unlikely(vsid == syscall::BF_INVALID_ID)) {
                return;
            }

            this->get_vs(vsid)->set_inactive(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vs_t is active on.
        ///     If the vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the PP the requested vs_t is active on.
        ///     If the vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->is_active();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vs_t is active on the
        ///     current PP, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns true if the requested vs_t is active on the
        ///     current PP, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls, bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return this->get_vs(vsid)->is_active_on_this_pp(tls);
        }

        /// <!-- description -->
        ///   @brief Migrates the requested vs_t from one PP to another
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP to migrate to
        ///   @param vsid the ID of the vs_t to migrate
        ///
        constexpr void
        migrate(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &ppid,
            bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->migrate(tls, intrinsic, ppid);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM the requested vs_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the VM the requested vs_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vm(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_vm();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP the requested vs_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the VP the requested vs_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vp(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_vp();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vs_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the vs_t to query
        ///   @return Returns the ID of the PP the requested vs_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_pp(bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_u16
        {
            return this->get_vs(vsid)->assigned_pp();
        }

        /// <!-- description -->
        ///   @brief If the requested VM is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID fo the VM to query
        ///   @return If the requested VM is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        vs_assigned_to_vm(bsl::safe_u16 const &vmid) const noexcept -> bsl::safe_u16
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);

            for (auto const &vs : m_pool) {
                if (vs.assigned_vm() == vmid) {
                    return vs.id();
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief If the requested PP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the ID fo the PP to query
        ///   @return If the requested PP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        vs_assigned_to_pp(bsl::safe_u16 const &ppid) const noexcept -> bsl::safe_u16
        {
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            for (auto const &vs : m_pool) {
                if (vs.assigned_pp() == ppid) {
                    return vs.id();
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief If the requested VP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID fo the VP to query
        ///   @return If the requested VP is assigned to a vs_t in the pool,
        ///     the ID of the first vs_t found is returned. Otherwise, this
        ///     function will return bsl::safe_u16::failure()
        ///
        [[nodiscard]] constexpr auto
        vs_assigned_to_vp(bsl::safe_u16 const &vpid) const noexcept -> bsl::safe_u16
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);

            for (auto const &vs : m_pool) {
                if (vs.assigned_vp() == vpid) {
                    return vs.id();
                }

                bsl::touch();
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the requested vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param state the state to set the vs_t to
        ///   @param vsid the ID of the vs_t to save the state to
        ///
        static constexpr void
        state_save_to_vs(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t const *const state,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(state);
            bsl::discard(vsid);
        }

        /// <!-- description -->
        ///   @brief Stores the requested vs_t state in the provided state save
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param state the state save to store the vs_t state to
        ///   @param vsid the ID of the vs_t to get the state from
        ///
        static constexpr void
        vs_to_state_save(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t const *const state,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(state);
            bsl::discard(vsid);
        }

        /// <!-- description -->
        ///   @brief Reads a field from the requested vs_t given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to read from the vs_t
        ///   @param vsid the ID of the vs_t to read from
        ///   @return Returns the value of the requested field from the
        ///     vs_t or bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        read(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_u16 const &vsid) const noexcept -> bsl::safe_umx
        {
            return this->get_vs(vsid)->read(tls, intrinsic, reg);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the requested vs_t given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to write to the vs_t
        ///   @param val the value to write to the vs_t
        ///   @param vsid the ID of the vs_t to write to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_umx const &val,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            return this->get_vs(vsid)->write(tls, intrinsic, reg, val);
        }

        /// <!-- description -->
        ///   @brief Runs the vs_t. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param mut_log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t const &tls, intrinsic_t const &intrinsic, vmexit_log_t &mut_log) noexcept
            -> bsl::safe_umx
        {
            auto const vsid{bsl::to_u16(tls.active_vsid)};
            return this->get_vs(vsid)->run(tls, intrinsic, mut_log);
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to advance the IP of
        ///
        static constexpr void
        advance_ip(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vsid);
        }

        /// <!-- description -->
        ///   @brief Clears the vs_t's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to clear
        ///
        constexpr void
        clear(tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            this->get_vs(vsid)->clear(tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Loops through every VS, and flushes any TLB entries
        ///     associated with a VS that is assigned to the provided VM
        ///     and the current PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vmid the ID of the vs_t to flush
        ///
        static constexpr void
        tlb_flush(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vmid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
        }

        /// <!-- description -->
        ///   @brief Given a GLA, invalidates any TLB entries on this PP
        ///     associated with this VS for the provided GLA.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param gla the guest linear address to invalidate
        ///   @param vsid the ID of the vs_t to flush
        ///
        static constexpr void
        tlb_flush(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            bsl::safe_u64 const &gla,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(gla);
            bsl::discard(vsid);
        }

        /// <!-- description -->
        ///   @brief Dumps the requested vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the vs_t to dump
        ///
        static constexpr void
        dump(tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vsid);
        }
    };
}

#endif
