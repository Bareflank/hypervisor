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

#ifndef VPS_POOL_T_HPP
#define VPS_POOL_T_HPP

#include "lock_guard_t.hpp"
#include "spinlock_t.hpp"

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>
#include <vps_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally_assert.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    class vp_pool_t;

    /// @class mk::vps_pool_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's VPS pool
    ///
    class vps_pool_t final
    {
        /// @brief stores the pool of vps_ts
        bsl::array<vps_t, HYPERVISOR_MAX_VPSS.get()> m_pool{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_pool_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> bsl::errc_type
        {
            bsl::finally_assert mut_release_on_error{
                [this, &mut_tls, &mut_page_pool]() noexcept -> void {
                    auto const ret{this->release(mut_tls, mut_page_pool)};
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return;
                    }

                    bsl::touch();
                }};

            for (auto const vps : m_pool) {
                auto const ret{vps.data->initialize(bsl::to_u16(vps.index))};
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            mut_release_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vps_pool_t. Note that if this function fails,
        ///     the microkernel is left in a corrupt state and all use of the
        ///     vps_pool_t after calling this function will results in UB.
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
            for (auto const vps : m_pool) {
                auto const ret{vps.data->release(mut_tls, mut_page_pool)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Allocates a vps from the vps pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param vpid The ID of the VP to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vps
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            intrinsic_t &mut_intrinsic,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            lock_guard_t mut_lock{mut_tls, m_lock};

            vps_t *pmut_mut_vps{};
            for (auto const elem : m_pool) {
                if (elem.data->is_deallocated()) {
                    pmut_mut_vps = elem.data;
                    break;
                }

                bsl::touch();
            }

            if (bsl::unlikely(nullptr == pmut_mut_vps)) {
                bsl::error() << "vps pool out of vpss\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            return pmut_mut_vps->allocate(mut_tls, mut_intrinsic, mut_page_pool, vpid, ppid);
        }

        /// <!-- description -->
        ///   @brief Returns a vps previously allocated using the allocate
        ///     function to the vps pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @param vpsid the ID of the vps to deallocate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            tls_t &mut_tls, page_pool_t &mut_page_pool, bsl::safe_uint16 const &vpsid) noexcept
            -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_index_out_of_bounds;
            }

            return pmut_vps->deallocate(mut_tls, mut_page_pool);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vps_t's status as zombified, meaning
        ///     it is no longer usable.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the vps_t to set as a zombie
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        zombify(bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_index_out_of_bounds;
            }

            pmut_vps->zombify();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is deallocated, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     deallocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns true if the requested vps_t is deallocated, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     deallocated.
        ///
        [[nodiscard]] constexpr auto
        is_deallocated(tls_t const &tls, bsl::safe_uint16 const &vpsid) const noexcept -> bool
        {
            bsl::discard(tls);

            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_deallocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is allocated, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     allocated.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns true if the requested vps_t is allocated, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     allocated.
        ///
        [[nodiscard]] constexpr auto
        is_allocated(tls_t const &tls, bsl::safe_uint16 const &vpsid) const noexcept -> bool
        {
            bsl::discard(tls);

            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_allocated();
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is a zombie, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     a zombie.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns true if the requested vps_t is a zombie, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     a zombie.
        ///
        [[nodiscard]] constexpr auto
        is_zombie(tls_t const &tls, bsl::safe_uint16 const &vpsid) const noexcept -> bool
        {
            bsl::discard(tls);

            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_zombie();
        }

        /// <!-- description -->
        ///   @brief If a vps_t in the pool is assigned to the requested VP,
        ///     the ID of the first vps_t found is returned. Otherwise, this
        ///     function will return bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpid the ID fo the VP to query
        ///   @return If a vps_t in the pool is assigned to the requested VP,
        ///     the ID of the first vps_t found is returned. Otherwise, this
        ///     function will return bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_assigned_to_vp(tls_t const &tls, bsl::safe_uint16 const &vpid) const noexcept
            -> bsl::safe_uint16
        {
            bsl::discard(tls);

            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            for (auto const elem : m_pool) {
                if (elem.data->assigned_vp() == vpid) {
                    return elem.data->id();
                }

                bsl::touch();
            }

            return bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Sets the requested vps_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param vpsid the ID of the vps_t to set as active
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(
            tls_t &mut_tls, intrinsic_t &mut_intrinsic, bsl::safe_uint16 const &vpsid) noexcept
            -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->set_active(mut_tls, mut_intrinsic);
        }

        /// <!-- description -->
        ///   @brief Sets the requested vps_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the vps_t to set as inactive
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(
            tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_uint16 const &vpsid) noexcept
            -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->set_inactive(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Returns true if the requested vps_t is active, false
        ///     if the provided VPID is invalid, or if the vps_t is not
        ///     active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns the ID of the PP that the requested vps_t is
        ///     still active on. If the vps_t is inactive, this function
        ///     returns bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t const &tls, bsl::safe_uint16 const &vpsid) noexcept -> bsl::safe_uint16
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::safe_uint16::failure();
            }

            return vps->is_active(tls);
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is active on the current PP,
        ///     false if the provided ID is invalid, or if the vps_t is not
        ///     active on the current PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns true if this vps_t is active on the current PP,
        ///     false if the provided ID is invalid, or if the vps_t is not
        ///     active on the current PP.
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t const &tls, bsl::safe_uint16 const &vpsid) noexcept -> bool
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return false;
            }

            return vps->is_active_on_current_pp(tls);
        }

        /// <!-- description -->
        ///   @brief Migrates the requested vps_t from one PP to another.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the vps_t to migrate
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(
            tls_t const &tls,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpsid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->migrate(tls, intrinsic, ppid);
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP the requested vps_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns the ID of the VP the requested vps_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vp(bsl::safe_uint16 const &vpsid) const noexcept -> bsl::safe_uint16
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::safe_uint16::failure();
            }

            return vps->assigned_vp();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP the requested vps_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid the ID of the vps_t to query
        ///   @return Returns the ID of the PP the requested vps_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_pp(bsl::safe_uint16 const &vpsid) const noexcept -> bsl::safe_uint16
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::safe_uint16::failure();
            }

            return vps->assigned_pp();
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the requested VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to set the state to
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            bsl::safe_uint16 const &vpsid,
            loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->state_save_to_vps(mut_tls, mut_intrinsic, state);
        }

        /// <!-- description -->
        ///   @brief Stores the requested VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to set the state to
        ///   @param mut_state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vps_to_state_save(
            tls_t &mut_tls,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpsid,
            loader::state_save_t &mut_state) const noexcept -> bsl::errc_type
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return vps->vps_to_state_save(mut_tls, intrinsic, mut_state);
        }

        /// <!-- description -->
        ///   @brief Reads a field from the requested VPS given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to read from
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     requested VPS or bsl::safe_uintmax::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        read(
            tls_t &mut_tls,
            intrinsic_t const &intrinsic,
            bsl::safe_uint16 const &vpsid,
            syscall::bf_reg_t const reg) const noexcept -> bsl::safe_uintmax
        {
            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::safe_uintmax::failure();
            }

            return vps->read(mut_tls, intrinsic, reg);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the requested VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to write to
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param value the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            bsl::safe_uint16 const &vpsid,
            syscall::bf_reg_t const reg,
            bsl::safe_uintmax const &value) noexcept -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->write(mut_tls, mut_intrinsic, reg, value);
        }

        /// <!-- description -->
        ///   @brief Runs the requested VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param mut_log the VMExit log to use
        ///   @param vpsid the ID of the VPS to run
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_uintmax::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            vmexit_log_t &mut_log,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::safe_uintmax
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::safe_uintmax::failure();
            }

            return pmut_vps->run(mut_tls, mut_intrinsic, mut_log);
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the requested VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to advance the IP for
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        advance_ip(
            tls_t &mut_tls, intrinsic_t &mut_intrinsic, bsl::safe_uint16 const &vpsid) noexcept
            -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->advance_ip(mut_tls, mut_intrinsic);
        }

        /// <!-- description -->
        ///   @brief Clears the requested VPS's internal cache. Note that this
        ///     is a hardware specific function and doesn't change the actual
        ///     values stored in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to clear
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_uint16 const &vpsid) noexcept
            -> bsl::errc_type
        {
            auto *const pmut_vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == pmut_vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return bsl::errc_failure;
            }

            return pmut_vps->clear(mut_tls, intrinsic);
        }

        /// <!-- description -->
        ///   @brief Dumps the requested VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param vpsid the ID of the VPS to dump
        ///
        constexpr void
        dump(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_uint16 const &vpsid)
            const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            auto const *const vps{m_pool.at_if(bsl::to_umax(vpsid))};
            if (bsl::unlikely(nullptr == vps)) {
                bsl::error()
                    << "vpsid "                                                              // --
                    << bsl::hex(vpsid)                                                       // --
                    << " is invalid or greater than or equal to the HYPERVISOR_MAX_VPSS "    // --
                    << bsl::hex(HYPERVISOR_MAX_VPSS)                                         // --
                    << bsl::endl                                                             // --
                    << bsl::here();                                                          // --

                return;
            }

            vps->dump(mut_tls, intrinsic);
        }
    };
}

#endif
