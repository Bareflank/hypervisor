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

#ifndef VP_T_HPP
#define VP_T_HPP

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <tls_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    class vm_pool_t;

    /// @class mk::vp_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VP
    ///
    class vp_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores the ID of the VM this vp_t is assigned to
        bsl::safe_uint16 m_assigned_vmid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is active on
        bsl::safe_uint16 m_active_ppid{bsl::safe_uint16::failure()};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param i the ID for this vp_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &tls, bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vp_t already initialized\n" << bsl::here();
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
        ///   @brief Release the vp_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &tls, vps_pool_t &vps_pool) noexcept -> bsl::errc_type
        {
            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            auto const vpsid{vps_pool.is_assigned_to_vp(tls, m_id)};
            if (bsl::unlikely(vpsid)) {
                bsl::error() << "vps "                    // --
                             << bsl::hex(vpsid)           // --
                             << " is assigned to vp "     // --
                             << bsl::hex(m_id)            // --
                             << " and therefore vp "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

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

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vmid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vp_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &tls, bsl::safe_uint16 const &vmid, bsl::safe_uint16 const &ppid) noexcept
            -> bsl::safe_uint16
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == vmid)) {
                bsl::error() << "vm "                                              // --
                             << bsl::hex(vmid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uint16::failure();
            }

            // if (bsl::unlikely(vm_pool.is_zombie(tls, vmid))) {
            //     bsl::error() << "vm "                                               // --
            //                  << bsl::hex(vmid)                                      // --
            //                  << " is a zombie and a vp cannot be assigned to it"    // --
            //                  << bsl::endl                                           // --
            //                  << bsl::here();                                        // --

            //     return bsl::safe_uint16::failure();
            // }

            // if (bsl::unlikely(vm_pool.is_deallocated(tls, vmid))) {
            //     bsl::error() << "vm "                                                        // --
            //                  << bsl::hex(vmid)                                               // --
            //                  << " has not been created and a vp cannot be assigned to it"    // --
            //                  << bsl::endl                                                    // --
            //                  << bsl::here();                                                 // --

            //     return bsl::safe_uint16::failure();
            // }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                              // --
                             << bsl::hex(ppid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(!(ppid < tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(tls.online_pps)                               // --
                             << " and a vp cannot be assigned to it"                   // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vp "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vp "                                            // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::safe_uint16::failure();
            }

            tls.state_reversal_required = true;
            tls.log_vpid = m_id.get();

            m_assigned_vmid = vmid;
            m_assigned_ppid = ppid;
            m_allocated = allocated_status_t::allocated;

            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &tls, vps_pool_t &vps_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vp "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vp "                                                // --
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

            auto const vpsid{vps_pool.is_assigned_to_vp(tls, m_id)};
            if (bsl::unlikely(vpsid)) {
                bsl::error() << "vps "                    // --
                             << bsl::hex(vpsid)           // --
                             << " is assigned to vp "     // --
                             << bsl::hex(m_id)            // --
                             << " and therefore vp "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

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

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vmid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t's status as zombified, meaning it is no
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

            bsl::alert() << "vp "                    // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
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
        ///   @brief Returns true if this vp_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vp_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &tls) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vp "                                              // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.active_vmid != m_assigned_vmid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to vm "                  // --
                             << bsl::hex(m_assigned_vmid)              // --
                             << " and cannot be activated with vm "    // --
                             << bsl::hex(tls.active_vmid)              // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                // --
                             << bsl::hex(m_id)                       // --
                             << " is assigned to pp "                // --
                             << bsl::hex(m_assigned_ppid)            // --
                             << " and cannot be activated on pp "    // --
                             << bsl::hex(tls.ppid)                   // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vpid)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(tls.active_vpid)    // --
                             << " is still active on pp "    // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vp "                                 // --
                             << bsl::hex(m_id)                        // --
                             << " is already the active vp on pp "    // --
                             << bsl::hex(m_active_ppid)               // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return bsl::errc_precondition;
            }

            tls.active_vpid = m_id.get();
            m_active_ppid = tls.ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vp_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &tls) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::deallocated)) {
                bsl::error() << "vp "                                              // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vpid)) {
                bsl::error() << "vp "                      // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.active_vpid != m_id)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(tls.active_vpid)    // --
                             << " is still active on pp "    // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!m_active_ppid)) {
                bsl::error() << "vp "                // --
                             << bsl::hex(m_id)       // --
                             << " is not active "    // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.ppid != m_active_ppid)) {
                bsl::error() << "vp "                      // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            tls.active_vpid = syscall::BF_INVALID_ID.get();
            m_active_ppid = bsl::safe_uint16::failure();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP that this vp_t is still active
        ///     on. If the vp_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the PP that this vp_t is still active
        ///     on. If the vp_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t &tls) const noexcept -> bsl::safe_uint16
        {
            bsl::discard(tls);
            return m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vp_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vp_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t &tls) const noexcept -> bool
        {
            return tls.ppid == m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Migrates this vp_t from one PP to another. If this calls
        ///     completes successfully, the VPS's assigned PP will not
        ///     match the VP's assigned PP. Future calls to the run ABI
        ///     will be able to detect this an migrate mismatched VPSs to
        ///     the proper PP as needed. Note that since the VP doesn't control
        ///     any hardware state, all we have to do here is set which PP
        ///     this VP is allowed to execute on. The VPS is what actually
        ///     needs to be migrated, and that will not happen until a call
        ///     to the run ABIs made. Once the run ABI detects a mismatch with
        ///     the VPS and it's assigned VP, it will be migrated then.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(tls_t &tls, bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vp_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vp "                                              // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                              // --
                             << bsl::hex(ppid)                                     // --
                             << " is invalid and a vp cannot be assigned to it"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(!(ppid < tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(tls.online_pps)                               // --
                             << " and a vp cannot be assigned to it"                   // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(ppid == m_assigned_ppid)) {
                bsl::error() << "vp "                              // --
                             << bsl::hex(m_id)                     // --
                             << " is already assigned to a pp "    // --
                             << bsl::hex(m_assigned_ppid)          // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(m_id)               // --
                             << " is still active on pp "    // --
                             << bsl::hex(m_active_ppid)      // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_precondition;
            }

            m_assigned_ppid = ppid;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM this vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM this vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vm() const noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(syscall::BF_INVALID_ID == m_assigned_vmid)) {
                return bsl::safe_uint16::failure();
            }

            return m_assigned_vmid;
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
        ///   @brief Dumps the vp_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        dump(tls_t &tls) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            if (bsl::unlikely(!m_id)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            bsl::print() << bsl::mag << "vp [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+--------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^12s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^11s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+--------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Allocated
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "allocated "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_allocated()) {
                bsl::print() << bsl::grn << bsl::fmt{"^11s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^11s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Active
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "active "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_active(tls)) {
                bsl::print() << bsl::grn << bsl::fmt{"^11s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^11s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned VM
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "assigned vm "};
            bsl::print() << bsl::ylw << "| ";
            if (syscall::BF_INVALID_ID != m_assigned_vmid) {
                bsl::print() << bsl::grn << "  " << bsl::hex(m_assigned_vmid) << "   ";
            }
            else {
                bsl::print() << bsl::red << "  " << bsl::hex(m_assigned_vmid) << "   ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned PP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "assigned pp "};
            bsl::print() << bsl::ylw << "| ";
            if (syscall::BF_INVALID_ID != m_assigned_ppid) {
                bsl::print() << bsl::grn << "  " << bsl::hex(m_assigned_ppid) << "   ";
            }
            else {
                bsl::print() << bsl::red << "  " << bsl::hex(m_assigned_ppid) << "   ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+--------------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
