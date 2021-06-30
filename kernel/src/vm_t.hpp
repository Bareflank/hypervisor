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

#ifndef VM_T_HPP
#define VM_T_HPP

#include "lock_guard_t.hpp"
#include "spinlock_t.hpp"

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    /// @class mk::vm_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VM. Unlike a VP or
    ///     VPS, a VM can be run on any PP at any time and in any combination.
    ///     For example, you could have PPs 0-2 running VM1 and PPs 3-4
    ///     running VM2. A VM is not dedicated to any specific PP. A VP and
    ///     VPS are different. They are assigned to a specific VM and a
    ///     specific PP (well, a VP is assigned to a VM and a PP, and a VPS
    ///     is assigned to a VP and PP, and so there for a VPS is indirectly
    ///     assigned to a VM since it's parent VP is). VM assignment for a
    ///     VP and VPS cannot change. The only way to change it is to
    ///     deallocate the VP or VPS and they allocate it later as a new
    ///     resource. PP reassignment is done through migration. Basically,
    ///     the VP is migrated to a new PP, and then any time you try to
    ///     run a VPS, if the PP doesn't match the VP's PP, it is migrated
    ///     at that time, which is used to not only prevent the microkernel
    ///     from performing migration on VPSs that don't need it, but it
    ///     also ensures that the VPS is cleared and loaded on the PP that
    ///     it is being migrated to, which is a requirement for Intel. In
    ///     otherwords on Intel, you have to clear the VPS and then load the
    ///     VPS on the PP you plan to run VMLaunch on, which means that
    ///     migration has to occur on the PP you plan to use.
    ///
    ///     So based on the above, we have to track which PP the VM is active
    ///     on as it can be active on a lot of PPs, where as with a VP and
    ///     VPS, we only have to track if it is active or not since it can
    ///     only be active on one PP at a time.
    ///
    class vm_t final
    {
        /// @brief stores the ID associated with this vm_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vm_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores whether or not this vm_t is active.
        bsl::array<bool, HYPERVISOR_MAX_PPS.get()> m_active{};
        /// @brief safe guards operations on the pool.
        mutable spinlock_t m_lock;

    public:
        /// <!-- description -->
        ///   @brief Initializes this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param i the ID for this vm_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(tls_t &tls, bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);

            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vm_t already initialized\n" << bsl::here();
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
        ///   @brief Release the vm_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the extension pool to use
        ///   @param vp_pool the VP pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(
            tls_t &tls, page_pool_t &page_pool, ext_pool_t &ext_pool, vp_pool_t &vp_pool) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            lock_guard_t lock{tls, m_lock};

            if (syscall::BF_ROOT_VMID == m_id) {
                return bsl::errc_success;
            }

            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            auto const vpid{vp_pool.is_assigned_to_vm(tls, m_id)};
            if (bsl::unlikely(vpid)) {
                bsl::error() << "vp "                     // --
                             << bsl::hex(vpid)            // --
                             << " is assigned to vm "     // --
                             << bsl::hex(m_id)            // --
                             << " and therefore vm "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            auto const active_ppid{this->is_active(tls)};
            if (bsl::unlikely(active_ppid)) {
                bsl::error() << "vm "                     // --
                             << bsl::hex(m_id)            // --
                             << " is active on pp "       // --
                             << bsl::hex(active_ppid)     // --
                             << " and therefore vm "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            ret = ext_pool.signal_vm_destroyed(tls, page_pool, m_id);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vm_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param ext_pool the extension pool to use
        ///   @return Returns ID of the newly allocated vm
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &tls, page_pool_t &page_pool, ext_pool_t &ext_pool) noexcept
            -> bsl::safe_uint16
        {
            bsl::errc_type ret{};
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vm "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vm "                                            // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::safe_uint16::failure();
            }

            tls.state_reversal_required = true;
            tls.log_vmid = m_id.get();

            ret = ext_pool.signal_vm_created(tls, page_pool, m_id);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_allocated = allocated_status_t::allocated;
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page_pool_t to use
        ///   @param vp_pool the VP pool to use
        ///   @param ext_pool the extension pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(
            tls_t &tls, page_pool_t &page_pool, vp_pool_t &vp_pool, ext_pool_t &ext_pool) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_id == syscall::BF_ROOT_VMID)) {
                bsl::error() << "vm "                                          // --
                             << bsl::hex(m_id)                                 // --
                             << " is the root VM which cannot be destroyed"    // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vm "                                     // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vm "                                                // --
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

            auto const vpid{vp_pool.is_assigned_to_vm(tls, m_id)};
            if (bsl::unlikely(vpid)) {
                bsl::error() << "vp "                     // --
                             << bsl::hex(vpid)            // --
                             << " is assigned to vm "     // --
                             << bsl::hex(m_id)            // --
                             << " and therefore vm "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            auto const active_ppid{this->is_active(tls)};
            if (bsl::unlikely(active_ppid)) {
                bsl::error() << "vm "                     // --
                             << bsl::hex(m_id)            // --
                             << " is active on pp "       // --
                             << bsl::hex(active_ppid)     // --
                             << " and therefore vm "      // --
                             << bsl::hex(m_id)            // --
                             << " cannot be destroyed"    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return bsl::errc_failure;
            }

            ret = ext_pool.signal_vm_destroyed(tls, page_pool, m_id);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_allocated = allocated_status_t::deallocated;

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t's status as zombified, meaning it is no
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

            if (bsl::unlikely(m_id == syscall::BF_ROOT_VMID)) {
                bsl::alert() << "attempt to zombify vm "                            // --
                             << bsl::hex(m_id)                                      // --
                             << " was ignored as the root VM cannot be a zombie"    // --
                             << bsl::endl;                                          // --
            }
            else {
                bsl::alert() << "vm "                    // --
                             << bsl::hex(m_id)           // --
                             << " has been zombified"    // --
                             << bsl::endl;               // --

                m_allocated = allocated_status_t::zombie;
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vm_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &tls) noexcept -> bsl::errc_type
        {
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vm "                                              // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vmid)) {
                bsl::error() << "vm "                        // --
                             << bsl::hex(tls.active_vmid)    // --
                             << " is still active on pp "    // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_precondition;
            }

            auto *const active{m_active.at_if(bsl::to_umax(tls.ppid))};
            if (bsl::unlikely_assert(nullptr == active)) {
                bsl::error() << "tls.ppid "                                   // --
                             << bsl::hex(m_id)                                // --
                             << " is greater than the HYPERVISOR_MAX_PPS "    // --
                             << bsl::hex(HYPERVISOR_MAX_PPS)                  // --
                             << bsl::endl                                     // --
                             << bsl::here();                                  // --

                return bsl::errc_index_out_of_bounds;
            }

            if (bsl::unlikely_assert(*active)) {
                bsl::error() << "vm "                                 // --
                             << bsl::hex(m_id)                        // --
                             << " is already the active vm on pp "    // --
                             << bsl::hex(tls.ppid)                    // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return bsl::errc_precondition;
            }

            tls.active_vmid = m_id.get();
            *active = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vm_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &tls) noexcept -> bsl::errc_type
        {
            lock_guard_t lock{tls, m_lock};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vm_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::deallocated)) {
                bsl::error() << "vm "                                              // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vmid)) {
                bsl::error() << "vm "                      // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.active_vmid != m_id)) {
                bsl::error() << "vm "                        // --
                             << bsl::hex(tls.active_vmid)    // --
                             << " is still active on pp "    // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::errc_precondition;
            }

            auto *const active{m_active.at_if(bsl::to_umax(tls.ppid))};
            if (bsl::unlikely_assert(nullptr == active)) {
                bsl::error() << "tls.ppid "                                   // --
                             << bsl::hex(m_id)                                // --
                             << " is greater than the HYPERVISOR_MAX_PPS "    // --
                             << bsl::hex(HYPERVISOR_MAX_PPS)                  // --
                             << bsl::endl                                     // --
                             << bsl::here();                                  // --

                return bsl::errc_index_out_of_bounds;
            }

            if (bsl::unlikely_assert(!*active)) {
                bsl::error() << "vm "                      // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            tls.active_vmid = syscall::BF_INVALID_ID.get();
            *active = false;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the first PP identified that this vm_t
        ///     is still active on. If the vm_t is inactive, this function
        ///     returns bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the first PP identified that this vm_t
        ///     is still active on. If the vm_t is inactive, this function
        ///     returns bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t &tls) const noexcept -> bsl::safe_uint16
        {
            auto const online_pps{m_active.size().min(bsl::to_umax(tls.online_pps))};

            for (bsl::safe_uintmax i{}; i < online_pps; ++i) {
                if (*m_active.at_if(i)) {
                    return bsl::to_u16(i);
                }

                bsl::touch();
            }

            return bsl::safe_uint16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vm_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t &tls) const noexcept -> bool
        {
            auto const *const active{m_active.at_if(bsl::to_umax(tls.ppid))};
            if (bsl::unlikely(nullptr == active)) {
                bsl::error() << "tls.ppid "                                   // --
                             << bsl::hex(m_id)                                // --
                             << " is greater than the HYPERVISOR_MAX_PPS "    // --
                             << bsl::hex(HYPERVISOR_MAX_PPS)                  // --
                             << bsl::endl                                     // --
                             << bsl::here();                                  // --

                return false;
            }

            return *active;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
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

            bsl::print() << bsl::mag << "vm [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^12s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^6s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Allocated
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "allocated "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_allocated()) {
                bsl::print() << bsl::grn << bsl::fmt{"^6s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^6s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Active
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<12s", "active "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_active(tls)) {
                bsl::print() << bsl::grn << bsl::fmt{"^6s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^6s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+---------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
