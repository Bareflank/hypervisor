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

#ifndef DISPATCH_SYSCALL_HELPERS_HPP
#define DISPATCH_SYSCALL_HELPERS_HPP

#include <bf_constants.hpp>
#include <bf_types.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// ------------------------------------------------------------------------
    /// Validation Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns true if a callback has already been registered by
    ///     the active ext. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param callback the callback to verify
    ///   @param name the name of the callback to verify
    ///   @return Returns true if a callback has already been registered.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    has_active_ext_registered_a_callback(
        tls_t const &tls, bsl::safe_umx const &callback, bsl::string_view const &name) noexcept
        -> bool
    {
        if (bsl::unlikely(callback.is_pos())) {
            bsl::error() << "ext "                      // --
                         << bsl::hex(tls.ext->id())     // --
                         << " already registered a "    // --
                         << name                        // --
                         << " callback"                 // --
                         << bsl::endl                   // --
                         << bsl::here();                // --

            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns true if a callback has already been registered by
    ///     any ext. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ext the registered extension
    ///   @param name the name of the callback to verify
    ///   @return Returns true if a callback has already been registered.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    has_any_ext_registered_a_callback(ext_t const *const ext, bsl::string_view const &name) noexcept
        -> bool
    {
        if (bsl::unlikely(nullptr != ext)) {
            bsl::error() << "ext "                      // --
                         << bsl::hex(ext->id())         // --
                         << " already registered a "    // --
                         << name                        // --
                         << " callback"                 // --
                         << bsl::endl                   // --
                         << bsl::here();                // --

            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register containing the version to verify
    ///   @return Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    is_version_supported(bsl::uint64 const reg) noexcept -> bool
    {
        auto const version{bsl::to_u32(reg)};
        if (bsl::unlikely(version != syscall::BF_SPEC_ID1_VAL)) {
            bsl::error() << "unsupported syscall ABI "    //--
                         << bsl::hex(version)             //--
                         << bsl::endl                     //--
                         << bsl::here();                  //--

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @return Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    verify_handle_for_current_ext(tls_t const &tls) noexcept -> bool
    {
        bool const valid{tls.ext->is_handle_valid(bsl::to_umx(tls.ext_reg0))};
        if (bsl::unlikely(!valid)) {
            bsl::error() << "invalid handle "         // --
                         << bsl::hex(tls.ext_reg0)    // --
                         << bsl::endl                 // --
                         << bsl::here();              // --

            return valid;
        }

        return valid;
    }

    /// <!-- description -->
    ///   @brief Returns true if the active extension is the extension that
    ///     registered for VMExits. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @return Returns true if the active extension is the extension that
    ///     registered for VMExits. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_the_active_ext_the_vmexit_ext(tls_t const &tls) noexcept -> bool
    {
        if (bsl::unlikely(tls.ext != tls.ext_vmexit)) {
            bsl::error() << " ext "                                  // --
                         << bsl::hex(tls.ext->id())                  // --
                         << " is not allowed to execute syscall "    // --
                         << bsl::hex(tls.ext_syscall)                //--
                         << " as it didn't register for vmexits"     // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vm_t associated with the
    ///     provided vmid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vmid the ID of the VM to query
    ///   @return Returns true if the vm_t associated with the
    ///     provided vmid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vm_destroyable(
        tls_t const &tls,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        bsl::safe_u16 const &vmid) noexcept -> bool
    {
        auto const active{vm_pool.is_active(tls, vmid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vm "                         // --
                         << bsl::hex(vmid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        auto const vpid{vp_pool.vp_assigned_to_vm(vmid)};
        if (bsl::unlikely(vpid.is_valid())) {
            bsl::error() << "vp "                          // --
                         << bsl::hex(vpid)                 // --
                         << " is still assigned to vm "    // --
                         << bsl::hex(vmid)                 // --
                         << " and cannot be destroyed"     // --
                         << bsl::endl                      // --
                         << bsl::here();                   // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vp_t associated with the
    ///     provided vpid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vpid the ID of the VP to query
    ///   @return Returns true if the vp_t associated with the
    ///     provided vpid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vp_destroyable(
        vp_pool_t const &vp_pool, vs_pool_t const &vs_pool, bsl::safe_u16 const &vpid) noexcept
        -> bool
    {
        auto const active{vp_pool.is_active(vpid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vp "                         // --
                         << bsl::hex(vpid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        auto const vsid{vs_pool.vs_assigned_to_vp(vpid)};
        if (bsl::unlikely(vsid.is_valid())) {
            bsl::error() << "vs "                          // --
                         << bsl::hex(vsid)                 // --
                         << " is still assigned to vp "    // --
                         << bsl::hex(vpid)                 // --
                         << " and cannot be destroyed"     // --
                         << bsl::endl                      // --
                         << bsl::here();                   // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vs_t associated with the
    ///     provided vsid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_destroyable(vs_pool_t const &vs_pool, bsl::safe_u16 const &vsid) noexcept -> bool
    {
        auto const active{vs_pool.is_active(vsid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vs "                         // --
                         << bsl::hex(vsid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vp_t associated with the
    ///     provided vpid is migratable to the PP associated with the
    ///     provided ppid. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vp_pool the vp_pool_t to use
    ///   @param ppid the ID of the PP to migrate the vp_t to
    ///   @param vpid the ID of the VP to query
    ///   @return Returns true if the vp_t associated with the
    ///     provided vpid is migratable to the PP associated with the
    ///     provided ppid. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vp_migratable(
        vp_pool_t const &vp_pool, bsl::safe_u16 const &ppid, bsl::safe_u16 const &vpid) noexcept
        -> bool
    {
        auto const active{vp_pool.is_active(vpid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vp "                        // --
                         << bsl::hex(vpid)               // --
                         << " is active on pp "          // --
                         << bsl::hex(active)             // --
                         << " and cannot be migrated"    // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --

            return false;
        }

        auto const assigned_ppid{vp_pool.assigned_pp(vpid)};
        if (bsl::unlikely(ppid == assigned_ppid)) {
            bsl::error() << "vp "                               // --
                         << bsl::hex(vpid)                      // --
                         << " is already assigned to pp "       // --
                         << bsl::hex(ppid)                      // --
                         << " and cannot be migrated to pp "    // --
                         << bsl::hex(ppid)                      // --
                         << " again"                            // --
                         << bsl::endl                           // --
                         << bsl::here();                        // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vp_t associated with the
    ///     provided vpid is assigned to the provided VM. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vpid the ID of the VP to query
    ///   @param vmid the ID of the VM to verify assignment with
    ///   @return Returns true if the vp_t associated with the
    ///     provided vpid is assigned to the provided VM. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vp_assigned_to_vm(
        vp_pool_t const &vp_pool, bsl::safe_u16 const &vpid, bsl::safe_u16 const &vmid) noexcept
        -> bool
    {
        auto const assigned_vmid{vp_pool.assigned_vm(vpid)};
        if (bsl::unlikely(assigned_vmid != vmid)) {
            bsl::error() << "vp "                              // --
                         << bsl::hex(vpid)                     // --
                         << " is assigned to vm "              // --
                         << bsl::hex(assigned_vmid)            // --
                         << " which is not the current vm "    // --
                         << bsl::hex(vmid)                     // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vp_t associated with the
    ///     provided vpid is assigned to the provided PP. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vpid the ID of the VP to query
    ///   @return Returns true if the vp_t associated with the
    ///     provided vpid is assigned to the provided PP. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vp_assigned_to_current_pp(
        tls_t const &tls, vp_pool_t const &vp_pool, bsl::safe_u16 const &vpid) noexcept -> bool
    {
        auto const assigned_ppid{vp_pool.assigned_pp(vpid)};
        if (bsl::unlikely(assigned_ppid != tls.ppid)) {
            bsl::error() << "vp "                              // --
                         << bsl::hex(vpid)                     // --
                         << " is assigned to pp "              // --
                         << bsl::hex(assigned_ppid)            // --
                         << " which is not the current pp "    // --
                         << bsl::hex(tls.ppid)                 // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the provided VP. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to query
    ///   @param vpid the ID of the VP to verify assignment with
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the provided VP. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_assigned_to_vp(
        vs_pool_t const &vs_pool, bsl::safe_u16 const &vsid, bsl::safe_u16 const &vpid) noexcept
        -> bool
    {
        auto const assigned_vpid{vs_pool.assigned_vp(vsid)};
        if (bsl::unlikely(assigned_vpid != vpid)) {
            bsl::error() << "vs "                              // --
                         << bsl::hex(vsid)                     // --
                         << " is assigned to vp "              // --
                         << bsl::hex(assigned_vpid)            // --
                         << " which is not the current vp "    // --
                         << bsl::hex(vpid)                     // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the provided PP. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the provided PP. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_assigned_to_current_pp(
        tls_t const &tls, vs_pool_t const &vs_pool, bsl::safe_u16 const &vsid) noexcept -> bool
    {
        auto const assigned_ppid{vs_pool.assigned_pp(vsid)};
        if (bsl::unlikely(assigned_ppid != tls.ppid)) {
            bsl::error() << "vs "                              // --
                         << bsl::hex(vsid)                     // --
                         << " is assigned to pp "              // --
                         << bsl::hex(assigned_ppid)            // --
                         << " which is not the current pp "    // --
                         << bsl::hex(tls.ppid)                 // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vs_t is a root vs_t, meaning it is a
    ///     vs_t that is allowed to contain root state. A root VS will have
    ///     the same ID as the ppid. Using the current VMID will not work
    ///     because a VMID is not present when a root VM is being set up,
    ///     and the root VM is able to create additional vs_t's for VSM
    ///     and nested virtualization support, just like guests, so the only
    ///     way to determine this is, the VSID is the same as the PPID, which
    ///     is only possible when a root VS is being created. All other VSIDs
    ///     will be larger then the PPIDs once the system has been bootstrapped
    ///     which means they will not be the same.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the provided PP. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_a_root_vs(tls_t const &tls, bsl::safe_u16 const &vsid) noexcept -> bool
    {
        if (bsl::unlikely(vsid != tls.ppid)) {
            bsl::error() << "vs "                                                 // --
                         << bsl::hex(vsid)                                        // --
                         << " is not a root vs_t and therefore cannot be used"    // --
                         << bsl::endl                                             // --
                         << bsl::here();                                          // --

            return false;
        }

        return true;
    }

    /// ------------------------------------------------------------------------
    /// Get Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Given an input register, returns a callback address on
    ///     success, or bsl::safe_umx::failure() on failure.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a callback address on
    ///     success, or bsl::safe_umx::failure() on failure.
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_callback(bsl::uint64 const reg) noexcept -> bsl::safe_umx
    {
        constexpr auto min_addr{HYPERVISOR_EXT_CODE_ADDR};
        constexpr auto max_addr{(min_addr + HYPERVISOR_EXT_CODE_SIZE).checked()};

        /// NOTE:
        /// - There is no way to know if the provided address actually points
        ///   to a function that performs the action that is supposed to be
        ///   handled, but we can at least ensure the address is in the
        ///   right range as a sanity check.
        ///

        auto const addr{bsl::to_umx(reg)};
        if (bsl::unlikely(addr < min_addr)) {
            bsl::error() << "the provided callback address "    // --
                         << bsl::hex(addr)                      // --
                         << " is out of range"                  // --
                         << bsl::endl                           // --
                         << bsl::here();                        // --

            return bsl::safe_umx::failure();
        }

        if (bsl::unlikely(addr >= max_addr)) {
            bsl::error() << "the provided callback address "    // --
                         << bsl::hex(addr)                      // --
                         << " is out of range"                  // --
                         << bsl::endl                           // --
                         << bsl::here();                        // --

            return bsl::safe_umx::failure();
        }

        return addr;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a ppid if the provided
    ///     register contains a valid ppid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param reg the register to get the ppid from.
    ///   @return Given an input register, returns a ppid if the provided
    ///     register contains a valid ppid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_ppid(tls_t const &tls, bsl::uint64 const reg) noexcept -> bsl::safe_u16
    {
        auto const ppid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
            bsl::error() << "the provided ppid "                      // --
                         << bsl::hex(ppid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(ppid) >= HYPERVISOR_MAX_PPS)) {
            bsl::error() << "the provided ppid "                      // --
                         << bsl::hex(ppid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(ppid >= tls.online_pps)) {
            bsl::error() << "the provided ppid "                   // --
                         << bsl::hex(ppid)                         // --
                         << " is not online and cannot be used"    // --
                         << bsl::endl                              // --
                         << bsl::here();                           // --

            return bsl::safe_u16::failure();
        }

        return ppid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vmid(bsl::uint64 const reg) noexcept -> bsl::safe_u16
    {
        auto const vmid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vmid)) {
            bsl::error() << "the provided vmid "                      // --
                         << bsl::hex(vmid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vmid) >= HYPERVISOR_MAX_VMS)) {
            bsl::error() << "the provided vmid "                      // --
                         << bsl::hex(vmid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the VM associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vmid from.
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the VM associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vmid(bsl::uint64 const reg, vm_pool_t const &vm_pool) noexcept -> bsl::safe_u16
    {
        auto const vmid{get_vmid(reg)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vm_pool.is_deallocated(vmid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vmid "                         // --
                         << bsl::hex(vmid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vpid from.
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vpid(bsl::uint64 const reg) noexcept -> bsl::safe_u16
    {
        auto const vpid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vpid) >= HYPERVISOR_MAX_VPS)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the VM associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the VM associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vpid(bsl::uint64 const reg, vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_vpid(reg)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vp_pool.is_deallocated(vpid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vpid "                         // --
                         << bsl::hex(vpid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vsid from.
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vsid(bsl::uint64 const reg) noexcept -> bsl::safe_u16
    {
        auto const vsid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vsid)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vsid) >= HYPERVISOR_MAX_VSS)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the VM associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vsid from.
    ///   @param vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the VM associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vsid(bsl::uint64 const reg, vs_pool_t const &vs_pool) noexcept -> bsl::safe_u16
    {
        auto const vsid{get_vsid(reg)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vs_pool.is_deallocated(vsid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vsid "                         // --
                         << bsl::hex(vsid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid, the VM associated with the
    ///     vsid is allocated and locally assigned to the current PP.
    ///     Otherwise, this function returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param reg the register to get the vsid from.
    ///   @param vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid, the VM associated with the
    ///     vsid is allocated and locally assigned to the current PP.
    ///     Otherwise, this function returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_locally_assigned_vsid(
        tls_t const &tls,
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        bsl::uint64 const reg,
        vs_pool_t const &vs_pool) noexcept -> bsl::safe_u16
    {
        auto const vsid{get_allocated_vsid(reg, vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const vs_assigned_to_pp{is_vs_assigned_to_current_pp(tls, vs_pool, vsid)};
        if (bsl::unlikely(!vs_assigned_to_pp)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a bf_reg_t if the provided
    ///     register contains a valid bf_reg_t. Otherwise, this function
    ///     returns syscall::bf_reg_t::bf_reg_t_invalid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vsid from.
    ///   @return Given an input register, returns a bf_reg_t if the provided
    ///     register contains a valid bf_reg_t. Otherwise, this function
    ///     returns syscall::bf_reg_t::bf_reg_t_invalid.
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_reg(bsl::uint64 const reg) noexcept -> syscall::bf_reg_t
    {
        if (bsl::unlikely(reg >= bsl::to_u64(syscall::BF_MAX_REG_T))) {
            bsl::error() << "the provided bf_reg_t "            // --
                         << bsl::hex(reg)                       // --
                         << " is invalid and cannot be used"    // --
                         << bsl::endl                           // --
                         << bsl::here();                        // --

            return syscall::bf_reg_t::bf_reg_t_invalid;
        }

        auto const ret{static_cast<syscall::bf_reg_t>(reg)};
        if (bsl::unlikely(syscall::bf_reg_t::bf_reg_t_unsupported == ret)) {
            bsl::error() << "the provided bf_reg_t "                // --
                         << bsl::hex(reg)                           // --
                         << " is unsupported and cannot be used"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::bf_reg_t::bf_reg_t_invalid;
        }

        return ret;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a physical address if the
    ///     provided register contains a valid physical address. Otherwise,
    ///     this function returns bsl::safe_umx::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the physical address from.
    ///   @return Given an input register, returns a physical address if the
    ///     provided register contains a valid physical address. Otherwise,
    ///     this function returns bsl::safe_umx::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_phys(bsl::uint64 const reg) noexcept -> bsl::safe_umx
    {
        auto const phys{bsl::to_umx(reg)};
        if (bsl::unlikely(phys.is_zero())) {
            bsl::error() << "the physical address "                    // --
                         << bsl::hex(phys)                             // --
                         << " is a NULL address and cannot be used"    // --
                         << bsl::endl                                  // --
                         << bsl::here();                               // --

            return bsl::safe_umx::failure();
        }

        if (bsl::unlikely(phys >= HYPERVISOR_EXT_DIRECT_MAP_SIZE)) {
            bsl::error() << "the physical address "                  // --
                         << bsl::hex(phys)                           // --
                         << " is out of range and cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_umx::failure();
        }

        bool const aligned{syscall::bf_is_page_aligned(phys)};
        if (bsl::unlikely(!aligned)) {
            bsl::error() << "the physical address "                      // --
                         << bsl::hex(phys)                               // --
                         << " is not page aligned and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_umx::failure();
        }

        return phys;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a virtual address if the
    ///     provided register contains a valid virtual address. Otherwise,
    ///     this function returns bsl::safe_umx::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the virtual address from.
    ///   @return Given an input register, returns a virtual address if the
    ///     provided register contains a valid virtual address. Otherwise,
    ///     this function returns bsl::safe_umx::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_virt(bsl::uint64 const reg) noexcept -> bsl::safe_umx
    {
        constexpr auto min_addr{HYPERVISOR_EXT_DIRECT_MAP_ADDR};
        constexpr auto max_addr{(min_addr + HYPERVISOR_EXT_DIRECT_MAP_SIZE).checked()};

        auto const virt{bsl::to_umx(reg)};
        if (bsl::unlikely(virt.is_zero())) {
            bsl::error() << "the virtual address "                     // --
                         << bsl::hex(virt)                             // --
                         << " is a NULL address and cannot be used"    // --
                         << bsl::endl                                  // --
                         << bsl::here();                               // --

            return bsl::safe_umx::failure();
        }

        if (bsl::unlikely(virt <= min_addr)) {
            bsl::error() << "the virtual address "                   // --
                         << bsl::hex(virt)                           // --
                         << " is out of range and cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_umx::failure();
        }

        if (bsl::unlikely(virt <= min_addr)) {
            bsl::error() << "the virtual address "                   // --
                         << bsl::hex(virt)                           // --
                         << " is out of range and cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_umx::failure();
        }

        if (bsl::unlikely(virt >= max_addr)) {
            bsl::error() << "the virtual address "                   // --
                         << bsl::hex(virt)                           // --
                         << " is out of range and cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_umx::failure();
        }

        bool const aligned{syscall::bf_is_page_aligned(virt)};
        if (bsl::unlikely(!aligned)) {
            bsl::error() << "the virtual address "                       // --
                         << bsl::hex(virt)                               // --
                         << " is not page aligned and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_umx::failure();
        }

        return virt;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a huge allocation size if
    ///     the provided register contains a valid huge allocation size.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the size from.
    ///   @return Given an input register, returns a huge allocation size if
    ///     the provided register contains a valid huge allocation size.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_huge_size(bsl::uint64 const reg) noexcept -> bsl::safe_u64
    {
        auto const size{bsl::to_u64(reg)};
        if (bsl::unlikely(size <= HYPERVISOR_PAGE_SIZE)) {
            bsl::error() << "the size "                                        // --
                         << bsl::hex(size)                                     // --
                         << " is not larger than a page and cannot be used"    // --
                         << bsl::endl                                          // --
                         << bsl::here();                                       // --

            return bsl::safe_u64::failure();
        }

        if (bsl::unlikely(size >= HYPERVISOR_MK_HUGE_POOL_SIZE)) {
            bsl::error() << "the size "                           // --
                         << bsl::hex(size)                        // --
                         << " is too large and cannot be used"    // --
                         << bsl::endl                             // --
                         << bsl::here();                          // --

            return bsl::safe_u64::failure();
        }

        bool const aligned{syscall::bf_is_page_aligned(size)};
        if (bsl::unlikely(!aligned)) {
            bsl::error() << "the size "                                  // --
                         << bsl::hex(size)                               // --
                         << " is not page aligned and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u64::failure();
        }

        return size;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns an msr index if the provided
    ///     register contains a valid msr index. Otherwise, this function
    ///     returns bsl::safe_u32::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the msr index from.
    ///   @return Given an input register, returns an msr index if the provided
    ///     register contains a valid msr index. Otherwise, this function
    ///     returns bsl::safe_u32::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_msr(bsl::uint64 const reg) noexcept -> bsl::safe_u32
    {
        /// TODO:
        /// - We need to compile a whitelist of safe MSRs that an extension
        ///   can read and then check to make sure that "reg" is in the
        ///   list. The easiest way to do this is to see what MicroV needs
        ///   and then limit this to that list. Any additional MSRs can be
        ///   added on demand from the community as needed.
        ///

        return bsl::to_u32_unsafe(reg);
    }

    /// ------------------------------------------------------------------------
    /// Report Unsupported Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Tells the user that the syscall is unknown or is not
    ///     supported by this hypervisor.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @return Always returns syscall::BF_STATUS_FAILURE_UNSUPPORTED.
    ///
    [[nodiscard]] constexpr auto
    report_syscall_unknown_unsupported(tls_t const &tls) noexcept -> syscall::bf_status_t
    {
        bsl::error() << "unknown/unsupported syscall "    //--
                     << bsl::hex(tls.ext_syscall)         //--
                     << bsl::endl                         //--
                     << bsl::here();                      //--

        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }
}

#endif
