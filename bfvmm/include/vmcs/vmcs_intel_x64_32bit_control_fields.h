//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef VMCS_INTEL_X64_32BIT_CONTROL_FIELDS_H
#define VMCS_INTEL_X64_32BIT_CONTROL_FIELDS_H

#include <bitmanip.h>
#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

/// Intel x86_64 VMCS 32-bit Control Fields
///
/// The following provides the interface for the 32-bit control VMCS
/// fields as defined in Appendix B.3.1, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace pin_based_vm_execution_controls
{
    constexpr const auto addr = 0x0000000000004000UL;
    constexpr const auto name = "pin_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_pinbased_ctls::addr;

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace external_interrupt_exiting
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "external_interrupt_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace nmi_exiting
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "nmi_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtual_nmis
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "virtual_nmis";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace activate_vmx_preemption_timer
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "activate_vmx_preemption_timer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace process_posted_interrupts
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "process_posted_interrupts";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace primary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x0000000000004002UL;
    constexpr const auto name = "primary_processor_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_procbased_ctls::addr;

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace interrupt_window_exiting
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "interrupt_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_tsc_offsetting
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "use_tsc_offsetting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace hlt_exiting
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "hlt_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace invlpg_exiting
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "invlpg_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace mwait_exiting
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "mwait_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdpmc_exiting
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdpmc_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdtsc_exiting
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "rdtsc_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr3_load_exiting
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "cr3_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr3_store_exiting
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "cr3_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr8_load_exiting
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "cr8_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace cr8_store_exiting
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "cr8_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_tpr_shadow
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "use_tpr_shadow";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace nmi_window_exiting
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "nmi_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace mov_dr_exiting
    {
        constexpr const auto mask = 0x0000000000800000UL;
        constexpr const auto from = 23;
        constexpr const auto name = "mov_dr_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace unconditional_io_exiting
    {
        constexpr const auto mask = 0x0000000001000000UL;
        constexpr const auto from = 24;
        constexpr const auto name = "unconditional_io_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_io_bitmaps
    {
        constexpr const auto mask = 0x0000000002000000UL;
        constexpr const auto from = 25;
        constexpr const auto name = "use_io_bitmaps";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace monitor_trap_flag
    {
        constexpr const auto mask = 0x0000000008000000UL;
        constexpr const auto from = 27;
        constexpr const auto name = "monitor_trap_flag";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace use_msr_bitmap
    {
        constexpr const auto mask = 0x0000000010000000UL;
        constexpr const auto from = 28;
        constexpr const auto name = "use_msr_bitmap";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace monitor_exiting
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "monitor_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace pause_exiting
    {
        constexpr const auto mask = 0x0000000040000000UL;
        constexpr const auto from = 30;
        constexpr const auto name = "pause_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace activate_secondary_controls
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "activate_secondary_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace exception_bitmap
{
    constexpr const auto addr = 0x0000000000004004UL;
    constexpr const auto name = "execption_bitmap";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace page_fault_error_code_mask
{
    constexpr const auto addr = 0x0000000000004006UL;
    constexpr const auto name = "page_fault_error_code_mask";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace page_fault_error_code_match
{
    constexpr const auto addr = 0x0000000000004008UL;
    constexpr const auto name = "page_fault_error_code_match";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace cr3_target_count
{
    constexpr const auto addr = 0x000000000000400AUL;
    constexpr const auto name = "cr3_target_count";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_exit_controls
{
    constexpr const auto addr = 0x000000000000400CUL;
    constexpr const auto name = "vm_exit_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_exit_ctls::addr;

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace save_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "save_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace host_address_space_size
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "host_address_space_size";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace acknowledge_interrupt_on_exit
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "acknowledge_interrupt_on_exit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_ia32_pat
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "save_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000080000UL;
        constexpr const auto from = 19;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_ia32_efer
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20;
        constexpr const auto name = "save_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000200000UL;
        constexpr const auto from = 21;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace save_vmx_preemption_timer_value
    {
        constexpr const auto mask = 0x0000000000400000UL;
        constexpr const auto from = 22;
        constexpr const auto name = "save_vmx_preemption_timer_value";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace clear_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000800000UL;
        constexpr const auto from = 23;
        constexpr const auto name = "clear_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace vm_exit_msr_store_count
{
    constexpr const auto addr = 0x000000000000400EUL;
    constexpr const auto name = "vm_exit_msr_store_count";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_exit_msr_load_count
{
    constexpr const auto addr = 0x0000000000004010UL;
    constexpr const auto name = "vm_exit_msr_load_count";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_controls
{
    constexpr const auto addr = 0x0000000000004012UL;
    constexpr const auto name = "vm_entry_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace load_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "load_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace ia_32e_mode_guest
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "ia_32e_mode_guest";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace entry_to_smm
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "entry_to_smm";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace deactivate_dual_monitor_treatment
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "deactivate_dual_monitor_treatment";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000008000UL;
        constexpr const auto from = 15;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace load_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "load_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace vm_entry_msr_load_count
{
    constexpr const auto addr = 0x0000000000004014UL;
    constexpr const auto name = "vm_entry_msr_load_count";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_interruption_information_field
{
    constexpr const auto addr = 0x0000000000004016UL;
    constexpr const auto name = "vm_entry_interruption_information_field";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace vector
    {
        constexpr const auto mask = 0x000000FFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "vector";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace interruption_type
    {
        constexpr const auto mask = 0x00000700UL;
        constexpr const auto from = 8;
        constexpr const auto name = "interruption_type";

        constexpr const auto external_interrupt = 0UL;
        constexpr const auto reserved = 1UL;
        constexpr const auto non_maskable_interrupt = 2UL;
        constexpr const auto hardware_exception = 3UL;
        constexpr const auto software_interrupt = 4UL;
        constexpr const auto privileged_software_exception = 5UL;
        constexpr const auto software_exception = 6UL;
        constexpr const auto other_event = 7UL;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace deliver_error_code_bit
    {
        constexpr const auto mask = 0x00000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "deliver_error_code_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists());
        }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x7FFFF000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace valid_bit
    {
        constexpr const auto mask = 0x80000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "valid_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bit(field, from), addr, name, exists()); }

        inline void enable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists());
        }

        inline void disable()
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(clear_bit(field, from), addr, name, exists());
        }

        inline void disable_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists());
        }
    }
}

namespace vm_entry_exception_error_code
{
    constexpr const auto addr = 0x0000000000004018UL;
    constexpr const auto name = "vm_entry_exception_error_code";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace vm_entry_instruction_length
{
    constexpr const auto addr = 0x000000000000401AUL;
    constexpr const auto name = "vm_entry_instruction_length";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace tpr_threshold
{
    constexpr const auto addr = 0x000000000000401CUL;
    constexpr const auto name = "tpr_threshold";

    inline auto exists() noexcept
    { return msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace secondary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x000000000000401EUL;
    constexpr const auto name = "secondary_processor_based_vm_execution_controls";
    constexpr const auto msr_addr = msrs::ia32_vmx_procbased_ctls2::addr;

    inline auto exists() noexcept
    { return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace virtualize_apic_accesses
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtualize_apic_accesses";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_ept
    {
        constexpr const auto mask = 0x0000000000000002UL;
        constexpr const auto from = 1;
        constexpr const auto name = "enable_ept";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace descriptor_table_exiting
    {
        constexpr const auto mask = 0x0000000000000004UL;
        constexpr const auto from = 2;
        constexpr const auto name = "descriptor_table_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_rdtscp
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "enable_rdtscp";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtualize_x2apic_mode
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "virtualize_x2apic_mode";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_vpid
    {
        constexpr const auto mask = 0x0000000000000020UL;
        constexpr const auto from = 5;
        constexpr const auto name = "enable_vpid";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace wbinvd_exiting
    {
        constexpr const auto mask = 0x0000000000000040UL;
        constexpr const auto from = 6;
        constexpr const auto name = "wbinvd_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace unrestricted_guest
    {
        constexpr const auto mask = 0x0000000000000080UL;
        constexpr const auto from = 7;
        constexpr const auto name = "unrestricted_guest";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace apic_register_virtualization
    {
        constexpr const auto mask = 0x0000000000000100UL;
        constexpr const auto from = 8;
        constexpr const auto name = "apic_register_virtualization";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace virtual_interrupt_delivery
    {
        constexpr const auto mask = 0x0000000000000200UL;
        constexpr const auto from = 9;
        constexpr const auto name = "virtual_interrupt_delivery";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace pause_loop_exiting
    {
        constexpr const auto mask = 0x0000000000000400UL;
        constexpr const auto from = 10;
        constexpr const auto name = "pause_loop_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdrand_exiting
    {
        constexpr const auto mask = 0x0000000000000800UL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdrand_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_invpcid
    {
        constexpr const auto mask = 0x0000000000001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "enable_invpcid";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_vm_functions
    {
        constexpr const auto mask = 0x0000000000002000UL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_vm_functions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace vmcs_shadowing
    {
        constexpr const auto mask = 0x0000000000004000UL;
        constexpr const auto from = 14;
        constexpr const auto name = "vmcs_shadowing";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace rdseed_exiting
    {
        constexpr const auto mask = 0x0000000000010000UL;
        constexpr const auto from = 16;
        constexpr const auto name = "rdseed_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_pml
    {
        constexpr const auto mask = 0x0000000000020000UL;
        constexpr const auto from = 17;
        constexpr const auto name = "enable_pml";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace ept_violation_ve
    {
        constexpr const auto mask = 0x0000000000040000UL;
        constexpr const auto from = 18;
        constexpr const auto name = "ept_violation_ve";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }

    namespace enable_xsaves_xrstors
    {
        constexpr const auto mask = 0x0000000000100000UL;
        constexpr const auto from = 20 ;
        constexpr const auto name = "enable_xsaves_xrstors";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vm_control(true, msr_addr, addr, name, mask, exists()); }

        inline void enable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(true, msr_addr, addr, name, mask, verbose, exists()); }

        inline void disable()
        { set_vm_control(false, msr_addr, addr, name, mask, exists()); }

        inline void disable_if_allowed(bool verbose = false) noexcept
        { set_vm_control_if_allowed(false, msr_addr, addr, name, mask, verbose, exists()); }
    }
}

namespace ple_gap
{
    constexpr const auto addr = 0x0000000000004020UL;
    constexpr const auto name = "ple_gap";

    inline auto exists() noexcept
    {
        return vmcs::secondary_processor_based_vm_execution_controls::exists() &&
               msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

namespace ple_window
{
    constexpr const auto addr = 0x0000000000004022UL;
    constexpr const auto name = "ple_window";

    inline auto exists() noexcept
    {
        return vmcs::secondary_processor_based_vm_execution_controls::exists() &&
               msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
