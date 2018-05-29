//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <arch/intel_x64/vmcs/helpers.h>

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
    constexpr const auto addr = 0x0000000000004000ULL;
    constexpr const auto name = "pin_based_vm_execution_controls";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace external_interrupt_exiting
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "external_interrupt_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace nmi_exiting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "nmi_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_pinbased_ctls::nmi_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace virtual_nmis
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "virtual_nmis";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_pinbased_ctls::virtual_nmis::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace activate_vmx_preemption_timer
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "activate_vmx_preemption_timer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace process_posted_interrupts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "process_posted_interrupts";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, "pin_based_vm_execution_controls", get(), msg);
        external_interrupt_exiting::dump(level, msg);
        nmi_exiting::dump(level, msg);
        virtual_nmis::dump(level, msg);
        activate_vmx_preemption_timer::dump(level, msg);
        process_posted_interrupts::dump(level, msg);
    }
}

namespace primary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x0000000000004002ULL;
    constexpr const auto name = "primary_processor_based_vm_execution_controls";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace interrupt_window_exiting
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "interrupt_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::interrupt_window_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace use_tsc_offsetting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "use_tsc_offsetting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::use_tsc_offsetting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace hlt_exiting
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "hlt_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::hlt_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace invlpg_exiting
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "invlpg_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::invlpg_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace mwait_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "mwait_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::mwait_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace rdpmc_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "rdpmc_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::rdpmc_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace rdtsc_exiting
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "rdtsc_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::rdtsc_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace cr3_load_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "cr3_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::cr3_load_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace cr3_store_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "cr3_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::cr3_store_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace cr8_load_exiting
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "cr8_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::cr8_load_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace cr8_store_exiting
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "cr8_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::cr8_store_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace use_tpr_shadow
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "use_tpr_shadow";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace nmi_window_exiting
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "nmi_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::nmi_window_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace mov_dr_exiting
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "mov_dr_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::mov_dr_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace unconditional_io_exiting
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "unconditional_io_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::unconditional_io_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace use_io_bitmaps
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "use_io_bitmaps";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::use_io_bitmaps::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace monitor_trap_flag
    {
        constexpr const auto mask = 0x0000000008000000ULL;
        constexpr const auto from = 27ULL;
        constexpr const auto name = "monitor_trap_flag";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace use_msr_bitmap
    {
        constexpr const auto mask = 0x0000000010000000ULL;
        constexpr const auto from = 28ULL;
        constexpr const auto name = "use_msr_bitmap";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmap::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace monitor_exiting
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29ULL;
        constexpr const auto name = "monitor_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::monitor_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace pause_exiting
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "pause_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::pause_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace activate_secondary_controls
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "activate_secondary_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, "primary_processor_based_vm_execution_controls", get(), msg);
        interrupt_window_exiting::dump(level, msg);
        use_tsc_offsetting::dump(level, msg);
        hlt_exiting::dump(level, msg);
        invlpg_exiting::dump(level, msg);
        mwait_exiting::dump(level, msg);
        rdpmc_exiting::dump(level, msg);
        rdtsc_exiting::dump(level, msg);
        cr3_load_exiting::dump(level, msg);
        cr3_store_exiting::dump(level, msg);
        cr8_load_exiting::dump(level, msg);
        cr8_store_exiting::dump(level, msg);
        use_tpr_shadow::dump(level, msg);
        nmi_window_exiting::dump(level, msg);
        mov_dr_exiting::dump(level, msg);
        unconditional_io_exiting::dump(level, msg);
        use_io_bitmaps::dump(level, msg);
        monitor_trap_flag::dump(level, msg);
        use_msr_bitmap::dump(level, msg);
        monitor_exiting::dump(level, msg);
        pause_exiting::dump(level, msg);
        activate_secondary_controls::dump(level, msg);
    }
}

namespace exception_bitmap
{
    constexpr const auto addr = 0x0000000000004004ULL;
    constexpr const auto name = "execption_bitmap";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace page_fault_error_code_mask
{
    constexpr const auto addr = 0x0000000000004006ULL;
    constexpr const auto name = "page_fault_error_code_mask";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace page_fault_error_code_match
{
    constexpr const auto addr = 0x0000000000004008ULL;
    constexpr const auto name = "page_fault_error_code_match";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr3_target_count
{
    constexpr const auto addr = 0x000000000000400AULL;
    constexpr const auto name = "cr3_target_count";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace vm_exit_controls
{
    constexpr const auto addr = 0x000000000000400CULL;
    constexpr const auto name = "vm_exit_controls";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace save_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "save_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::save_debug_controls::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace host_address_space_size
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "host_address_space_size";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::host_address_space_size::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace acknowledge_interrupt_on_exit
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "acknowledge_interrupt_on_exit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace save_ia32_pat
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "save_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace save_ia32_efer
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "save_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace save_vmx_preemption_timer_value
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "save_vmx_preemption_timer_value";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace clear_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "clear_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace pt_conceal_vm_exits
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23ULL;
        constexpr const auto name = "pt_conceal_vm_exits";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, "vm_exit_controls", get(), msg);
        save_debug_controls::dump(level, msg);
        host_address_space_size::dump(level, msg);
        load_ia32_perf_global_ctrl::dump(level, msg);
        acknowledge_interrupt_on_exit::dump(level, msg);
        save_ia32_pat::dump(level, msg);
        load_ia32_pat::dump(level, msg);
        save_ia32_efer::dump(level, msg);
        load_ia32_efer::dump(level, msg);
        save_vmx_preemption_timer_value::dump(level, msg);
        clear_ia32_bndcfgs::dump(level, msg);
        pt_conceal_vm_exits::dump(level, msg);
    }
}

namespace vm_exit_msr_store_count
{
    constexpr const auto addr = 0x000000000000400EULL;
    constexpr const auto name = "vm_exit_msr_store_count";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace vm_exit_msr_load_count
{
    constexpr const auto addr = 0x0000000000004010ULL;
    constexpr const auto name = "vm_exit_msr_load_count";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace vm_entry_controls
{
    constexpr const auto addr = 0x0000000000004012ULL;
    constexpr const auto name = "vm_entry_controls";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace load_debug_controls
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "load_debug_controls";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::load_debug_controls::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace ia_32e_mode_guest
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "ia_32e_mode_guest";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::ia_32e_mode_guest::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace entry_to_smm
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "entry_to_smm";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::entry_to_smm::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace deactivate_dual_monitor_treatment
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "deactivate_dual_monitor_treatment";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::deactivate_dual_monitor_treatment::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace load_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "load_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace pt_conceal_vm_entries
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "pt_conceal_vm_entries";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, "vm_entry_controls", get(), msg);
        load_debug_controls::dump(level, msg);
        ia_32e_mode_guest::dump(level, msg);
        entry_to_smm::dump(level, msg);
        deactivate_dual_monitor_treatment::dump(level, msg);
        load_ia32_perf_global_ctrl::dump(level, msg);
        load_ia32_pat::dump(level, msg);
        load_ia32_efer::dump(level, msg);
        load_ia32_bndcfgs::dump(level, msg);
        pt_conceal_vm_entries::dump(level, msg);
    }
}

namespace vm_entry_msr_load_count
{
    constexpr const auto addr = 0x0000000000004014ULL;
    constexpr const auto name = "vm_entry_msr_load_count";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace vm_entry_interruption_information
{
    constexpr const auto addr = 0x0000000000004016ULL;
    constexpr const auto name = "vm_entry_interruption_information";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace vector
    {
        constexpr const auto mask = 0x000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace interruption_type
    {
        constexpr const auto mask = 0x00000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "interruption_type";

        constexpr const auto external_interrupt = 0ULL;
        constexpr const auto reserved = 1ULL;
        constexpr const auto non_maskable_interrupt = 2ULL;
        constexpr const auto hardware_exception = 3ULL;
        constexpr const auto software_interrupt = 4ULL;
        constexpr const auto privileged_software_exception = 5ULL;
        constexpr const auto software_exception = 6ULL;
        constexpr const auto other_event = 7ULL;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace deliver_error_code_bit
    {
        constexpr const auto mask = 0x00000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "deliver_error_code_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x7FFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace valid_bit
    {
        constexpr const auto mask = 0x80000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "valid_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        vector::dump(level, msg);
        interruption_type::dump(level, msg);
        deliver_error_code_bit::dump(level, msg);
        reserved::dump(level, msg);
        valid_bit::dump(level, msg);
    }
}

namespace vm_entry_exception_error_code
{
    constexpr const auto addr = 0x0000000000004018ULL;
    constexpr const auto name = "vm_entry_exception_error_code";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace vm_entry_instruction_length
{
    constexpr const auto addr = 0x000000000000401AULL;
    constexpr const auto name = "vm_entry_instruction_length";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace tpr_threshold
{
    constexpr const auto addr = 0x000000000000401CULL;
    constexpr const auto name = "tpr_threshold";

    inline auto exists()
    { return msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace secondary_processor_based_vm_execution_controls
{
    constexpr const auto addr = 0x000000000000401EULL;
    constexpr const auto name = "secondary_processor_based_vm_execution_controls";

    inline auto exists()
    { return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace virtualize_apic_accesses
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "virtualize_apic_accesses";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_ept
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "enable_ept";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace descriptor_table_exiting
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "descriptor_table_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::descriptor_table_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_rdtscp
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "enable_rdtscp";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_rdtscp::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace virtualize_x2apic_mode
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "virtualize_x2apic_mode";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_vpid
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "enable_vpid";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_vpid::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace wbinvd_exiting
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "wbinvd_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::wbinvd_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace unrestricted_guest
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "unrestricted_guest";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::unrestricted_guest::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace apic_register_virtualization
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "apic_register_virtualization";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::apic_register_virtualization::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace virtual_interrupt_delivery
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "virtual_interrupt_delivery";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace pause_loop_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "pause_loop_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace rdrand_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "rdrand_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::rdrand_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_invpcid
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "enable_invpcid";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_invpcid::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_vm_functions
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "enable_vm_functions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace vmcs_shadowing
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "vmcs_shadowing";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_encls_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "vmcs_shadowing";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_encls_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace rdseed_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "rdseed_exiting";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::rdseed_exiting::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_pml
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "enable_pml";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_pml::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace ept_violation_ve
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "ept_violation_ve";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace pt_conceal_vmx_nonroot_operation
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19ULL;
        constexpr const auto name = "pt_conceal_vmx_nonroot_operation";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::pt_conceal_nonroot_operation::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace enable_xsaves_xrstors
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "enable_xsaves_xrstors";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace ept_mode_based_control
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "ept_mode_based_control";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::ept_mode_based_control::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    namespace use_tsc_scaling
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25ULL;
        constexpr const auto name = "use_tsc_scaling";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_allowed0()
        { return msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed0(); }

        inline auto is_allowed1()
        { return msrs::ia32_vmx_procbased_ctls2::use_tsc_scaling::is_allowed1(); }

        inline void enable()
        { enable_vm_control(addr, from, is_allowed1(), name, exists()); }

        inline void enable_if_allowed(bool verbose = false)
        { enable_vm_control_if_allowed(addr, from, is_allowed1(), name, verbose, exists()); }

        inline void disable()
        { disable_vm_control(addr, from, is_allowed0(), name, exists()); }

        inline void disable_if_allowed(bool verbose = false)
        { disable_vm_control_if_allowed(addr, from, is_allowed0(), name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set_if_allowed(bool val, bool verbose = false)
        { val ? enable_if_allowed(verbose) : disable_if_allowed(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vm_control(level, exists(), is_allowed1(), is_enabled_if_exists(), name, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, "secondary_processor_based_vm_execution_controls", get(), msg);
        virtualize_apic_accesses::dump(level, msg);
        enable_ept::dump(level, msg);
        descriptor_table_exiting::dump(level, msg);
        enable_rdtscp::dump(level, msg);
        virtualize_x2apic_mode::dump(level, msg);
        enable_vpid::dump(level, msg);
        wbinvd_exiting::dump(level, msg);
        unrestricted_guest::dump(level, msg);
        apic_register_virtualization::dump(level, msg);
        virtual_interrupt_delivery::dump(level, msg);
        pause_loop_exiting::dump(level, msg);
        rdrand_exiting::dump(level, msg);
        enable_invpcid::dump(level, msg);
        enable_vm_functions::dump(level, msg);
        vmcs_shadowing::dump(level, msg);
        enable_encls_exiting::dump(level, msg);
        rdseed_exiting::dump(level, msg);
        enable_pml::dump(level, msg);
        ept_violation_ve::dump(level, msg);
        pt_conceal_vmx_nonroot_operation::dump(level, msg);
        enable_xsaves_xrstors::dump(level, msg);
        ept_mode_based_control::dump(level, msg);
        use_tsc_scaling::dump(level, msg);
    }
}

namespace ple_gap
{
    constexpr const auto addr = 0x0000000000004020ULL;
    constexpr const auto name = "ple_gap";

    inline auto exists()
    {
        return vmcs::secondary_processor_based_vm_execution_controls::exists() &&
               msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace ple_window
{
    constexpr const auto addr = 0x0000000000004022ULL;
    constexpr const auto name = "ple_window";

    inline auto exists()
    {
        return vmcs::secondary_processor_based_vm_execution_controls::exists() &&
               msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

}
}

// *INDENT-ON*

#endif
