//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_32BIT_READ_ONLY_DATA_FIELDS_H
#define VMCS_INTEL_X64_32BIT_READ_ONLY_DATA_FIELDS_H

#include <bitmanip.h>
#include <vmcs/vmcs_intel_x64.h>

/// Intel x86_64 VMCS 32-bit Read-Only Data Fields
///
/// The following provides the interface for the 32-bit read-only data VMCS
/// fields as defined in Appendix B.3.2, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace vm_instruction_error
{
    constexpr const auto addr = 0x0000000000004400UL;
    constexpr const auto name = "vm_instruction_error";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto __vm_instruction_error_description(T error)
    {
        switch (error)
        {
            case 1U:
                return "VMCALL executed in VMX root operation";

            case 2U:
                return "VMCLEAR with invalid physical address";

            case 3U:
                return "VMCLEAR with VMXON pointer";

            case 4U:
                return "VMLAUNCH with non-clear VMCS";

            case 5U:
                return "VMRESUME with non-launched VMCS";

            case 6U:
                return "VMRESUME after VMXOFF (VMXOFF AND VMXON between VMLAUNCH and VMRESUME)";

            case 7U:
                return "VM entry with invalid control field(s)";

            case 8U:
                return "VM entry with invalid host-state field(s)";

            case 9U:
                return "VMPTRLD with invalid physical address";

            case 10U:
                return "VMPTRLD with VMXON pointer";

            case 11U:
                return "VMPTRLD with incorrect VMCS revision identifier";

            case 12U:
                return "VMREAD/VMWRITE from/to unsupported VMCS component";

            case 13U:
                return "VMWRITE to read-only VMCS component";

            case 15U:
                return "VMXON executed in VMX root operation";

            case 16U:
                return "VM entry with invalid executive-VMCS pointer";

            case 17U:
                return "VM entry with non-launched executive VMCS";

            case 18U:
                return "VM entry with executive-VMCS pointer not VMXON pointer "
                       "(when attempting to deactivate the dual-monitor treatment of SMIs and SMM)";

            case 19U:
                return "VMCALL with non-clear VMCS (when attempting to activate"
                       " the dual-monitor treatment of SMIs and SMM)";

            case 20U:
                return "VMCALL with invalid VM-exit control fields";

            case 22U:
                return "VMCALL with incorrect MSEG revision identifier (when attempting "
                       "to activate the dual-monitor treatment of SMIs and SMM)";

            case 23U:
                return "VMXOFF under dual-monitor treatment of SMIs and SMM";

            case 24U:
                return "VMCALL with invalid SMM-monitor features (when attempting to "
                       "activate the dual-monitor treatment of SMIs and SMM)";

            case 25U:
                return "VM entry with invalid VM-execution control fields in executive"
                       " VMCS (when attempting to return from SMM)";

            case 26U:
                return "VM entry with events blocked by MOV SS";

            case 28U:
                return "Invalid operand to INVEPT/INVVPID";

            default:
                return "Unknown VM-instruction error";
        }
    }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto vm_instruction_error_description(T error, bool exists)
    {
        if (!exists)
            throw std::logic_error("vm_instruction_error() failed: vm_instruction_error field doesn't exist");

        return __vm_instruction_error_description(error);
    }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto vm_instruction_error_description_if_exists(T error, bool verbose, bool exists)
    {
        if (!exists && verbose)
            bfwarning << "vm_instruction_error() failed: vm_instruction_error field doesn't exist" << '\n';

        if (exists)
            return __vm_instruction_error_description(error);

        return "";
    }

    inline auto description()
    { return vm_instruction_error_description(get_vmcs_field(addr, name, exists()), exists()); }

    inline auto description_if_exists(bool verbose = false) noexcept
    {
        auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
        return vm_instruction_error_description_if_exists(field, verbose, exists());
    }
}

namespace exit_reason
{
    constexpr const auto addr = 0x0000000000004402UL;
    constexpr const auto name = "exit_reason";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    namespace basic_exit_reason
    {
        constexpr const auto mask = 0x000000000000FFFFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "basic_exit_reason";

        constexpr const auto exception_or_non_maskable_interrupt = 0U;
        constexpr const auto external_interrupt = 1U;
        constexpr const auto triple_fault = 2U;
        constexpr const auto init_signal = 3U;
        constexpr const auto sipi = 4U;
        constexpr const auto smi = 5U;
        constexpr const auto other_smi = 6U;
        constexpr const auto interrupt_window = 7U;
        constexpr const auto nmi_window = 8U;
        constexpr const auto task_switch = 9U;
        constexpr const auto cpuid = 10U;
        constexpr const auto getsec = 11U;
        constexpr const auto hlt = 12U;
        constexpr const auto invd = 13U;
        constexpr const auto invlpg = 14U;
        constexpr const auto rdpmc = 15U;
        constexpr const auto rdtsc = 16U;
        constexpr const auto rsm = 17U;
        constexpr const auto vmcall = 18U;
        constexpr const auto vmclear = 19U;
        constexpr const auto vmlaunch = 20U;
        constexpr const auto vmptrld = 21U;
        constexpr const auto vmptrst = 22U;
        constexpr const auto vmread = 23U;
        constexpr const auto vmresume = 24U;
        constexpr const auto vmwrite = 25U;
        constexpr const auto vmxoff = 26U;
        constexpr const auto vmxon = 27U;
        constexpr const auto control_register_accesses = 28U;
        constexpr const auto mov_dr = 29U;
        constexpr const auto io_instruction = 30U;
        constexpr const auto rdmsr = 31U;
        constexpr const auto wrmsr = 32U;
        constexpr const auto vm_entry_failure_invalid_guest_state = 33U;
        constexpr const auto vm_entry_failure_msr_loading = 34U;
        constexpr const auto mwait = 36U;
        constexpr const auto monitor_trap_flag = 37U;
        constexpr const auto monitor = 39U;
        constexpr const auto pause = 40U;
        constexpr const auto vm_entry_failure_machine_check_event = 41U;
        constexpr const auto tpr_below_threshold = 43U;
        constexpr const auto apic_access = 44U;
        constexpr const auto virtualized_eoi = 45U;
        constexpr const auto access_to_gdtr_or_idtr = 46U;
        constexpr const auto access_to_ldtr_or_tr = 47U;
        constexpr const auto ept_violation = 48U;
        constexpr const auto ept_misconfiguration = 49U;
        constexpr const auto invept = 50U;
        constexpr const auto rdtscp = 51U;
        constexpr const auto vmx_preemption_timer_expired = 52U;
        constexpr const auto invvpid = 53U;
        constexpr const auto wbinvd = 54U;
        constexpr const auto xsetbv = 55U;
        constexpr const auto apic_write = 56U;
        constexpr const auto rdrand = 57U;
        constexpr const auto invpcid = 58U;
        constexpr const auto vmfunc = 59U;
        constexpr const auto rdseed = 61U;
        constexpr const auto xsaves = 63U;
        constexpr const auto xrstors = 64U;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto __basic_exit_reason_description(T reason)
        {
            switch (reason)
            {
                case exception_or_non_maskable_interrupt:
                    return "exception_or_non_maskable_interrupt";

                case external_interrupt:
                    return "external_interrupt";

                case triple_fault:
                    return "triple_fault";

                case init_signal:
                    return "init_signal";

                case sipi:
                    return "sipi";

                case smi:
                    return "smi";

                case other_smi:
                    return "other_smi";

                case interrupt_window:
                    return "interrupt_window";

                case nmi_window:
                    return "nmi_window";

                case task_switch:
                    return "task_switch";

                case cpuid:
                    return "cpuid";

                case getsec:
                    return "getsec";

                case hlt:
                    return "hlt";

                case invd:
                    return "invd";

                case invlpg:
                    return "invlpg";

                case rdpmc:
                    return "rdpmc";

                case rdtsc:
                    return "rdtsc";

                case rsm:
                    return "rsm";

                case vmcall:
                    return "vmcall";

                case vmclear:
                    return "vmclear";

                case vmlaunch:
                    return "vmlaunch";

                case vmptrld:
                    return "vmptrld";

                case vmptrst:
                    return "vmptrst";

                case vmread:
                    return "vmread";

                case vmresume:
                    return "vmresume";

                case vmwrite:
                    return "vmwrite";

                case vmxoff:
                    return "vmxoff";

                case vmxon:
                    return "vmxon";

                case control_register_accesses:
                    return "control_register_accesses";

                case mov_dr:
                    return "mov_dr";

                case io_instruction:
                    return "io_instruction";

                case rdmsr:
                    return "rdmsr";

                case wrmsr:
                    return "wrmsr";

                case vm_entry_failure_invalid_guest_state:
                    return "vm_entry_failure_invalid_guest_state";

                case vm_entry_failure_msr_loading:
                    return "vm_entry_failure_msr_loading";

                case mwait:
                    return "mwait";

                case monitor_trap_flag:
                    return "monitor_trap_flag";

                case monitor:
                    return "monitor";

                case pause:
                    return "pause";

                case vm_entry_failure_machine_check_event:
                    return "vm_entry_failure_machine_check_event";

                case tpr_below_threshold:
                    return "tpr_below_threshold";

                case apic_access:
                    return "apic_access";

                case virtualized_eoi:
                    return "virtualized_eoi";

                case access_to_gdtr_or_idtr:
                    return "access_to_gdtr_or_idtr";

                case access_to_ldtr_or_tr:
                    return "access_to_ldtr_or_tr";

                case ept_violation:
                    return "ept_violation";

                case ept_misconfiguration:
                    return "ept_misconfiguration";

                case invept:
                    return "invept";

                case rdtscp:
                    return "rdtscp";

                case vmx_preemption_timer_expired:
                    return "vmx_preemption_timer_expired";

                case invvpid:
                    return "invvpid";

                case wbinvd:
                    return "wbinvd";

                case xsetbv:
                    return "xsetbv";

                case apic_write:
                    return "apic_write";

                case rdrand:
                    return "rdrand";

                case invpcid:
                    return "invpcid";

                case vmfunc:
                    return "vmfunc";

                case rdseed:
                    return "rdseed";

                case xsaves:
                    return "xsaves";

                case xrstors:
                    return "xrstors";

                default:
                    return "unknown";
            };
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto basic_exit_reason_description(T reason, bool exists)
        {
            if (!exists)
                throw std::logic_error("basic_exit_reason_description failed: exit_reason field doesn't exist");

            return __basic_exit_reason_description(reason);
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto basic_exit_reason_description_if_exists(T reason, bool verbose, bool exists)
        {
            if (!exists && verbose)
                bfwarning << "basic_exit_reason_description_if_exists failed: exit_reason field doesn't exist" << '\n';

            if (exists)
                return __basic_exit_reason_description(reason);

            return "";
        }

        inline auto description()
        {
            auto&& field = get_bits(get_vmcs_field(addr, name, exists()), mask) >> from;
            return basic_exit_reason_description(field, exists());
        }

        inline auto description_if_exists(bool verbose = false) noexcept
        {
            auto&& field = get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from;
            return basic_exit_reason_description_if_exists(field, verbose, exists());
        }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x0000000047FF0000UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
    }

    namespace vm_exit_incident_to_enclave_mode
    {
        constexpr const auto mask = 0x0000000008000000UL;
        constexpr const auto from = 27;
        constexpr const auto name = "vm_exit_incident_to_enclave_mode";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
    }

    namespace pending_mtf_vm_exit
    {
        constexpr const auto mask = 0x0000000010000000UL;
        constexpr const auto from = 28;
        constexpr const auto name = "pending_mtf_vm_exit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
    }

    namespace vm_exit_from_vmx_root_operation
    {
        constexpr const auto mask = 0x0000000020000000UL;
        constexpr const auto from = 29;
        constexpr const auto name = "vm_exit_from_vmx_root_operation";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
    }

    namespace vm_entry_failure
    {
        constexpr const auto mask = 0x0000000080000000UL;
        constexpr const auto from = 31;
        constexpr const auto name = "vm_entry_failure";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
    }
}

namespace vm_exit_interruption_information
{
    constexpr const auto addr = 0x0000000000004404UL;
    constexpr const auto name = "vm_exit_interruption_information";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    namespace vector
    {
        constexpr const auto mask = 0x000000FFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "vector";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
    }

    namespace interruption_type
    {
        constexpr const auto mask = 0x00000700UL;
        constexpr const auto from = 8;
        constexpr const auto name = "interruption_type";

        constexpr const auto external_interrupt = 0UL;
        constexpr const auto non_maskable_interrupt = 2UL;
        constexpr const auto hardware_exception = 3UL;
        constexpr const auto software_exception = 6UL;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
    }

    namespace error_code_valid
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
    }

    namespace nmi_unblocking_due_to_iret
    {
        constexpr const auto mask = 0x00001000UL;
        constexpr const auto from = 12;
        constexpr const auto name = "nmi_unblocking_due_to_iret";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled_if_exists(bool verbose = false) noexcept
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
    }

    namespace reserved
    {
        constexpr const auto mask = 0x7FFFE000UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
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
    }
}

namespace vm_exit_interruption_error_code
{
    constexpr const auto addr = 0x0000000000004406UL;
    constexpr const auto name = "vm_exit_interruption_error_code";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace idt_vectoring_information
{
    constexpr const auto addr = 0x0000000000004408UL;
    constexpr const auto name = "idt_vectoring_information_field";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    namespace vector
    {
        constexpr const auto mask = 0x000000FFUL;
        constexpr const auto from = 0;
        constexpr const auto name = "vector";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
    }

    namespace interruption_type
    {
        constexpr const auto mask = 0x00000700UL;
        constexpr const auto from = 8;
        constexpr const auto name = "interruption_type";

        constexpr const auto external_interrupt = 0UL;
        constexpr const auto non_maskable_interrupt = 2UL;
        constexpr const auto hardware_exception = 3UL;
        constexpr const auto software_interrupt = 4UL;
        constexpr const auto privileged_software_exception = 5UL;
        constexpr const auto software_exception = 6UL;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
    }

    namespace error_code_valid
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
    }

    namespace reserved
    {
        constexpr const auto mask = 0x7FFFE000UL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
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
    }
}

namespace idt_vectoring_error_code
{
    constexpr const auto addr = 0x000000000000440AUL;
    constexpr const auto name = "idt_vectoring_error_code";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace vm_exit_instruction_length
{
    constexpr const auto addr = 0x000000000000440CUL;
    constexpr const auto name = "vm_exit_instruction_length";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace vm_exit_instruction_information
{
    constexpr const auto addr = 0x000000000000440EUL;
    constexpr const auto name = "vm_exit_instruction_information";

    inline auto exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    namespace ins
    {
        constexpr const auto name = "ins";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace outs
    {
        constexpr const auto name = "outs";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace invept
    {
        constexpr const auto name = "invept";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg2
        {
            constexpr const auto mask = 0x00000000F0000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "reg2";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace invpcid
    {
        constexpr const auto name = "invpcid";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg2
        {
            constexpr const auto mask = 0x00000000F0000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "reg2";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace invvpid
    {
        constexpr const auto name = "invvpid";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg2
        {
            constexpr const auto mask = 0x00000000F0000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "reg2";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace lidt
    {
        constexpr const auto name = "lidt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sgdt = 0U;
            constexpr const auto sidt = 1U;
            constexpr const auto lgdt = 2U;
            constexpr const auto lidt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace lgdt
    {
        constexpr const auto name = "lgdt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sgdt = 0U;
            constexpr const auto sidt = 1U;
            constexpr const auto lgdt = 2U;
            constexpr const auto lidt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace sidt
    {
        constexpr const auto name = "sidt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sgdt = 0U;
            constexpr const auto sidt = 1U;
            constexpr const auto lgdt = 2U;
            constexpr const auto lidt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace sgdt
    {
        constexpr const auto name = "sgdt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000000800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sgdt = 0U;
            constexpr const auto sidt = 1U;
            constexpr const auto lgdt = 2U;
            constexpr const auto lidt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace lldt
    {
        constexpr const auto name = "lldt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sldt = 0U;
            constexpr const auto str = 1U;
            constexpr const auto lldt = 2U;
            constexpr const auto ltr = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace ltr
    {
        constexpr const auto name = "ltr";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sldt = 0U;
            constexpr const auto str = 1U;
            constexpr const auto lldt = 2U;
            constexpr const auto ltr = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace sldt
    {
        constexpr const auto name = "sldt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sldt = 0U;
            constexpr const auto str = 1U;
            constexpr const auto lldt = 2U;
            constexpr const auto ltr = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace str
    {
        constexpr const auto name = "str";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace instruction_identity
        {
            constexpr const auto mask = 0x0000000030000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "instruction_identity";

            constexpr const auto sldt = 0U;
            constexpr const auto str = 1U;
            constexpr const auto lldt = 2U;
            constexpr const auto ltr = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace rdrand
    {
        constexpr const auto name = "rdrand";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace destination_register
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "destination_register";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000001800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace rdseed
    {
        constexpr const auto name = "rdseed";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace destination_register
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "destination_register";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_size
        {
            constexpr const auto mask = 0x0000000000001800UL;
            constexpr const auto from = 11;
            constexpr const auto name = "operand_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmclear
    {
        constexpr const auto name = "vmclear";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmptrld
    {
        constexpr const auto name = "vmptrld";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmptrst
    {
        constexpr const auto name = "vmptrst";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmxon
    {
        constexpr const auto name = "vmxon";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace xrstors
    {
        constexpr const auto name = "xrstors";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace xsaves
    {
        constexpr const auto name = "xsaves";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmread
    {
        constexpr const auto name = "vmread";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg2
        {
            constexpr const auto mask = 0x00000000F0000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "reg2";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace vmwrite
    {
        constexpr const auto name = "vmwrite";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace scaling
        {
            constexpr const auto mask = 0x0000000000000003UL;
            constexpr const auto from = 0;
            constexpr const auto name = "scaling";

            constexpr const auto no_scaling = 0U;
            constexpr const auto scale_by_2 = 1U;
            constexpr const auto scale_by_4 = 2U;
            constexpr const auto scale_by_8 = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg1
        {
            constexpr const auto mask = 0x0000000000000078UL;
            constexpr const auto from = 3;
            constexpr const auto name = "reg1";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace address_size
        {
            constexpr const auto mask = 0x0000000000000380UL;
            constexpr const auto from = 7;
            constexpr const auto name = "address_size";

            constexpr const auto _16bit = 0U;
            constexpr const auto _32bit = 1U;
            constexpr const auto _64bit = 2U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace mem_reg
        {
            constexpr const auto mask = 0x0000000000000400UL;
            constexpr const auto from = 10;
            constexpr const auto name = "mem/reg";

            constexpr const auto mem = 0U;
            constexpr const auto reg = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace segment_register
        {
            constexpr const auto mask = 0x0000000000038000UL;
            constexpr const auto from = 15;
            constexpr const auto name = "segment_register";

            constexpr const auto es = 0U;
            constexpr const auto cs = 1U;
            constexpr const auto ss = 2U;
            constexpr const auto ds = 3U;
            constexpr const auto fs = 4U;
            constexpr const auto gs = 5U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg
        {
            constexpr const auto mask = 0x00000000003C0000UL;
            constexpr const auto from = 18;
            constexpr const auto name = "index_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace index_reg_invalid
        {
            constexpr const auto mask = 0x0000000000400000UL;
            constexpr const auto from = 22;
            constexpr const auto name = "index_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg
        {
            constexpr const auto mask = 0x0000000007800000UL;
            constexpr const auto from = 23;
            constexpr const auto name = "base_reg";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace base_reg_invalid
        {
            constexpr const auto mask = 0x0000000008000000UL;
            constexpr const auto from = 27;
            constexpr const auto name = "base_reg_invalid";

            constexpr const auto valid = 0U;
            constexpr const auto invalid = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reg2
        {
            constexpr const auto mask = 0x00000000F0000000UL;
            constexpr const auto from = 28;
            constexpr const auto name = "reg2";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }
}

}
}

// *INDENT-ON*

#endif
