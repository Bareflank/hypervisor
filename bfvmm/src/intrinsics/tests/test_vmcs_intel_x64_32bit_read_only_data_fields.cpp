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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_vmread).Do(test_vmread);
}

static std::map<uint64_t, const char *> vm_instruction_error_codes {
    {
        {1U, "VMCALL executed in VMX root operation"},
        {2U, "VMCLEAR with invalid physical address"},
        {3U, "VMCLEAR with VMXON pointer"},
        {4U, "VMLAUNCH with non-clear VMCS"},
        {5U, "VMRESUME with non-launched VMCS"},
        {6U, "VMRESUME after VMXOFF (VMXOFF AND VMXON between VMLAUNCH and VMRESUME)"},
        {7U, "VM entry with invalid control field(s)"},
        {8U, "VM entry with invalid host-state field(s)"},
        {9U, "VMPTRLD with invalid physical address"},
        {10U, "VMPTRLD with VMXON pointer"},
        {11U, "VMPTRLD with incorrect VMCS revision identifier"},
        {12U, "VMREAD/VMWRITE from/to unsupported VMCS component"},
        {13U, "VMWRITE to read-only VMCS component"},
        {15U, "VMXON executed in VMX root operation"},
        {16U, "VM entry with invalid executive-VMCS pointer"},
        {17U, "VM entry with non-launched executive VMCS"},
        {
            18U, "VM entry with executive-VMCS pointer not VMXON pointer "
            "(when attempting to deactivate the dual-monitor treatment of SMIs and SMM)"
        },
        {
            19U, "VMCALL with non-clear VMCS (when attempting to activate"
            " the dual-monitor treatment of SMIs and SMM)"
        },
        {20U, "VMCALL with invalid VM-exit control fields"},
        {
            22U, "VMCALL with incorrect MSEG revision identifier (when attempting "
            "to activate the dual-monitor treatment of SMIs and SMM)"
        },
        {23U, "VMXOFF under dual-monitor treatment of SMIs and SMM"},
        {
            24U, "VMCALL with invalid SMM-monitor features (when attempting to "
            "activate the dual-monitor treatment of SMIs and SMM)"
        },
        {
            25U, "VM entry with invalid VM-execution control fields in executive"
            " VMCS (when attempting to return from SMM)"
        },
        {26U, "VM entry with events blocked by MOV SS"},
        {28U, "Invalid operand to INVEPT/INVVPID"},
        {29U, "Unknown VM-instruction error"}
    }
};

static std::map<uint64_t, std::string> exit_reasons {
    {
        {vmcs::exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt, "exception_or_non_maskable_interrupt"_s},
        {vmcs::exit_reason::basic_exit_reason::external_interrupt, "external_interrupt"_s},
        {vmcs::exit_reason::basic_exit_reason::triple_fault, "triple_fault"_s},
        {vmcs::exit_reason::basic_exit_reason::init_signal, "init_signal"_s},
        {vmcs::exit_reason::basic_exit_reason::sipi, "sipi"_s},
        {vmcs::exit_reason::basic_exit_reason::smi, "smi"_s},
        {vmcs::exit_reason::basic_exit_reason::other_smi, "other_smi"_s},
        {vmcs::exit_reason::basic_exit_reason::interrupt_window, "interrupt_window"_s},
        {vmcs::exit_reason::basic_exit_reason::nmi_window, "nmi_window"_s},
        {vmcs::exit_reason::basic_exit_reason::task_switch, "task_switch"_s},
        {vmcs::exit_reason::basic_exit_reason::cpuid, "cpuid"_s},
        {vmcs::exit_reason::basic_exit_reason::getsec, "getsec"_s},
        {vmcs::exit_reason::basic_exit_reason::hlt, "hlt"_s},
        {vmcs::exit_reason::basic_exit_reason::invd, "invd"_s},
        {vmcs::exit_reason::basic_exit_reason::invlpg, "invlpg"_s},
        {vmcs::exit_reason::basic_exit_reason::rdpmc, "rdpmc"_s},
        {vmcs::exit_reason::basic_exit_reason::rdtsc, "rdtsc"_s},
        {vmcs::exit_reason::basic_exit_reason::rsm, "rsm"_s},
        {vmcs::exit_reason::basic_exit_reason::vmcall, "vmcall"_s},
        {vmcs::exit_reason::basic_exit_reason::vmclear, "vmclear"_s},
        {vmcs::exit_reason::basic_exit_reason::vmlaunch, "vmlaunch"_s},
        {vmcs::exit_reason::basic_exit_reason::vmptrld, "vmptrld"_s},
        {vmcs::exit_reason::basic_exit_reason::vmptrst, "vmptrst"_s},
        {vmcs::exit_reason::basic_exit_reason::vmread, "vmread"_s},
        {vmcs::exit_reason::basic_exit_reason::vmresume, "vmresume"_s},
        {vmcs::exit_reason::basic_exit_reason::vmwrite, "vmwrite"_s},
        {vmcs::exit_reason::basic_exit_reason::vmxoff, "vmxoff"_s},
        {vmcs::exit_reason::basic_exit_reason::vmxon, "vmxon"_s},
        {vmcs::exit_reason::basic_exit_reason::control_register_accesses, "control_register_accesses"_s},
        {vmcs::exit_reason::basic_exit_reason::mov_dr, "mov_dr"_s},
        {vmcs::exit_reason::basic_exit_reason::io_instruction, "io_instruction"_s},
        {vmcs::exit_reason::basic_exit_reason::rdmsr, "rdmsr"_s},
        {vmcs::exit_reason::basic_exit_reason::wrmsr, "wrmsr"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_invalid_guest_state, "vm_entry_failure_invalid_guest_state"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_msr_loading, "vm_entry_failure_msr_loading"_s},
        {vmcs::exit_reason::basic_exit_reason::mwait, "mwait"_s},
        {vmcs::exit_reason::basic_exit_reason::monitor_trap_flag, "monitor_trap_flag"_s},
        {vmcs::exit_reason::basic_exit_reason::monitor, "monitor"_s},
        {vmcs::exit_reason::basic_exit_reason::pause, "pause"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_machine_check_event, "vm_entry_failure_machine_check_event"_s},
        {vmcs::exit_reason::basic_exit_reason::tpr_below_threshold, "tpr_below_threshold"_s},
        {vmcs::exit_reason::basic_exit_reason::apic_access, "apic_access"_s},
        {vmcs::exit_reason::basic_exit_reason::virtualized_eoi, "virtualized_eoi"_s},
        {vmcs::exit_reason::basic_exit_reason::access_to_gdtr_or_idtr, "access_to_gdtr_or_idtr"_s},
        {vmcs::exit_reason::basic_exit_reason::access_to_ldtr_or_tr, "access_to_ldtr_or_tr"_s},
        {vmcs::exit_reason::basic_exit_reason::ept_violation, "ept_violation"_s},
        {vmcs::exit_reason::basic_exit_reason::ept_misconfiguration, "ept_misconfiguration"_s},
        {vmcs::exit_reason::basic_exit_reason::invept, "invept"_s},
        {vmcs::exit_reason::basic_exit_reason::rdtscp, "rdtscp"_s},
        {vmcs::exit_reason::basic_exit_reason::vmx_preemption_timer_expired, "vmx_preemption_timer_expired"_s},
        {vmcs::exit_reason::basic_exit_reason::invvpid, "invvpid"_s},
        {vmcs::exit_reason::basic_exit_reason::wbinvd, "wbinvd"_s},
        {vmcs::exit_reason::basic_exit_reason::xsetbv, "xsetbv"_s},
        {vmcs::exit_reason::basic_exit_reason::apic_write, "apic_write"_s},
        {vmcs::exit_reason::basic_exit_reason::rdrand, "rdrand"_s},
        {vmcs::exit_reason::basic_exit_reason::invpcid, "invpcid"_s},
        {vmcs::exit_reason::basic_exit_reason::vmfunc, "vmfunc"_s},
        {vmcs::exit_reason::basic_exit_reason::rdseed, "rdseed"_s},
        {vmcs::exit_reason::basic_exit_reason::xsaves, "xsaves"_s},
        {vmcs::exit_reason::basic_exit_reason::xrstors, "xrstors"_s},
        {0x0000BEEF, "unknown"_s}
    }
};

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_vm_instruction_error")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_instruction_error::exists());

    for (auto &&code : vm_instruction_error_codes) {
        g_vmcs_fields[vmcs::vm_instruction_error::addr] = code.first;
        CHECK(vmcs::vm_instruction_error::get() == code.first);
        CHECK(vmcs::vm_instruction_error::get_if_exists() == code.first);
        CHECK(vmcs::vm_instruction_error::description() == code.second);
        CHECK(vmcs::vm_instruction_error::description_if_exists() == code.second);
    }
}

TEST_CASE("vmcs_vm_instruction_error_description")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_instruction_error;

    CHECK_THROWS(vm_instruction_error_description(0UL, false));
    CHECK(vm_instruction_error_description(1UL,
                                           true) == "VMCALL executed in VMX root operation"_s);
}

TEST_CASE("vmcs_vm_instruction_error_description_if_exists")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_instruction_error;

    CHECK_NOTHROW(vm_instruction_error_description_if_exists(0UL, true, false));
    CHECK(vm_instruction_error_description_if_exists(0UL, true, false) == ""_s);
    CHECK(vm_instruction_error_description_if_exists(1UL, true,
            true) == "VMCALL executed in VMX root operation"_s);
}

TEST_CASE("vmcs_exit_reason")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::exit_reason::exists());

    g_vmcs_fields[vmcs::exit_reason::addr] = 1UL;
    CHECK(vmcs::exit_reason::get() == 1UL);

    g_vmcs_fields[vmcs::exit_reason::addr] = 2UL;
    CHECK(vmcs::exit_reason::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_exit_reason_basic_exit_reason")
{
    using namespace vmcs::exit_reason;

    for (auto &&reason : exit_reasons) {
        MockRepository mocks;
        setup_intrinsics(mocks);

        g_vmcs_fields[addr] = reason.first << basic_exit_reason::from;
        CHECK(basic_exit_reason::get() == reason.first);
        CHECK(basic_exit_reason::get_if_exists() == reason.first);
        CHECK(basic_exit_reason::description() == reason.second);
        CHECK(basic_exit_reason::description_if_exists() == reason.second);
    }
}

TEST_CASE("vmcs_exit_reason_basic_exit_reason_description")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    CHECK_THROWS(basic_exit_reason::basic_exit_reason_description(0UL, false));
    CHECK(basic_exit_reason::basic_exit_reason_description(40UL,
            true) == "pause"_s);
}

TEST_CASE("vmcs_exit_reason_basic_exit_reason_description_if_exists")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    CHECK_NOTHROW(basic_exit_reason::basic_exit_reason_description_if_exists(0UL, true, false));
    CHECK(basic_exit_reason::basic_exit_reason_description_if_exists(0UL, true,
            false) == ""_s);
    CHECK(basic_exit_reason::basic_exit_reason_description_if_exists(
              40UL, true, true) == "pause"_s);
}

TEST_CASE("vmcs_exit_reason_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = reserved::mask;
    CHECK(reserved::get() == reserved::mask >> reserved::from);
    CHECK(reserved::get_if_exists() == reserved::mask >> reserved::from);
}

TEST_CASE("vmcs_exit_reason_vm_exit_incident_to_enclave_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_incident_to_enclave_mode::is_disabled());
    CHECK(vm_exit_incident_to_enclave_mode::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_exit_incident_to_enclave_mode::mask;
    CHECK(vm_exit_incident_to_enclave_mode::is_enabled());
    CHECK(vm_exit_incident_to_enclave_mode::is_enabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_pending_mtf_vm_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    CHECK(pending_mtf_vm_exit::is_disabled());
    CHECK(pending_mtf_vm_exit::is_disabled_if_exists());

    g_vmcs_fields[addr] = pending_mtf_vm_exit::mask;
    CHECK(pending_mtf_vm_exit::is_enabled());
    CHECK(pending_mtf_vm_exit::is_enabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_vm_exit_from_vmx_root_operation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_from_vmx_root_operation::is_disabled());
    CHECK(vm_exit_from_vmx_root_operation::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_exit_from_vmx_root_operation::mask;
    CHECK(vm_exit_from_vmx_root_operation::is_enabled());
    CHECK(vm_exit_from_vmx_root_operation::is_enabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_vm_entry_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_entry_failure::is_disabled());
    CHECK(vm_entry_failure::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_entry_failure::mask;
    CHECK(vm_entry_failure::is_enabled());
    CHECK(vm_entry_failure::is_enabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::vm_exit_interruption_information::exists());

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 1UL;
    CHECK(vmcs::vm_exit_interruption_information::get() == 1UL);
    CHECK(vmcs::vm_exit_interruption_information::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_interruption_information_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    CHECK(vmcs::vm_exit_interruption_information::vector::get() == 0xFFUL);
    CHECK(vmcs::vm_exit_interruption_information::vector::get_if_exists() == 0xFFUL);
}

TEST_CASE("vmcs_vm_exit_interruption_information_interruption_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    CHECK(vmcs::vm_exit_interruption_information::interruption_type::get() == 7UL);
    CHECK(vmcs::vm_exit_interruption_information::interruption_type::get_if_exists() ==
          7UL);
}

TEST_CASE("vmcs_vm_exit_interruption_information_error_code_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    CHECK(vmcs::vm_exit_interruption_information::error_code_valid::is_enabled());
    CHECK(vmcs::vm_exit_interruption_information::error_code_valid::is_enabled_if_exists());

    CHECK_FALSE(vmcs::vm_exit_interruption_information::error_code_valid::is_disabled());
    CHECK_FALSE(
        vmcs::vm_exit_interruption_information::error_code_valid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information_nmi_blocking_due_to_iret")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0x1000UL;

    CHECK(vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_enabled());
    CHECK(
        vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_enabled_if_exists());

    CHECK_FALSE(
        vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_disabled());
    CHECK_FALSE(
        vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xEE000UL;

    CHECK(vmcs::vm_exit_interruption_information::reserved::get() == 0xEE000U);
    CHECK(vmcs::vm_exit_interruption_information::reserved::get_if_exists() == 0xEE000U);
}

TEST_CASE("vmcs_vm_exit_interruption_information_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0x80001000UL;

    CHECK(vmcs::vm_exit_interruption_information::valid_bit::is_enabled());
    CHECK(vmcs::vm_exit_interruption_information::valid_bit::is_enabled_if_exists());

    CHECK_FALSE(vmcs::vm_exit_interruption_information::valid_bit::is_disabled());
    CHECK_FALSE(vmcs::vm_exit_interruption_information::valid_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_interruption_error_code::addr] = 1UL;

    CHECK(vmcs::vm_exit_interruption_error_code::exists());
    CHECK(vmcs::vm_exit_interruption_error_code::get() == 1U);
    CHECK(vmcs::vm_exit_interruption_error_code::get_if_exists() == 1U);
}

TEST_CASE("vmcs_idt_vectoring_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 1UL;

    CHECK(vmcs::idt_vectoring_information::exists());
    CHECK(vmcs::idt_vectoring_information::get() == 1UL);
    CHECK(vmcs::idt_vectoring_information::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_idt_vectoring_information_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    CHECK(vmcs::idt_vectoring_information::vector::get() == 0xFFUL);
    CHECK(vmcs::idt_vectoring_information::vector::get_if_exists() == 0xFFUL);
}

TEST_CASE("vmcs_idt_vectoring_information_interruption_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    CHECK(vmcs::idt_vectoring_information::interruption_type::get() == 7UL);
    CHECK(vmcs::idt_vectoring_information::interruption_type::get_if_exists() == 7UL);
}

TEST_CASE("vmcs_idt_vectoring_information_error_code_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    CHECK(vmcs::idt_vectoring_information::error_code_valid::is_enabled());
    CHECK(vmcs::idt_vectoring_information::error_code_valid::is_enabled_if_exists());

    CHECK_FALSE(vmcs::idt_vectoring_information::error_code_valid::is_disabled());
    CHECK_FALSE(vmcs::idt_vectoring_information::error_code_valid::is_disabled_if_exists());
}

TEST_CASE("vmcs_idt_vectoring_information_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xEE000UL;

    CHECK(vmcs::idt_vectoring_information::reserved::get() == 0xEE000U);
    CHECK(vmcs::idt_vectoring_information::reserved::get_if_exists() == 0xEE000U);
}

TEST_CASE("vmcs_idt_vectoring_information_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0x80001000UL;

    CHECK(vmcs::idt_vectoring_information::valid_bit::is_enabled());
    CHECK(vmcs::idt_vectoring_information::valid_bit::is_enabled_if_exists());

    CHECK_FALSE(vmcs::idt_vectoring_information::valid_bit::is_disabled());
    CHECK_FALSE(vmcs::idt_vectoring_information::valid_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_idt_vectoring_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::idt_vectoring_error_code::addr] = 1UL;

    CHECK(vmcs::idt_vectoring_error_code::exists());
    CHECK(vmcs::idt_vectoring_error_code::get() == 1U);
    CHECK(vmcs::idt_vectoring_error_code::get_if_exists() == 1U);
}

TEST_CASE("vmcs_vm_exit_instruction_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_instruction_length::addr] = 1UL;

    CHECK(vmcs::vm_exit_instruction_length::exists());
    CHECK(vmcs::vm_exit_instruction_length::get() == 1U);
    CHECK(vmcs::vm_exit_instruction_length::get_if_exists() == 1U);
}

TEST_CASE("vmcs_vm_exit_instruction_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_vmcs_fields[vmcs::vm_exit_instruction_information::addr] = 1UL;

    CHECK(vmcs::vm_exit_instruction_information::exists());
    CHECK(vmcs::vm_exit_instruction_information::get() == 1UL);
    CHECK(vmcs::vm_exit_instruction_information::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ins")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(ins::get_name() == ins::name);
    CHECK(ins::get() == 1UL);
    CHECK(ins::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ins_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ins::address_size::_16bit << ins::address_size::from;
    CHECK(ins::address_size::get() == ins::address_size::_16bit);

    g_vmcs_fields[addr] = ins::address_size::_32bit << ins::address_size::from;
    CHECK(ins::address_size::get_if_exists() == ins::address_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(outs::get_name() == outs::name);
    CHECK(outs::get() == 1UL);
    CHECK(outs::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = outs::address_size::_16bit << outs::address_size::from;
    CHECK(outs::address_size::get() == outs::address_size::_16bit);

    g_vmcs_fields[addr] = outs::address_size::_32bit << outs::address_size::from;
    CHECK(outs::address_size::get_if_exists() == outs::address_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = outs::segment_register::ss << outs::segment_register::from;
    CHECK(outs::segment_register::get() == outs::segment_register::ss);

    g_vmcs_fields[addr] = outs::segment_register::cs << outs::segment_register::from;
    CHECK(outs::segment_register::get_if_exists() == outs::segment_register::cs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(invept::get_name() == invept::name);
    CHECK(invept::get() == 1UL);
    CHECK(invept::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::scaling::scale_by_2 << invept::scaling::from;
    CHECK(invept::scaling::get() == invept::scaling::scale_by_2);

    g_vmcs_fields[addr] = invept::scaling::scale_by_8 << invept::scaling::from;
    CHECK(invept::scaling::get_if_exists() == invept::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::address_size::_32bit << invept::address_size::from;
    CHECK(invept::address_size::get() == invept::address_size::_32bit);

    g_vmcs_fields[addr] = invept::address_size::_64bit << invept::address_size::from;
    CHECK(invept::address_size::get_if_exists() == invept::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::segment_register::cs << invept::segment_register::from;
    CHECK(invept::segment_register::get() == invept::segment_register::cs);

    g_vmcs_fields[addr] = invept::segment_register::gs << invept::segment_register::from;
    CHECK(invept::segment_register::get_if_exists() == invept::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::index_reg::rsi << invept::index_reg::from;
    CHECK(invept::index_reg::get() == invept::index_reg::rsi);

    g_vmcs_fields[addr] = invept::index_reg::r11 << invept::index_reg::from;
    CHECK(invept::index_reg::get_if_exists() == invept::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::index_reg_invalid::valid << invept::index_reg_invalid::from;
    CHECK(invept::index_reg_invalid::get() == invept::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invept::index_reg_invalid::invalid << invept::index_reg_invalid::from;
    CHECK(invept::index_reg_invalid::get_if_exists() == invept::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::base_reg::rdi << invept::base_reg::from;
    CHECK(invept::base_reg::get() == invept::base_reg::rdi);

    g_vmcs_fields[addr] = invept::base_reg::rcx << invept::base_reg::from;
    CHECK(invept::base_reg::get_if_exists() == invept::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::base_reg_invalid::valid << invept::base_reg_invalid::from;
    CHECK(invept::base_reg_invalid::get() == invept::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invept::base_reg_invalid::invalid << invept::base_reg_invalid::from;
    CHECK(invept::base_reg_invalid::get_if_exists() == invept::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::reg2::rdx << invept::reg2::from;
    CHECK(invept::reg2::get() == invept::reg2::rdx);

    g_vmcs_fields[addr] = invept::reg2::rsp << invept::reg2::from;
    CHECK(invept::reg2::get_if_exists() == invept::reg2::rsp);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(invpcid::get_name() == invpcid::name);
    CHECK(invpcid::get() == 1UL);
    CHECK(invpcid::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::scaling::scale_by_2 << invpcid::scaling::from;
    CHECK(invpcid::scaling::get() == invpcid::scaling::scale_by_2);

    g_vmcs_fields[addr] = invpcid::scaling::scale_by_8 << invpcid::scaling::from;
    CHECK(invpcid::scaling::get_if_exists() == invpcid::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::address_size::_32bit << invpcid::address_size::from;
    CHECK(invpcid::address_size::get() == invpcid::address_size::_32bit);

    g_vmcs_fields[addr] = invpcid::address_size::_64bit << invpcid::address_size::from;
    CHECK(invpcid::address_size::get_if_exists() == invpcid::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::segment_register::cs << invpcid::segment_register::from;
    CHECK(invpcid::segment_register::get() == invpcid::segment_register::cs);

    g_vmcs_fields[addr] = invpcid::segment_register::gs << invpcid::segment_register::from;
    CHECK(invpcid::segment_register::get_if_exists() == invpcid::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::index_reg::rsi << invpcid::index_reg::from;
    CHECK(invpcid::index_reg::get() == invpcid::index_reg::rsi);

    g_vmcs_fields[addr] = invpcid::index_reg::r11 << invpcid::index_reg::from;
    CHECK(invpcid::index_reg::get_if_exists() == invpcid::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::valid << invpcid::index_reg_invalid::from;
    CHECK(invpcid::index_reg_invalid::get() == invpcid::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::invalid << invpcid::index_reg_invalid::from;
    CHECK(invpcid::index_reg_invalid::get_if_exists() ==
          invpcid::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::base_reg::rdi << invpcid::base_reg::from;
    CHECK(invpcid::base_reg::get() == invpcid::base_reg::rdi);

    g_vmcs_fields[addr] = invpcid::base_reg::rcx << invpcid::base_reg::from;
    CHECK(invpcid::base_reg::get_if_exists() == invpcid::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::valid << invpcid::base_reg_invalid::from;
    CHECK(invpcid::base_reg_invalid::get() == invpcid::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::invalid << invpcid::base_reg_invalid::from;
    CHECK(invpcid::base_reg_invalid::get_if_exists() == invpcid::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::reg2::rdx << invpcid::reg2::from;
    CHECK(invpcid::reg2::get() == invpcid::reg2::rdx);

    g_vmcs_fields[addr] = invpcid::reg2::rsp << invpcid::reg2::from;
    CHECK(invpcid::reg2::get_if_exists() == invpcid::reg2::rsp);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(invvpid::get_name() == invvpid::name);
    CHECK(invvpid::get() == 1UL);
    CHECK(invvpid::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::scaling::scale_by_2 << invvpid::scaling::from;
    CHECK(invvpid::scaling::get() == invvpid::scaling::scale_by_2);

    g_vmcs_fields[addr] = invvpid::scaling::scale_by_8 << invvpid::scaling::from;
    CHECK(invvpid::scaling::get_if_exists() == invvpid::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::address_size::_32bit << invvpid::address_size::from;
    CHECK(invvpid::address_size::get() == invvpid::address_size::_32bit);

    g_vmcs_fields[addr] = invvpid::address_size::_64bit << invvpid::address_size::from;
    CHECK(invvpid::address_size::get_if_exists() == invvpid::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::segment_register::cs << invvpid::segment_register::from;
    CHECK(invvpid::segment_register::get() == invvpid::segment_register::cs);

    g_vmcs_fields[addr] = invvpid::segment_register::gs << invvpid::segment_register::from;
    CHECK(invvpid::segment_register::get_if_exists() == invvpid::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::index_reg::rsi << invvpid::index_reg::from;
    CHECK(invvpid::index_reg::get() == invvpid::index_reg::rsi);

    g_vmcs_fields[addr] = invvpid::index_reg::r11 << invvpid::index_reg::from;
    CHECK(invvpid::index_reg::get_if_exists() == invvpid::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::valid << invvpid::index_reg_invalid::from;
    CHECK(invvpid::index_reg_invalid::get() == invvpid::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::invalid << invvpid::index_reg_invalid::from;
    CHECK(invvpid::index_reg_invalid::get_if_exists() ==
          invvpid::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::base_reg::rdi << invvpid::base_reg::from;
    CHECK(invvpid::base_reg::get() == invvpid::base_reg::rdi);

    g_vmcs_fields[addr] = invvpid::base_reg::rcx << invvpid::base_reg::from;
    CHECK(invvpid::base_reg::get_if_exists() == invvpid::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::valid << invvpid::base_reg_invalid::from;
    CHECK(invvpid::base_reg_invalid::get() == invvpid::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::invalid << invvpid::base_reg_invalid::from;
    CHECK(invvpid::base_reg_invalid::get_if_exists() == invvpid::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::reg2::rdx << invvpid::reg2::from;
    CHECK(invvpid::reg2::get() == invvpid::reg2::rdx);

    g_vmcs_fields[addr] = invvpid::reg2::rsp << invvpid::reg2::from;
    CHECK(invvpid::reg2::get_if_exists() == invvpid::reg2::rsp);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(lidt::get_name() == lidt::name);
    CHECK(lidt::get() == 1UL);
    CHECK(lidt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::scaling::scale_by_2 << lidt::scaling::from;
    CHECK(lidt::scaling::get() == lidt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lidt::scaling::scale_by_8 << lidt::scaling::from;
    CHECK(lidt::scaling::get_if_exists() == lidt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::address_size::_32bit << lidt::address_size::from;
    CHECK(lidt::address_size::get() == lidt::address_size::_32bit);

    g_vmcs_fields[addr] = lidt::address_size::_64bit << lidt::address_size::from;
    CHECK(lidt::address_size::get_if_exists() == lidt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::operand_size::_16bit << lidt::operand_size::from;
    CHECK(lidt::operand_size::get() == lidt::operand_size::_16bit);

    g_vmcs_fields[addr] = lidt::operand_size::_32bit << lidt::operand_size::from;
    CHECK(lidt::operand_size::get_if_exists() == lidt::operand_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::segment_register::cs << lidt::segment_register::from;
    CHECK(lidt::segment_register::get() == lidt::segment_register::cs);

    g_vmcs_fields[addr] = lidt::segment_register::gs << lidt::segment_register::from;
    CHECK(lidt::segment_register::get_if_exists() == lidt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::index_reg::rsi << lidt::index_reg::from;
    CHECK(lidt::index_reg::get() == lidt::index_reg::rsi);

    g_vmcs_fields[addr] = lidt::index_reg::r11 << lidt::index_reg::from;
    CHECK(lidt::index_reg::get_if_exists() == lidt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::index_reg_invalid::valid << lidt::index_reg_invalid::from;
    CHECK(lidt::index_reg_invalid::get() == lidt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lidt::index_reg_invalid::invalid << lidt::index_reg_invalid::from;
    CHECK(lidt::index_reg_invalid::get_if_exists() == lidt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::base_reg::rdi << lidt::base_reg::from;
    CHECK(lidt::base_reg::get() == lidt::base_reg::rdi);

    g_vmcs_fields[addr] = lidt::base_reg::rcx << lidt::base_reg::from;
    CHECK(lidt::base_reg::get_if_exists() == lidt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::base_reg_invalid::valid << lidt::base_reg_invalid::from;
    CHECK(lidt::base_reg_invalid::get() == lidt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lidt::base_reg_invalid::invalid << lidt::base_reg_invalid::from;
    CHECK(lidt::base_reg_invalid::get_if_exists() == lidt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::instruction_identity::sgdt << lidt::instruction_identity::from;
    CHECK(lidt::instruction_identity::get() == lidt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = lidt::instruction_identity::lidt << lidt::instruction_identity::from;
    CHECK(lidt::instruction_identity::get_if_exists() == lidt::instruction_identity::lidt);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(lgdt::get_name() == lgdt::name);
    CHECK(lgdt::get() == 1UL);
    CHECK(lgdt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::scaling::scale_by_2 << lgdt::scaling::from;
    CHECK(lgdt::scaling::get() == lgdt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lgdt::scaling::scale_by_8 << lgdt::scaling::from;
    CHECK(lgdt::scaling::get_if_exists() == lgdt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::address_size::_32bit << lgdt::address_size::from;
    CHECK(lgdt::address_size::get() == lgdt::address_size::_32bit);

    g_vmcs_fields[addr] = lgdt::address_size::_64bit << lgdt::address_size::from;
    CHECK(lgdt::address_size::get_if_exists() == lgdt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::operand_size::_16bit << lgdt::operand_size::from;
    CHECK(lgdt::operand_size::get() == lgdt::operand_size::_16bit);

    g_vmcs_fields[addr] = lgdt::operand_size::_32bit << lgdt::operand_size::from;
    CHECK(lgdt::operand_size::get_if_exists() == lgdt::operand_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::segment_register::cs << lgdt::segment_register::from;
    CHECK(lgdt::segment_register::get() == lgdt::segment_register::cs);

    g_vmcs_fields[addr] = lgdt::segment_register::gs << lgdt::segment_register::from;
    CHECK(lgdt::segment_register::get_if_exists() == lgdt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::index_reg::rsi << lgdt::index_reg::from;
    CHECK(lgdt::index_reg::get() == lgdt::index_reg::rsi);

    g_vmcs_fields[addr] = lgdt::index_reg::r11 << lgdt::index_reg::from;
    CHECK(lgdt::index_reg::get_if_exists() == lgdt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::valid << lgdt::index_reg_invalid::from;
    CHECK(lgdt::index_reg_invalid::get() == lgdt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::invalid << lgdt::index_reg_invalid::from;
    CHECK(lgdt::index_reg_invalid::get_if_exists() == lgdt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::base_reg::rdi << lgdt::base_reg::from;
    CHECK(lgdt::base_reg::get() == lgdt::base_reg::rdi);

    g_vmcs_fields[addr] = lgdt::base_reg::rcx << lgdt::base_reg::from;
    CHECK(lgdt::base_reg::get_if_exists() == lgdt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::valid << lgdt::base_reg_invalid::from;
    CHECK(lgdt::base_reg_invalid::get() == lgdt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::invalid << lgdt::base_reg_invalid::from;
    CHECK(lgdt::base_reg_invalid::get_if_exists() == lgdt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::instruction_identity::sgdt << lgdt::instruction_identity::from;
    CHECK(lgdt::instruction_identity::get() == lgdt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = lgdt::instruction_identity::lgdt << lgdt::instruction_identity::from;
    CHECK(lgdt::instruction_identity::get_if_exists() == lgdt::instruction_identity::lgdt);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(sidt::get_name() == sidt::name);
    CHECK(sidt::get() == 1UL);
    CHECK(sidt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::scaling::scale_by_2 << sidt::scaling::from;
    CHECK(sidt::scaling::get() == sidt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sidt::scaling::scale_by_8 << sidt::scaling::from;
    CHECK(sidt::scaling::get_if_exists() == sidt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::address_size::_32bit << sidt::address_size::from;
    CHECK(sidt::address_size::get() == sidt::address_size::_32bit);

    g_vmcs_fields[addr] = sidt::address_size::_64bit << sidt::address_size::from;
    CHECK(sidt::address_size::get_if_exists() == sidt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::operand_size::_16bit << sidt::operand_size::from;
    CHECK(sidt::operand_size::get() == sidt::operand_size::_16bit);

    g_vmcs_fields[addr] = sidt::operand_size::_32bit << sidt::operand_size::from;
    CHECK(sidt::operand_size::get_if_exists() == sidt::operand_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::segment_register::cs << sidt::segment_register::from;
    CHECK(sidt::segment_register::get() == sidt::segment_register::cs);

    g_vmcs_fields[addr] = sidt::segment_register::gs << sidt::segment_register::from;
    CHECK(sidt::segment_register::get_if_exists() == sidt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::index_reg::rsi << sidt::index_reg::from;
    CHECK(sidt::index_reg::get() == sidt::index_reg::rsi);

    g_vmcs_fields[addr] = sidt::index_reg::r11 << sidt::index_reg::from;
    CHECK(sidt::index_reg::get_if_exists() == sidt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::index_reg_invalid::valid << sidt::index_reg_invalid::from;
    CHECK(sidt::index_reg_invalid::get() == sidt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sidt::index_reg_invalid::invalid << sidt::index_reg_invalid::from;
    CHECK(sidt::index_reg_invalid::get_if_exists() == sidt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::base_reg::rdi << sidt::base_reg::from;
    CHECK(sidt::base_reg::get() == sidt::base_reg::rdi);

    g_vmcs_fields[addr] = sidt::base_reg::rcx << sidt::base_reg::from;
    CHECK(sidt::base_reg::get_if_exists() == sidt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::base_reg_invalid::valid << sidt::base_reg_invalid::from;
    CHECK(sidt::base_reg_invalid::get() == sidt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sidt::base_reg_invalid::invalid << sidt::base_reg_invalid::from;
    CHECK(sidt::base_reg_invalid::get_if_exists() == sidt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::instruction_identity::sgdt << sidt::instruction_identity::from;
    CHECK(sidt::instruction_identity::get() == sidt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = sidt::instruction_identity::sidt << sidt::instruction_identity::from;
    CHECK(sidt::instruction_identity::get_if_exists() == sidt::instruction_identity::sidt);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(sgdt::get_name() == sgdt::name);
    CHECK(sgdt::get() == 1UL);
    CHECK(sgdt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::scaling::scale_by_2 << sgdt::scaling::from;
    CHECK(sgdt::scaling::get() == sgdt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sgdt::scaling::scale_by_8 << sgdt::scaling::from;
    CHECK(sgdt::scaling::get_if_exists() == sgdt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::address_size::_32bit << sgdt::address_size::from;
    CHECK(sgdt::address_size::get() == sgdt::address_size::_32bit);

    g_vmcs_fields[addr] = sgdt::address_size::_64bit << sgdt::address_size::from;
    CHECK(sgdt::address_size::get_if_exists() == sgdt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::operand_size::_16bit << sgdt::operand_size::from;
    CHECK(sgdt::operand_size::get() == sgdt::operand_size::_16bit);

    g_vmcs_fields[addr] = sgdt::operand_size::_32bit << sgdt::operand_size::from;
    CHECK(sgdt::operand_size::get_if_exists() == sgdt::operand_size::_32bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::segment_register::cs << sgdt::segment_register::from;
    CHECK(sgdt::segment_register::get() == sgdt::segment_register::cs);

    g_vmcs_fields[addr] = sgdt::segment_register::gs << sgdt::segment_register::from;
    CHECK(sgdt::segment_register::get_if_exists() == sgdt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::index_reg::rsi << sgdt::index_reg::from;
    CHECK(sgdt::index_reg::get() == sgdt::index_reg::rsi);

    g_vmcs_fields[addr] = sgdt::index_reg::r11 << sgdt::index_reg::from;
    CHECK(sgdt::index_reg::get_if_exists() == sgdt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::valid << sgdt::index_reg_invalid::from;
    CHECK(sgdt::index_reg_invalid::get() == sgdt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::invalid << sgdt::index_reg_invalid::from;
    CHECK(sgdt::index_reg_invalid::get_if_exists() == sgdt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::base_reg::rdi << sgdt::base_reg::from;
    CHECK(sgdt::base_reg::get() == sgdt::base_reg::rdi);

    g_vmcs_fields[addr] = sgdt::base_reg::rcx << sgdt::base_reg::from;
    CHECK(sgdt::base_reg::get_if_exists() == sgdt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::valid << sgdt::base_reg_invalid::from;
    CHECK(sgdt::base_reg_invalid::get() == sgdt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::invalid << sgdt::base_reg_invalid::from;
    CHECK(sgdt::base_reg_invalid::get_if_exists() == sgdt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::instruction_identity::sgdt << sgdt::instruction_identity::from;
    CHECK(sgdt::instruction_identity::get() == sgdt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = sgdt::instruction_identity::sgdt << sgdt::instruction_identity::from;
    CHECK(sgdt::instruction_identity::get_if_exists() == sgdt::instruction_identity::sgdt);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(lldt::get_name() == lldt::name);
    CHECK(lldt::get() == 1UL);
    CHECK(lldt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::scaling::scale_by_2 << lldt::scaling::from;
    CHECK(lldt::scaling::get() == lldt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lldt::scaling::scale_by_8 << lldt::scaling::from;
    CHECK(lldt::scaling::get_if_exists() == lldt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::reg1::rbp << lldt::reg1::from;
    CHECK(lldt::reg1::get() == lldt::reg1::rbp);

    g_vmcs_fields[addr] = lldt::reg1::r13 << lldt::reg1::from;
    CHECK(lldt::reg1::get_if_exists() == lldt::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::address_size::_32bit << lldt::address_size::from;
    CHECK(lldt::address_size::get() == lldt::address_size::_32bit);

    g_vmcs_fields[addr] = lldt::address_size::_64bit << lldt::address_size::from;
    CHECK(lldt::address_size::get_if_exists() == lldt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::mem_reg::mem << lldt::mem_reg::from;
    CHECK(lldt::mem_reg::get() == lldt::mem_reg::mem);

    g_vmcs_fields[addr] = lldt::mem_reg::reg << lldt::mem_reg::from;
    CHECK(lldt::mem_reg::get_if_exists() == lldt::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::segment_register::cs << lldt::segment_register::from;
    CHECK(lldt::segment_register::get() == lldt::segment_register::cs);

    g_vmcs_fields[addr] = lldt::segment_register::gs << lldt::segment_register::from;
    CHECK(lldt::segment_register::get_if_exists() == lldt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::index_reg::rsi << lldt::index_reg::from;
    CHECK(lldt::index_reg::get() == lldt::index_reg::rsi);

    g_vmcs_fields[addr] = lldt::index_reg::r11 << lldt::index_reg::from;
    CHECK(lldt::index_reg::get_if_exists() == lldt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::index_reg_invalid::valid << lldt::index_reg_invalid::from;
    CHECK(lldt::index_reg_invalid::get() == lldt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lldt::index_reg_invalid::invalid << lldt::index_reg_invalid::from;
    CHECK(lldt::index_reg_invalid::get_if_exists() == lldt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::base_reg::rdi << lldt::base_reg::from;
    CHECK(lldt::base_reg::get() == lldt::base_reg::rdi);

    g_vmcs_fields[addr] = lldt::base_reg::rcx << lldt::base_reg::from;
    CHECK(lldt::base_reg::get_if_exists() == lldt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::base_reg_invalid::valid << lldt::base_reg_invalid::from;
    CHECK(lldt::base_reg_invalid::get() == lldt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lldt::base_reg_invalid::invalid << lldt::base_reg_invalid::from;
    CHECK(lldt::base_reg_invalid::get_if_exists() == lldt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::instruction_identity::sldt << lldt::instruction_identity::from;
    CHECK(lldt::instruction_identity::get() == lldt::instruction_identity::sldt);

    g_vmcs_fields[addr] = lldt::instruction_identity::lldt << lldt::instruction_identity::from;
    CHECK(lldt::instruction_identity::get_if_exists() == lldt::instruction_identity::lldt);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(ltr::get_name() == ltr::name);
    CHECK(ltr::get() == 1UL);
    CHECK(ltr::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::scaling::scale_by_2 << ltr::scaling::from;
    CHECK(ltr::scaling::get() == ltr::scaling::scale_by_2);

    g_vmcs_fields[addr] = ltr::scaling::scale_by_8 << ltr::scaling::from;
    CHECK(ltr::scaling::get_if_exists() == ltr::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::reg1::rbp << ltr::reg1::from;
    CHECK(ltr::reg1::get() == ltr::reg1::rbp);

    g_vmcs_fields[addr] = ltr::reg1::r13 << ltr::reg1::from;
    CHECK(ltr::reg1::get_if_exists() == ltr::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::address_size::_32bit << ltr::address_size::from;
    CHECK(ltr::address_size::get() == ltr::address_size::_32bit);

    g_vmcs_fields[addr] = ltr::address_size::_64bit << ltr::address_size::from;
    CHECK(ltr::address_size::get_if_exists() == ltr::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::mem_reg::mem << ltr::mem_reg::from;
    CHECK(ltr::mem_reg::get() == ltr::mem_reg::mem);

    g_vmcs_fields[addr] = ltr::mem_reg::reg << ltr::mem_reg::from;
    CHECK(ltr::mem_reg::get_if_exists() == ltr::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::segment_register::cs << ltr::segment_register::from;
    CHECK(ltr::segment_register::get() == ltr::segment_register::cs);

    g_vmcs_fields[addr] = ltr::segment_register::gs << ltr::segment_register::from;
    CHECK(ltr::segment_register::get_if_exists() == ltr::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::index_reg::rsi << ltr::index_reg::from;
    CHECK(ltr::index_reg::get() == ltr::index_reg::rsi);

    g_vmcs_fields[addr] = ltr::index_reg::r11 << ltr::index_reg::from;
    CHECK(ltr::index_reg::get_if_exists() == ltr::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::index_reg_invalid::valid << ltr::index_reg_invalid::from;
    CHECK(ltr::index_reg_invalid::get() == ltr::index_reg_invalid::valid);

    g_vmcs_fields[addr] = ltr::index_reg_invalid::invalid << ltr::index_reg_invalid::from;
    CHECK(ltr::index_reg_invalid::get_if_exists() == ltr::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::base_reg::rdi << ltr::base_reg::from;
    CHECK(ltr::base_reg::get() == ltr::base_reg::rdi);

    g_vmcs_fields[addr] = ltr::base_reg::rcx << ltr::base_reg::from;
    CHECK(ltr::base_reg::get_if_exists() == ltr::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::base_reg_invalid::valid << ltr::base_reg_invalid::from;
    CHECK(ltr::base_reg_invalid::get() == ltr::base_reg_invalid::valid);

    g_vmcs_fields[addr] = ltr::base_reg_invalid::invalid << ltr::base_reg_invalid::from;
    CHECK(ltr::base_reg_invalid::get_if_exists() == ltr::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::instruction_identity::sldt << ltr::instruction_identity::from;
    CHECK(ltr::instruction_identity::get() == ltr::instruction_identity::sldt);

    g_vmcs_fields[addr] = ltr::instruction_identity::ltr << ltr::instruction_identity::from;
    CHECK(ltr::instruction_identity::get_if_exists() == ltr::instruction_identity::ltr);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(sldt::get_name() == sldt::name);
    CHECK(sldt::get() == 1UL);
    CHECK(sldt::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::scaling::scale_by_2 << sldt::scaling::from;
    CHECK(sldt::scaling::get() == sldt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sldt::scaling::scale_by_8 << sldt::scaling::from;
    CHECK(sldt::scaling::get_if_exists() == sldt::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::reg1::rbp << sldt::reg1::from;
    CHECK(sldt::reg1::get() == sldt::reg1::rbp);

    g_vmcs_fields[addr] = sldt::reg1::r13 << sldt::reg1::from;
    CHECK(sldt::reg1::get_if_exists() == sldt::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::address_size::_32bit << sldt::address_size::from;
    CHECK(sldt::address_size::get() == sldt::address_size::_32bit);

    g_vmcs_fields[addr] = sldt::address_size::_64bit << sldt::address_size::from;
    CHECK(sldt::address_size::get_if_exists() == sldt::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::mem_reg::mem << sldt::mem_reg::from;
    CHECK(sldt::mem_reg::get() == sldt::mem_reg::mem);

    g_vmcs_fields[addr] = sldt::mem_reg::reg << sldt::mem_reg::from;
    CHECK(sldt::mem_reg::get_if_exists() == sldt::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::segment_register::cs << sldt::segment_register::from;
    CHECK(sldt::segment_register::get() == sldt::segment_register::cs);

    g_vmcs_fields[addr] = sldt::segment_register::gs << sldt::segment_register::from;
    CHECK(sldt::segment_register::get_if_exists() == sldt::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::index_reg::rsi << sldt::index_reg::from;
    CHECK(sldt::index_reg::get() == sldt::index_reg::rsi);

    g_vmcs_fields[addr] = sldt::index_reg::r11 << sldt::index_reg::from;
    CHECK(sldt::index_reg::get_if_exists() == sldt::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::index_reg_invalid::valid << sldt::index_reg_invalid::from;
    CHECK(sldt::index_reg_invalid::get() == sldt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sldt::index_reg_invalid::invalid << sldt::index_reg_invalid::from;
    CHECK(sldt::index_reg_invalid::get_if_exists() == sldt::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::base_reg::rdi << sldt::base_reg::from;
    CHECK(sldt::base_reg::get() == sldt::base_reg::rdi);

    g_vmcs_fields[addr] = sldt::base_reg::rcx << sldt::base_reg::from;
    CHECK(sldt::base_reg::get_if_exists() == sldt::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::base_reg_invalid::valid << sldt::base_reg_invalid::from;
    CHECK(sldt::base_reg_invalid::get() == sldt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sldt::base_reg_invalid::invalid << sldt::base_reg_invalid::from;
    CHECK(sldt::base_reg_invalid::get_if_exists() == sldt::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::instruction_identity::sldt << sldt::instruction_identity::from;
    CHECK(sldt::instruction_identity::get() == sldt::instruction_identity::sldt);

    g_vmcs_fields[addr] = sldt::instruction_identity::ltr << sldt::instruction_identity::from;
    CHECK(sldt::instruction_identity::get_if_exists() == sldt::instruction_identity::ltr);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(str::get_name() == str::name);
    CHECK(str::get() == 1UL);
    CHECK(str::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::scaling::scale_by_2 << str::scaling::from;
    CHECK(str::scaling::get() == str::scaling::scale_by_2);

    g_vmcs_fields[addr] = str::scaling::scale_by_8 << str::scaling::from;
    CHECK(str::scaling::get_if_exists() == str::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::reg1::rbp << str::reg1::from;
    CHECK(str::reg1::get() == str::reg1::rbp);

    g_vmcs_fields[addr] = str::reg1::r13 << str::reg1::from;
    CHECK(str::reg1::get_if_exists() == str::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::address_size::_32bit << str::address_size::from;
    CHECK(str::address_size::get() == str::address_size::_32bit);

    g_vmcs_fields[addr] = str::address_size::_64bit << str::address_size::from;
    CHECK(str::address_size::get_if_exists() == str::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::mem_reg::mem << str::mem_reg::from;
    CHECK(str::mem_reg::get() == str::mem_reg::mem);

    g_vmcs_fields[addr] = str::mem_reg::reg << str::mem_reg::from;
    CHECK(str::mem_reg::get_if_exists() == str::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::segment_register::cs << str::segment_register::from;
    CHECK(str::segment_register::get() == str::segment_register::cs);

    g_vmcs_fields[addr] = str::segment_register::gs << str::segment_register::from;
    CHECK(str::segment_register::get_if_exists() == str::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::index_reg::rsi << str::index_reg::from;
    CHECK(str::index_reg::get() == str::index_reg::rsi);

    g_vmcs_fields[addr] = str::index_reg::r11 << str::index_reg::from;
    CHECK(str::index_reg::get_if_exists() == str::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::index_reg_invalid::valid << str::index_reg_invalid::from;
    CHECK(str::index_reg_invalid::get() == str::index_reg_invalid::valid);

    g_vmcs_fields[addr] = str::index_reg_invalid::invalid << str::index_reg_invalid::from;
    CHECK(str::index_reg_invalid::get_if_exists() == str::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::base_reg::rdi << str::base_reg::from;
    CHECK(str::base_reg::get() == str::base_reg::rdi);

    g_vmcs_fields[addr] = str::base_reg::rcx << str::base_reg::from;
    CHECK(str::base_reg::get_if_exists() == str::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::base_reg_invalid::valid << str::base_reg_invalid::from;
    CHECK(str::base_reg_invalid::get() == str::base_reg_invalid::valid);

    g_vmcs_fields[addr] = str::base_reg_invalid::invalid << str::base_reg_invalid::from;
    CHECK(str::base_reg_invalid::get_if_exists() == str::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::instruction_identity::sldt << str::instruction_identity::from;
    CHECK(str::instruction_identity::get() == str::instruction_identity::sldt);

    g_vmcs_fields[addr] = str::instruction_identity::str << str::instruction_identity::from;
    CHECK(str::instruction_identity::get_if_exists() == str::instruction_identity::str);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(rdrand::get_name() == rdrand::name);
    CHECK(rdrand::get() == 1UL);
    CHECK(rdrand::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand_destination_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdrand::destination_register::rdx << rdrand::destination_register::from;
    CHECK(rdrand::destination_register::get() == rdrand::destination_register::rdx);

    g_vmcs_fields[addr] = rdrand::destination_register::r14 << rdrand::destination_register::from;
    CHECK(rdrand::destination_register::get_if_exists() ==
          rdrand::destination_register::r14);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdrand::operand_size::_16bit << rdrand::operand_size::from;
    CHECK(rdrand::operand_size::get() == rdrand::operand_size::_16bit);

    g_vmcs_fields[addr] = rdrand::operand_size::_64bit << rdrand::operand_size::from;
    CHECK(rdrand::operand_size::get_if_exists() == rdrand::operand_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(rdseed::get_name() == rdseed::name);
    CHECK(rdseed::get() == 1UL);
    CHECK(rdseed::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed_destination_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdseed::destination_register::rdx << rdseed::destination_register::from;
    CHECK(rdseed::destination_register::get() == rdseed::destination_register::rdx);

    g_vmcs_fields[addr] = rdseed::destination_register::r14 << rdseed::destination_register::from;
    CHECK(rdseed::destination_register::get_if_exists() ==
          rdseed::destination_register::r14);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdseed::operand_size::_16bit << rdseed::operand_size::from;
    CHECK(rdseed::operand_size::get() == rdseed::operand_size::_16bit);

    g_vmcs_fields[addr] = rdseed::operand_size::_64bit << rdseed::operand_size::from;
    CHECK(rdseed::operand_size::get_if_exists() == rdseed::operand_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmclear::get_name() == vmclear::name);
    CHECK(vmclear::get() == 1UL);
    CHECK(vmclear::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::scaling::scale_by_2 << vmclear::scaling::from;
    CHECK(vmclear::scaling::get() == vmclear::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmclear::scaling::scale_by_8 << vmclear::scaling::from;
    CHECK(vmclear::scaling::get_if_exists() == vmclear::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::address_size::_32bit << vmclear::address_size::from;
    CHECK(vmclear::address_size::get() == vmclear::address_size::_32bit);

    g_vmcs_fields[addr] = vmclear::address_size::_64bit << vmclear::address_size::from;
    CHECK(vmclear::address_size::get_if_exists() == vmclear::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::segment_register::cs << vmclear::segment_register::from;
    CHECK(vmclear::segment_register::get() == vmclear::segment_register::cs);

    g_vmcs_fields[addr] = vmclear::segment_register::gs << vmclear::segment_register::from;
    CHECK(vmclear::segment_register::get_if_exists() == vmclear::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::index_reg::rsi << vmclear::index_reg::from;
    CHECK(vmclear::index_reg::get() == vmclear::index_reg::rsi);

    g_vmcs_fields[addr] = vmclear::index_reg::r11 << vmclear::index_reg::from;
    CHECK(vmclear::index_reg::get_if_exists() == vmclear::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::valid << vmclear::index_reg_invalid::from;
    CHECK(vmclear::index_reg_invalid::get() == vmclear::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::invalid << vmclear::index_reg_invalid::from;
    CHECK(vmclear::index_reg_invalid::get_if_exists() ==
          vmclear::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::base_reg::rdi << vmclear::base_reg::from;
    CHECK(vmclear::base_reg::get() == vmclear::base_reg::rdi);

    g_vmcs_fields[addr] = vmclear::base_reg::rcx << vmclear::base_reg::from;
    CHECK(vmclear::base_reg::get_if_exists() == vmclear::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::valid << vmclear::base_reg_invalid::from;
    CHECK(vmclear::base_reg_invalid::get() == vmclear::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::invalid << vmclear::base_reg_invalid::from;
    CHECK(vmclear::base_reg_invalid::get_if_exists() == vmclear::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmptrld::get_name() == vmptrld::name);
    CHECK(vmptrld::get() == 1UL);
    CHECK(vmptrld::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::scaling::scale_by_2 << vmptrld::scaling::from;
    CHECK(vmptrld::scaling::get() == vmptrld::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmptrld::scaling::scale_by_8 << vmptrld::scaling::from;
    CHECK(vmptrld::scaling::get_if_exists() == vmptrld::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::address_size::_32bit << vmptrld::address_size::from;
    CHECK(vmptrld::address_size::get() == vmptrld::address_size::_32bit);

    g_vmcs_fields[addr] = vmptrld::address_size::_64bit << vmptrld::address_size::from;
    CHECK(vmptrld::address_size::get_if_exists() == vmptrld::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::segment_register::cs << vmptrld::segment_register::from;
    CHECK(vmptrld::segment_register::get() == vmptrld::segment_register::cs);

    g_vmcs_fields[addr] = vmptrld::segment_register::gs << vmptrld::segment_register::from;
    CHECK(vmptrld::segment_register::get_if_exists() == vmptrld::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::index_reg::rsi << vmptrld::index_reg::from;
    CHECK(vmptrld::index_reg::get() == vmptrld::index_reg::rsi);

    g_vmcs_fields[addr] = vmptrld::index_reg::r11 << vmptrld::index_reg::from;
    CHECK(vmptrld::index_reg::get_if_exists() == vmptrld::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::valid << vmptrld::index_reg_invalid::from;
    CHECK(vmptrld::index_reg_invalid::get() == vmptrld::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::invalid << vmptrld::index_reg_invalid::from;
    CHECK(vmptrld::index_reg_invalid::get_if_exists() ==
          vmptrld::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::base_reg::rdi << vmptrld::base_reg::from;
    CHECK(vmptrld::base_reg::get() == vmptrld::base_reg::rdi);

    g_vmcs_fields[addr] = vmptrld::base_reg::rcx << vmptrld::base_reg::from;
    CHECK(vmptrld::base_reg::get_if_exists() == vmptrld::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::valid << vmptrld::base_reg_invalid::from;
    CHECK(vmptrld::base_reg_invalid::get() == vmptrld::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::invalid << vmptrld::base_reg_invalid::from;
    CHECK(vmptrld::base_reg_invalid::get_if_exists() == vmptrld::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmptrst::get_name() == vmptrst::name);
    CHECK(vmptrst::get() == 1UL);
    CHECK(vmptrst::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::scaling::scale_by_2 << vmptrst::scaling::from;
    CHECK(vmptrst::scaling::get() == vmptrst::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmptrst::scaling::scale_by_8 << vmptrst::scaling::from;
    CHECK(vmptrst::scaling::get_if_exists() == vmptrst::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::address_size::_32bit << vmptrst::address_size::from;
    CHECK(vmptrst::address_size::get() == vmptrst::address_size::_32bit);

    g_vmcs_fields[addr] = vmptrst::address_size::_64bit << vmptrst::address_size::from;
    CHECK(vmptrst::address_size::get_if_exists() == vmptrst::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::segment_register::cs << vmptrst::segment_register::from;
    CHECK(vmptrst::segment_register::get() == vmptrst::segment_register::cs);

    g_vmcs_fields[addr] = vmptrst::segment_register::gs << vmptrst::segment_register::from;
    CHECK(vmptrst::segment_register::get_if_exists() == vmptrst::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::index_reg::rsi << vmptrst::index_reg::from;
    CHECK(vmptrst::index_reg::get() == vmptrst::index_reg::rsi);

    g_vmcs_fields[addr] = vmptrst::index_reg::r11 << vmptrst::index_reg::from;
    CHECK(vmptrst::index_reg::get_if_exists() == vmptrst::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::valid << vmptrst::index_reg_invalid::from;
    CHECK(vmptrst::index_reg_invalid::get() == vmptrst::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::invalid << vmptrst::index_reg_invalid::from;
    CHECK(vmptrst::index_reg_invalid::get_if_exists() ==
          vmptrst::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::base_reg::rdi << vmptrst::base_reg::from;
    CHECK(vmptrst::base_reg::get() == vmptrst::base_reg::rdi);

    g_vmcs_fields[addr] = vmptrst::base_reg::rcx << vmptrst::base_reg::from;
    CHECK(vmptrst::base_reg::get_if_exists() == vmptrst::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::valid << vmptrst::base_reg_invalid::from;
    CHECK(vmptrst::base_reg_invalid::get() == vmptrst::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::invalid << vmptrst::base_reg_invalid::from;
    CHECK(vmptrst::base_reg_invalid::get_if_exists() == vmptrst::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmxon::get_name() == vmxon::name);
    CHECK(vmxon::get() == 1UL);
    CHECK(vmxon::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::scaling::scale_by_2 << vmxon::scaling::from;
    CHECK(vmxon::scaling::get() == vmxon::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmxon::scaling::scale_by_8 << vmxon::scaling::from;
    CHECK(vmxon::scaling::get_if_exists() == vmxon::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::address_size::_32bit << vmxon::address_size::from;
    CHECK(vmxon::address_size::get() == vmxon::address_size::_32bit);

    g_vmcs_fields[addr] = vmxon::address_size::_64bit << vmxon::address_size::from;
    CHECK(vmxon::address_size::get_if_exists() == vmxon::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::segment_register::cs << vmxon::segment_register::from;
    CHECK(vmxon::segment_register::get() == vmxon::segment_register::cs);

    g_vmcs_fields[addr] = vmxon::segment_register::gs << vmxon::segment_register::from;
    CHECK(vmxon::segment_register::get_if_exists() == vmxon::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::index_reg::rsi << vmxon::index_reg::from;
    CHECK(vmxon::index_reg::get() == vmxon::index_reg::rsi);

    g_vmcs_fields[addr] = vmxon::index_reg::r11 << vmxon::index_reg::from;
    CHECK(vmxon::index_reg::get_if_exists() == vmxon::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::valid << vmxon::index_reg_invalid::from;
    CHECK(vmxon::index_reg_invalid::get() == vmxon::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::invalid << vmxon::index_reg_invalid::from;
    CHECK(vmxon::index_reg_invalid::get_if_exists() == vmxon::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::base_reg::rdi << vmxon::base_reg::from;
    CHECK(vmxon::base_reg::get() == vmxon::base_reg::rdi);

    g_vmcs_fields[addr] = vmxon::base_reg::rcx << vmxon::base_reg::from;
    CHECK(vmxon::base_reg::get_if_exists() == vmxon::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::valid << vmxon::base_reg_invalid::from;
    CHECK(vmxon::base_reg_invalid::get() == vmxon::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::invalid << vmxon::base_reg_invalid::from;
    CHECK(vmxon::base_reg_invalid::get_if_exists() == vmxon::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(xrstors::get_name() == xrstors::name);
    CHECK(xrstors::get() == 1UL);
    CHECK(xrstors::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::scaling::scale_by_2 << xrstors::scaling::from;
    CHECK(xrstors::scaling::get() == xrstors::scaling::scale_by_2);

    g_vmcs_fields[addr] = xrstors::scaling::scale_by_8 << xrstors::scaling::from;
    CHECK(xrstors::scaling::get_if_exists() == xrstors::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::address_size::_32bit << xrstors::address_size::from;
    CHECK(xrstors::address_size::get() == xrstors::address_size::_32bit);

    g_vmcs_fields[addr] = xrstors::address_size::_64bit << xrstors::address_size::from;
    CHECK(xrstors::address_size::get_if_exists() == xrstors::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::segment_register::cs << xrstors::segment_register::from;
    CHECK(xrstors::segment_register::get() == xrstors::segment_register::cs);

    g_vmcs_fields[addr] = xrstors::segment_register::gs << xrstors::segment_register::from;
    CHECK(xrstors::segment_register::get_if_exists() == xrstors::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::index_reg::rsi << xrstors::index_reg::from;
    CHECK(xrstors::index_reg::get() == xrstors::index_reg::rsi);

    g_vmcs_fields[addr] = xrstors::index_reg::r11 << xrstors::index_reg::from;
    CHECK(xrstors::index_reg::get_if_exists() == xrstors::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::valid << xrstors::index_reg_invalid::from;
    CHECK(xrstors::index_reg_invalid::get() == xrstors::index_reg_invalid::valid);

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::invalid << xrstors::index_reg_invalid::from;
    CHECK(xrstors::index_reg_invalid::get_if_exists() ==
          xrstors::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::base_reg::rdi << xrstors::base_reg::from;
    CHECK(xrstors::base_reg::get() == xrstors::base_reg::rdi);

    g_vmcs_fields[addr] = xrstors::base_reg::rcx << xrstors::base_reg::from;
    CHECK(xrstors::base_reg::get_if_exists() == xrstors::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::valid << xrstors::base_reg_invalid::from;
    CHECK(xrstors::base_reg_invalid::get() == xrstors::base_reg_invalid::valid);

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::invalid << xrstors::base_reg_invalid::from;
    CHECK(xrstors::base_reg_invalid::get_if_exists() == xrstors::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(xsaves::get_name() == xsaves::name);
    CHECK(xsaves::get() == 1UL);
    CHECK(xsaves::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::scaling::scale_by_2 << xsaves::scaling::from;
    CHECK(xsaves::scaling::get() == xsaves::scaling::scale_by_2);

    g_vmcs_fields[addr] = xsaves::scaling::scale_by_8 << xsaves::scaling::from;
    CHECK(xsaves::scaling::get_if_exists() == xsaves::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::address_size::_32bit << xsaves::address_size::from;
    CHECK(xsaves::address_size::get() == xsaves::address_size::_32bit);

    g_vmcs_fields[addr] = xsaves::address_size::_64bit << xsaves::address_size::from;
    CHECK(xsaves::address_size::get_if_exists() == xsaves::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::segment_register::cs << xsaves::segment_register::from;
    CHECK(xsaves::segment_register::get() == xsaves::segment_register::cs);

    g_vmcs_fields[addr] = xsaves::segment_register::gs << xsaves::segment_register::from;
    CHECK(xsaves::segment_register::get_if_exists() == xsaves::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::index_reg::rsi << xsaves::index_reg::from;
    CHECK(xsaves::index_reg::get() == xsaves::index_reg::rsi);

    g_vmcs_fields[addr] = xsaves::index_reg::r11 << xsaves::index_reg::from;
    CHECK(xsaves::index_reg::get_if_exists() == xsaves::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::valid << xsaves::index_reg_invalid::from;
    CHECK(xsaves::index_reg_invalid::get() == xsaves::index_reg_invalid::valid);

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::invalid << xsaves::index_reg_invalid::from;
    CHECK(xsaves::index_reg_invalid::get_if_exists() == xsaves::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::base_reg::rdi << xsaves::base_reg::from;
    CHECK(xsaves::base_reg::get() == xsaves::base_reg::rdi);

    g_vmcs_fields[addr] = xsaves::base_reg::rcx << xsaves::base_reg::from;
    CHECK(xsaves::base_reg::get_if_exists() == xsaves::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::valid << xsaves::base_reg_invalid::from;
    CHECK(xsaves::base_reg_invalid::get() == xsaves::base_reg_invalid::valid);

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::invalid << xsaves::base_reg_invalid::from;
    CHECK(xsaves::base_reg_invalid::get_if_exists() == xsaves::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmread::get_name() == vmread::name);
    CHECK(vmread::get() == 1UL);
    CHECK(vmread::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::scaling::scale_by_2 << vmread::scaling::from;
    CHECK(vmread::scaling::get() == vmread::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmread::scaling::scale_by_8 << vmread::scaling::from;
    CHECK(vmread::scaling::get_if_exists() == vmread::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::reg1::rbp << vmread::reg1::from;
    CHECK(vmread::reg1::get() == vmread::reg1::rbp);

    g_vmcs_fields[addr] = vmread::reg1::r13 << vmread::reg1::from;
    CHECK(vmread::reg1::get_if_exists() == vmread::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::address_size::_32bit << vmread::address_size::from;
    CHECK(vmread::address_size::get() == vmread::address_size::_32bit);

    g_vmcs_fields[addr] = vmread::address_size::_64bit << vmread::address_size::from;
    CHECK(vmread::address_size::get_if_exists() == vmread::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::mem_reg::mem << vmread::mem_reg::from;
    CHECK(vmread::mem_reg::get() == vmread::mem_reg::mem);

    g_vmcs_fields[addr] = vmread::mem_reg::reg << vmread::mem_reg::from;
    CHECK(vmread::mem_reg::get_if_exists() == vmread::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::segment_register::cs << vmread::segment_register::from;
    CHECK(vmread::segment_register::get() == vmread::segment_register::cs);

    g_vmcs_fields[addr] = vmread::segment_register::gs << vmread::segment_register::from;
    CHECK(vmread::segment_register::get_if_exists() == vmread::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::index_reg::rsi << vmread::index_reg::from;
    CHECK(vmread::index_reg::get() == vmread::index_reg::rsi);

    g_vmcs_fields[addr] = vmread::index_reg::r11 << vmread::index_reg::from;
    CHECK(vmread::index_reg::get_if_exists() == vmread::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::index_reg_invalid::valid << vmread::index_reg_invalid::from;
    CHECK(vmread::index_reg_invalid::get() == vmread::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmread::index_reg_invalid::invalid << vmread::index_reg_invalid::from;
    CHECK(vmread::index_reg_invalid::get_if_exists() == vmread::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::base_reg::rdi << vmread::base_reg::from;
    CHECK(vmread::base_reg::get() == vmread::base_reg::rdi);

    g_vmcs_fields[addr] = vmread::base_reg::rcx << vmread::base_reg::from;
    CHECK(vmread::base_reg::get_if_exists() == vmread::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::base_reg_invalid::valid << vmread::base_reg_invalid::from;
    CHECK(vmread::base_reg_invalid::get() == vmread::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmread::base_reg_invalid::invalid << vmread::base_reg_invalid::from;
    CHECK(vmread::base_reg_invalid::get_if_exists() == vmread::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::reg2::rdx << vmread::reg2::from;
    CHECK(vmread::reg2::get() == vmread::reg2::rdx);

    g_vmcs_fields[addr] = vmread::reg2::rsp << vmread::reg2::from;
    CHECK(vmread::reg2::get_if_exists() == vmread::reg2::rsp);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    CHECK(vmwrite::get_name() == vmwrite::name);
    CHECK(vmwrite::get() == 1UL);
    CHECK(vmwrite::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::scaling::scale_by_2 << vmwrite::scaling::from;
    CHECK(vmwrite::scaling::get() == vmwrite::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmwrite::scaling::scale_by_8 << vmwrite::scaling::from;
    CHECK(vmwrite::scaling::get_if_exists() == vmwrite::scaling::scale_by_8);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::reg1::rbp << vmwrite::reg1::from;
    CHECK(vmwrite::reg1::get() == vmwrite::reg1::rbp);

    g_vmcs_fields[addr] = vmwrite::reg1::r13 << vmwrite::reg1::from;
    CHECK(vmwrite::reg1::get_if_exists() == vmwrite::reg1::r13);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::address_size::_32bit << vmwrite::address_size::from;
    CHECK(vmwrite::address_size::get() == vmwrite::address_size::_32bit);

    g_vmcs_fields[addr] = vmwrite::address_size::_64bit << vmwrite::address_size::from;
    CHECK(vmwrite::address_size::get_if_exists() == vmwrite::address_size::_64bit);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::mem_reg::mem << vmwrite::mem_reg::from;
    CHECK(vmwrite::mem_reg::get() == vmwrite::mem_reg::mem);

    g_vmcs_fields[addr] = vmwrite::mem_reg::reg << vmwrite::mem_reg::from;
    CHECK(vmwrite::mem_reg::get_if_exists() == vmwrite::mem_reg::reg);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::segment_register::cs << vmwrite::segment_register::from;
    CHECK(vmwrite::segment_register::get() == vmwrite::segment_register::cs);

    g_vmcs_fields[addr] = vmwrite::segment_register::gs << vmwrite::segment_register::from;
    CHECK(vmwrite::segment_register::get_if_exists() == vmwrite::segment_register::gs);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::index_reg::rsi << vmwrite::index_reg::from;
    CHECK(vmwrite::index_reg::get() == vmwrite::index_reg::rsi);

    g_vmcs_fields[addr] = vmwrite::index_reg::r11 << vmwrite::index_reg::from;
    CHECK(vmwrite::index_reg::get_if_exists() == vmwrite::index_reg::r11);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::valid << vmwrite::index_reg_invalid::from;
    CHECK(vmwrite::index_reg_invalid::get() == vmwrite::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::invalid << vmwrite::index_reg_invalid::from;
    CHECK(vmwrite::index_reg_invalid::get_if_exists() ==
          vmwrite::index_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::base_reg::rdi << vmwrite::base_reg::from;
    CHECK(vmwrite::base_reg::get() == vmwrite::base_reg::rdi);

    g_vmcs_fields[addr] = vmwrite::base_reg::rcx << vmwrite::base_reg::from;
    CHECK(vmwrite::base_reg::get_if_exists() == vmwrite::base_reg::rcx);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::valid << vmwrite::base_reg_invalid::from;
    CHECK(vmwrite::base_reg_invalid::get() == vmwrite::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::invalid << vmwrite::base_reg_invalid::from;
    CHECK(vmwrite::base_reg_invalid::get_if_exists() == vmwrite::base_reg_invalid::invalid);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::reg2::rdx << vmwrite::reg2::from;
    CHECK(vmwrite::reg2::get() == vmwrite::reg2::rdx);

    g_vmcs_fields[addr] = vmwrite::reg2::rsp << vmwrite::reg2::from;
    CHECK(vmwrite::reg2::get_if_exists() == vmwrite::reg2::rsp);
}

#endif
