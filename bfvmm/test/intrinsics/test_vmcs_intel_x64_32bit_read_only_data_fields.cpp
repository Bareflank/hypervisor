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

static std::map<uint64_t, std::string> vm_instruction_error_codes {
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

    using namespace vmcs::vm_instruction_error;

    CHECK(exists());

    for (auto &&code : vm_instruction_error_codes) {
        g_vmcs_fields[addr] = code.first;
        CHECK(get() == code.first);
        CHECK(description() == code.second);
    }
}

//TEST_CASE("vmcs_vm_instruction_error_description")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    using namespace vmcs::vm_instruction_error;
//
//    CHECK_THROWS(vm_instruction_error_description(0UL));
//    CHECK(vm_instruction_error_description(1UL) == "VMCALL executed in VMX root operation"_s);
//}
//
//TEST_CASE("vmcs_vm_instruction_error_description_if_exists")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    using namespace vmcs::vm_instruction_error;
//
//    CHECK_NOTHROW(vm_instruction_error_description_if_exists(0UL, true, false));
//    CHECK(vm_instruction_error_description_if_exists(0UL, true, false) == ""_s);
//    CHECK(vm_instruction_error_description_if_exists(1UL, true,
//            true) == "VMCALL executed in VMX root operation"_s);
//}

TEST_CASE("vmcs_exit_reason")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    CHECK(exists());

    dump(0);
}

TEST_CASE("vmcs_exit_reason_basic_exit_reason")
{
    using namespace vmcs::exit_reason;

    for (auto &&reason : exit_reasons) {
        MockRepository mocks;
        setup_intrinsics(mocks);

        g_vmcs_fields[addr] = reason.first << basic_exit_reason::from;
        CHECK(basic_exit_reason::get() == reason.first);
        CHECK(basic_exit_reason::description() == reason.second);
    }
}

//TEST_CASE("vmcs_exit_reason_basic_exit_reason_description")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    using namespace vmcs::exit_reason;
//
//    CHECK_THROWS(basic_exit_reason::basic_exit_reason_description(0UL, false));
//    CHECK(basic_exit_reason::basic_exit_reason_description(40UL,
//            true) == "pause"_s);
//}
//
//TEST_CASE("vmcs_exit_reason_basic_exit_reason_description_if_exists")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    using namespace vmcs::exit_reason;
//
//    CHECK_NOTHROW(basic_exit_reason::basic_exit_reason_description_if_exists(0UL, true, false));
//    CHECK(basic_exit_reason::basic_exit_reason_description_if_exists(0UL, true,
//            false) == ""_s);
//    CHECK(basic_exit_reason::basic_exit_reason_description_if_exists(
//              40UL, true, true) == "pause"_s);
//}

TEST_CASE("vmcs_exit_reason_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = reserved::mask;
    CHECK(reserved::get() == reserved::mask >> reserved::from);
}

TEST_CASE("vmcs_exit_reason_vm_exit_incident_to_enclave_mode")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = vm_exit_incident_to_enclave_mode::mask;
    CHECK(vm_exit_incident_to_enclave_mode::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_incident_to_enclave_mode::is_disabled());

    g_vmcs_fields[addr] = vm_exit_incident_to_enclave_mode::mask;
    CHECK(vm_exit_incident_to_enclave_mode::is_enabled(vm_exit_incident_to_enclave_mode::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_incident_to_enclave_mode::is_disabled(0x0));

    g_vmcs_fields[addr] = vm_exit_incident_to_enclave_mode::mask;
    CHECK(vm_exit_incident_to_enclave_mode::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_incident_to_enclave_mode::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_pending_mtf_vm_exit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = pending_mtf_vm_exit::mask;
    CHECK(pending_mtf_vm_exit::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(pending_mtf_vm_exit::is_disabled());

    g_vmcs_fields[addr] = pending_mtf_vm_exit::mask;
    CHECK(pending_mtf_vm_exit::is_enabled(pending_mtf_vm_exit::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(pending_mtf_vm_exit::is_disabled(0x0));

    g_vmcs_fields[addr] = pending_mtf_vm_exit::mask;
    CHECK(pending_mtf_vm_exit::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(pending_mtf_vm_exit::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_vm_exit_from_vmx_root_operation")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = vm_exit_from_vmx_root_operation::mask;
    CHECK(vm_exit_from_vmx_root_operation::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_from_vmx_root_operation::is_disabled());

    g_vmcs_fields[addr] = vm_exit_from_vmx_root_operation::mask;
    CHECK(vm_exit_from_vmx_root_operation::is_enabled(vm_exit_from_vmx_root_operation::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_from_vmx_root_operation::is_disabled(0x0));

    g_vmcs_fields[addr] = vm_exit_from_vmx_root_operation::mask;
    CHECK(vm_exit_from_vmx_root_operation::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_exit_from_vmx_root_operation::is_disabled_if_exists());
}

TEST_CASE("vmcs_exit_reason_vm_entry_failure")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = vm_entry_failure::mask;
    CHECK(vm_entry_failure::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_entry_failure::is_disabled());

    g_vmcs_fields[addr] = vm_entry_failure::mask;
    CHECK(vm_entry_failure::is_enabled(vm_entry_failure::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_entry_failure::is_disabled(0x0));

    g_vmcs_fields[addr] = vm_entry_failure::mask;
    CHECK(vm_entry_failure::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vm_entry_failure::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    CHECK(exists());

    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_interruption_information_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get() == (vector::mask >> vector::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get_if_exists() == (vector::mask >> vector::from));
}

TEST_CASE("vmcs_vm_exit_interruption_information_interruption_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get() == (interruption_type::mask >> interruption_type::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get(interruption_type::mask) == (interruption_type::mask >> interruption_type::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get_if_exists() == (interruption_type::mask >> interruption_type::from));
}

TEST_CASE("vmcs_vm_exit_interruption_information_error_code_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled());

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled(error_code_valid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled(0x0));

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information_nmi_blocking_due_to_iret")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = nmi_unblocking_due_to_iret::mask;
    CHECK(nmi_unblocking_due_to_iret::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(nmi_unblocking_due_to_iret::is_disabled());

    g_vmcs_fields[addr] = nmi_unblocking_due_to_iret::mask;
    CHECK(nmi_unblocking_due_to_iret::is_enabled(nmi_unblocking_due_to_iret::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(nmi_unblocking_due_to_iret::is_disabled(0x0));

    g_vmcs_fields[addr] = nmi_unblocking_due_to_iret::mask;
    CHECK(nmi_unblocking_due_to_iret::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(nmi_unblocking_due_to_iret::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_information_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_vm_exit_interruption_information_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_information;

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled());

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled(valid_bit::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled(0x0));

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_interruption_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_interruption_error_code;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFUL);
    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(get_if_exists() == 0xFFFFFFFFFFFFFFFUL);

    dump(0);
}

TEST_CASE("vmcs_idt_vectoring_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;
    CHECK(exists());

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(get() == 0xFFFFFFFFFFFFFFFUL);
    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(get_if_exists() == 0xFFFFFFFFFFFFFFFUL);

    dump(0);
}

TEST_CASE("vmcs_idt_vectoring_information_vector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get() == (vector::mask >> vector::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get(vector::mask) == (vector::mask >> vector::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vector::get_if_exists() == (vector::mask >> vector::from));
}

TEST_CASE("vmcs_idt_vectoring_information_interruption_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get() == (interruption_type::mask >> interruption_type::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get(interruption_type::mask) == (interruption_type::mask >> interruption_type::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(interruption_type::get_if_exists() == (interruption_type::mask >> interruption_type::from));
}

TEST_CASE("vmcs_idt_vectoring_information_error_code_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled());

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled(error_code_valid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled(0x0));

    g_vmcs_fields[addr] = error_code_valid::mask;
    CHECK(error_code_valid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(error_code_valid::is_disabled_if_exists());
}

TEST_CASE("vmcs_idt_vectoring_information_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_idt_vectoring_information_valid_bit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_information;

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled());

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled(valid_bit::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled(0x0));

    g_vmcs_fields[addr] = valid_bit::mask;
    CHECK(valid_bit::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(valid_bit::is_disabled_if_exists());
}

TEST_CASE("vmcs_idt_vectoring_error_code")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::idt_vectoring_error_code;

    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    CHECK(exists());

    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_instruction_length")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_length;

    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    CHECK(exists());

    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_instruction_information")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 100UL;
    CHECK(get() == 100UL);
    CHECK(exists());

    g_vmcs_fields[addr] = 200UL;
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ins")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ins::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ins::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ins_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ins::address_size::get() == (ins::address_size::mask >> ins::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ins::address_size::get(ins::address_size::mask) == (ins::address_size::mask >> ins::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ins::address_size::get_if_exists() == (ins::address_size::mask >> ins::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::address_size::get() == (outs::address_size::mask >> outs::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::address_size::get(outs::address_size::mask) == (outs::address_size::mask >> outs::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::address_size::get_if_exists() == (outs::address_size::mask >> outs::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_outs_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::segment_register::get() == (outs::segment_register::mask >> outs::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::segment_register::get(outs::segment_register::mask) == (outs::segment_register::mask >> outs::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(outs::segment_register::get_if_exists() == (outs::segment_register::mask >> outs::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::scaling::get() == (invept::scaling::mask >> invept::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::scaling::get(invept::scaling::mask) == (invept::scaling::mask >> invept::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::scaling::get_if_exists() == (invept::scaling::mask >> invept::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::address_size::get() == (invept::address_size::mask >> invept::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::address_size::get(invept::address_size::mask) == (invept::address_size::mask >> invept::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::address_size::get_if_exists() == (invept::address_size::mask >> invept::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::segment_register::get() == (invept::segment_register::mask >> invept::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::segment_register::get(invept::segment_register::mask) == (invept::segment_register::mask >> invept::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::segment_register::get_if_exists() == (invept::segment_register::mask >> invept::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::index_reg::get() == (invept::index_reg::mask >> invept::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::index_reg::get(invept::index_reg::mask) == (invept::index_reg::mask >> invept::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::index_reg::get_if_exists() == (invept::index_reg::mask >> invept::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::index_reg_invalid::mask;
    CHECK(invept::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invept::index_reg_invalid::mask;
    CHECK(invept::index_reg_invalid::is_enabled(invept::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invept::index_reg_invalid::mask;
    CHECK(invept::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::base_reg::get() == (invept::base_reg::mask >> invept::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::base_reg::get(invept::base_reg::mask) == (invept::base_reg::mask >> invept::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::base_reg::get_if_exists() == (invept::base_reg::mask >> invept::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::base_reg_invalid::mask;
    CHECK(invept::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invept::base_reg_invalid::mask;
    CHECK(invept::base_reg_invalid::is_enabled(invept::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invept::base_reg_invalid::mask;
    CHECK(invept::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invept::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invept_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::reg2::get() == (invept::reg2::mask >> invept::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::reg2::get(invept::reg2::mask) == (invept::reg2::mask >> invept::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invept::reg2::get_if_exists() == (invept::reg2::mask >> invept::reg2::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::scaling::get() == (invpcid::scaling::mask >> invpcid::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::scaling::get(invpcid::scaling::mask) == (invpcid::scaling::mask >> invpcid::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::scaling::get_if_exists() == (invpcid::scaling::mask >> invpcid::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::address_size::get() == (invpcid::address_size::mask >> invpcid::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::address_size::get(invpcid::address_size::mask) == (invpcid::address_size::mask >> invpcid::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::address_size::get_if_exists() == (invpcid::address_size::mask >> invpcid::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::segment_register::get() == (invpcid::segment_register::mask >> invpcid::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::segment_register::get(invpcid::segment_register::mask) == (invpcid::segment_register::mask >> invpcid::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::segment_register::get_if_exists() == (invpcid::segment_register::mask >> invpcid::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::index_reg::get() == (invpcid::index_reg::mask >> invpcid::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::index_reg::get(invpcid::index_reg::mask) == (invpcid::index_reg::mask >> invpcid::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::index_reg::get_if_exists() == (invpcid::index_reg::mask >> invpcid::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::mask;
    CHECK(invpcid::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::mask;
    CHECK(invpcid::index_reg_invalid::is_enabled(invpcid::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::mask;
    CHECK(invpcid::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::base_reg::get() == (invpcid::base_reg::mask >> invpcid::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::base_reg::get(invpcid::base_reg::mask) == (invpcid::base_reg::mask >> invpcid::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::base_reg::get_if_exists() == (invpcid::base_reg::mask >> invpcid::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::mask;
    CHECK(invpcid::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::mask;
    CHECK(invpcid::base_reg_invalid::is_enabled(invpcid::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::mask;
    CHECK(invpcid::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invpcid::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invpcid_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::reg2::get() == (invpcid::reg2::mask >> invpcid::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::reg2::get(invpcid::reg2::mask) == (invpcid::reg2::mask >> invpcid::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invpcid::reg2::get_if_exists() == (invpcid::reg2::mask >> invpcid::reg2::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::scaling::get() == (invvpid::scaling::mask >> invvpid::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::scaling::get(invvpid::scaling::mask) == (invvpid::scaling::mask >> invvpid::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::scaling::get_if_exists() == (invvpid::scaling::mask >> invvpid::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::address_size::get() == (invvpid::address_size::mask >> invvpid::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::address_size::get(invvpid::address_size::mask) == (invvpid::address_size::mask >> invvpid::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::address_size::get_if_exists() == (invvpid::address_size::mask >> invvpid::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::segment_register::get() == (invvpid::segment_register::mask >> invvpid::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::segment_register::get(invvpid::segment_register::mask) == (invvpid::segment_register::mask >> invvpid::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::segment_register::get_if_exists() == (invvpid::segment_register::mask >> invvpid::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::index_reg::get() == (invvpid::index_reg::mask >> invvpid::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::index_reg::get(invvpid::index_reg::mask) == (invvpid::index_reg::mask >> invvpid::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::index_reg::get_if_exists() == (invvpid::index_reg::mask >> invvpid::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::mask;
    CHECK(invvpid::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::mask;
    CHECK(invvpid::index_reg_invalid::is_enabled(invvpid::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::mask;
    CHECK(invvpid::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::base_reg::get() == (invvpid::base_reg::mask >> invvpid::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::base_reg::get(invvpid::base_reg::mask) == (invvpid::base_reg::mask >> invvpid::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::base_reg::get_if_exists() == (invvpid::base_reg::mask >> invvpid::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::mask;
    CHECK(invvpid::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::mask;
    CHECK(invvpid::base_reg_invalid::is_enabled(invvpid::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::mask;
    CHECK(invvpid::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(invvpid::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_invvpid_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::reg2::get() == (invvpid::reg2::mask >> invvpid::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::reg2::get(invvpid::reg2::mask) == (invvpid::reg2::mask >> invvpid::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(invvpid::reg2::get_if_exists() == (invvpid::reg2::mask >> invvpid::reg2::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::scaling::get() == (lidt::scaling::mask >> lidt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::scaling::get(lidt::scaling::mask) == (lidt::scaling::mask >> lidt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::scaling::get_if_exists() == (lidt::scaling::mask >> lidt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::address_size::get() == (lidt::address_size::mask >> lidt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::address_size::get(lidt::address_size::mask) == (lidt::address_size::mask >> lidt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::address_size::get_if_exists() == (lidt::address_size::mask >> lidt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::operand_size::get() == (lidt::operand_size::mask >> lidt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::operand_size::get(lidt::operand_size::mask) == (lidt::operand_size::mask >> lidt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::operand_size::get_if_exists() == (lidt::operand_size::mask >> lidt::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::segment_register::get() == (lidt::segment_register::mask >> lidt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::segment_register::get(lidt::segment_register::mask) == (lidt::segment_register::mask >> lidt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::segment_register::get_if_exists() == (lidt::segment_register::mask >> lidt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::index_reg::get() == (lidt::index_reg::mask >> lidt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::index_reg::get(lidt::index_reg::mask) == (lidt::index_reg::mask >> lidt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::index_reg::get_if_exists() == (lidt::index_reg::mask >> lidt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::index_reg_invalid::mask;
    CHECK(lidt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lidt::index_reg_invalid::mask;
    CHECK(lidt::index_reg_invalid::is_enabled(lidt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lidt::index_reg_invalid::mask;
    CHECK(lidt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::base_reg::get() == (lidt::base_reg::mask >> lidt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::base_reg::get(lidt::base_reg::mask) == (lidt::base_reg::mask >> lidt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::base_reg::get_if_exists() == (lidt::base_reg::mask >> lidt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::base_reg_invalid::mask;
    CHECK(lidt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lidt::base_reg_invalid::mask;
    CHECK(lidt::base_reg_invalid::is_enabled(lidt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lidt::base_reg_invalid::mask;
    CHECK(lidt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lidt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lidt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::instruction_identity::get() == (lidt::instruction_identity::mask >> lidt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::instruction_identity::get(lidt::instruction_identity::mask) == (lidt::instruction_identity::mask >> lidt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lidt::instruction_identity::get_if_exists() == (lidt::instruction_identity::mask >> lidt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::scaling::get() == (lgdt::scaling::mask >> lgdt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::scaling::get(lgdt::scaling::mask) == (lgdt::scaling::mask >> lgdt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::scaling::get_if_exists() == (lgdt::scaling::mask >> lgdt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::address_size::get() == (lgdt::address_size::mask >> lgdt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::address_size::get(lgdt::address_size::mask) == (lgdt::address_size::mask >> lgdt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::address_size::get_if_exists() == (lgdt::address_size::mask >> lgdt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::operand_size::get() == (lgdt::operand_size::mask >> lgdt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::operand_size::get(lgdt::operand_size::mask) == (lgdt::operand_size::mask >> lgdt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::operand_size::get_if_exists() == (lgdt::operand_size::mask >> lgdt::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::segment_register::get() == (lgdt::segment_register::mask >> lgdt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::segment_register::get(lgdt::segment_register::mask) == (lgdt::segment_register::mask >> lgdt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::segment_register::get_if_exists() == (lgdt::segment_register::mask >> lgdt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::index_reg::get() == (lgdt::index_reg::mask >> lgdt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::index_reg::get(lgdt::index_reg::mask) == (lgdt::index_reg::mask >> lgdt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::index_reg::get_if_exists() == (lgdt::index_reg::mask >> lgdt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::mask;
    CHECK(lgdt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::mask;
    CHECK(lgdt::index_reg_invalid::is_enabled(lgdt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::mask;
    CHECK(lgdt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::base_reg::get() == (lgdt::base_reg::mask >> lgdt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::base_reg::get(lgdt::base_reg::mask) == (lgdt::base_reg::mask >> lgdt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::base_reg::get_if_exists() == (lgdt::base_reg::mask >> lgdt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::mask;
    CHECK(lgdt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::mask;
    CHECK(lgdt::base_reg_invalid::is_enabled(lgdt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::mask;
    CHECK(lgdt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lgdt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lgdt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::instruction_identity::get() == (lgdt::instruction_identity::mask >> lgdt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::instruction_identity::get(lgdt::instruction_identity::mask) == (lgdt::instruction_identity::mask >> lgdt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lgdt::instruction_identity::get_if_exists() == (lgdt::instruction_identity::mask >> lgdt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::scaling::get() == (sidt::scaling::mask >> sidt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::scaling::get(sidt::scaling::mask) == (sidt::scaling::mask >> sidt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::scaling::get_if_exists() == (sidt::scaling::mask >> sidt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::address_size::get() == (sidt::address_size::mask >> sidt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::address_size::get(sidt::address_size::mask) == (sidt::address_size::mask >> sidt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::address_size::get_if_exists() == (sidt::address_size::mask >> sidt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::operand_size::get() == (sidt::operand_size::mask >> sidt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::operand_size::get(sidt::operand_size::mask) == (sidt::operand_size::mask >> sidt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::operand_size::get_if_exists() == (sidt::operand_size::mask >> sidt::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::segment_register::get() == (sidt::segment_register::mask >> sidt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::segment_register::get(sidt::segment_register::mask) == (sidt::segment_register::mask >> sidt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::segment_register::get_if_exists() == (sidt::segment_register::mask >> sidt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::index_reg::get() == (sidt::index_reg::mask >> sidt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::index_reg::get(sidt::index_reg::mask) == (sidt::index_reg::mask >> sidt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::index_reg::get_if_exists() == (sidt::index_reg::mask >> sidt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::index_reg_invalid::mask;
    CHECK(sidt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sidt::index_reg_invalid::mask;
    CHECK(sidt::index_reg_invalid::is_enabled(sidt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sidt::index_reg_invalid::mask;
    CHECK(sidt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::base_reg::get() == (sidt::base_reg::mask >> sidt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::base_reg::get(sidt::base_reg::mask) == (sidt::base_reg::mask >> sidt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::base_reg::get_if_exists() == (sidt::base_reg::mask >> sidt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::base_reg_invalid::mask;
    CHECK(sidt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sidt::base_reg_invalid::mask;
    CHECK(sidt::base_reg_invalid::is_enabled(sidt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sidt::base_reg_invalid::mask;
    CHECK(sidt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sidt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sidt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::instruction_identity::get() == (sidt::instruction_identity::mask >> sidt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::instruction_identity::get(sidt::instruction_identity::mask) == (sidt::instruction_identity::mask >> sidt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sidt::instruction_identity::get_if_exists() == (sidt::instruction_identity::mask >> sidt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::scaling::get() == (sgdt::scaling::mask >> sgdt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::scaling::get(sgdt::scaling::mask) == (sgdt::scaling::mask >> sgdt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::scaling::get_if_exists() == (sgdt::scaling::mask >> sgdt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::address_size::get() == (sgdt::address_size::mask >> sgdt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::address_size::get(sgdt::address_size::mask) == (sgdt::address_size::mask >> sgdt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::address_size::get_if_exists() == (sgdt::address_size::mask >> sgdt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::operand_size::get() == (sgdt::operand_size::mask >> sgdt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::operand_size::get(sgdt::operand_size::mask) == (sgdt::operand_size::mask >> sgdt::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::operand_size::get_if_exists() == (sgdt::operand_size::mask >> sgdt::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::segment_register::get() == (sgdt::segment_register::mask >> sgdt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::segment_register::get(sgdt::segment_register::mask) == (sgdt::segment_register::mask >> sgdt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::segment_register::get_if_exists() == (sgdt::segment_register::mask >> sgdt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::index_reg::get() == (sgdt::index_reg::mask >> sgdt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::index_reg::get(sgdt::index_reg::mask) == (sgdt::index_reg::mask >> sgdt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::index_reg::get_if_exists() == (sgdt::index_reg::mask >> sgdt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::mask;
    CHECK(sgdt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::mask;
    CHECK(sgdt::index_reg_invalid::is_enabled(sgdt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::mask;
    CHECK(sgdt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::base_reg::get() == (sgdt::base_reg::mask >> sgdt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::base_reg::get(sgdt::base_reg::mask) == (sgdt::base_reg::mask >> sgdt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::base_reg::get_if_exists() == (sgdt::base_reg::mask >> sgdt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::mask;
    CHECK(sgdt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::mask;
    CHECK(sgdt::base_reg_invalid::is_enabled(sgdt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::mask;
    CHECK(sgdt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sgdt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sgdt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::instruction_identity::get() == (sgdt::instruction_identity::mask >> sgdt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::instruction_identity::get(sgdt::instruction_identity::mask) == (sgdt::instruction_identity::mask >> sgdt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sgdt::instruction_identity::get_if_exists() == (sgdt::instruction_identity::mask >> sgdt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::scaling::get() == (lldt::scaling::mask >> lldt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::scaling::get(lldt::scaling::mask) == (lldt::scaling::mask >> lldt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::scaling::get_if_exists() == (lldt::scaling::mask >> lldt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::reg1::get() == (lldt::reg1::mask >> lldt::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::reg1::get(lldt::reg1::mask) == (lldt::reg1::mask >> lldt::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::reg1::get_if_exists() == (lldt::reg1::mask >> lldt::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::address_size::get() == (lldt::address_size::mask >> lldt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::address_size::get(lldt::address_size::mask) == (lldt::address_size::mask >> lldt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::address_size::get_if_exists() == (lldt::address_size::mask >> lldt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::mem_reg::get() == (lldt::mem_reg::mask >> lldt::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::mem_reg::get(lldt::mem_reg::mask) == (lldt::mem_reg::mask >> lldt::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::mem_reg::get_if_exists() == (lldt::mem_reg::mask >> lldt::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::segment_register::get() == (lldt::segment_register::mask >> lldt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::segment_register::get(lldt::segment_register::mask) == (lldt::segment_register::mask >> lldt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::segment_register::get_if_exists() == (lldt::segment_register::mask >> lldt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::index_reg::get() == (lldt::index_reg::mask >> lldt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::index_reg::get(lldt::index_reg::mask) == (lldt::index_reg::mask >> lldt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::index_reg::get_if_exists() == (lldt::index_reg::mask >> lldt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::index_reg_invalid::mask;
    CHECK(lldt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lldt::index_reg_invalid::mask;
    CHECK(lldt::index_reg_invalid::is_enabled(lldt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lldt::index_reg_invalid::mask;
    CHECK(lldt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::base_reg::get() == (lldt::base_reg::mask >> lldt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::base_reg::get(lldt::base_reg::mask) == (lldt::base_reg::mask >> lldt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::base_reg::get_if_exists() == (lldt::base_reg::mask >> lldt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::base_reg_invalid::mask;
    CHECK(lldt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = lldt::base_reg_invalid::mask;
    CHECK(lldt::base_reg_invalid::is_enabled(lldt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = lldt::base_reg_invalid::mask;
    CHECK(lldt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(lldt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_lldt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::instruction_identity::get() == (lldt::instruction_identity::mask >> lldt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::instruction_identity::get(lldt::instruction_identity::mask) == (lldt::instruction_identity::mask >> lldt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(lldt::instruction_identity::get_if_exists() == (lldt::instruction_identity::mask >> lldt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::scaling::get() == (ltr::scaling::mask >> ltr::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::scaling::get(ltr::scaling::mask) == (ltr::scaling::mask >> ltr::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::scaling::get_if_exists() == (ltr::scaling::mask >> ltr::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::reg1::get() == (ltr::reg1::mask >> ltr::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::reg1::get(ltr::reg1::mask) == (ltr::reg1::mask >> ltr::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::reg1::get_if_exists() == (ltr::reg1::mask >> ltr::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::address_size::get() == (ltr::address_size::mask >> ltr::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::address_size::get(ltr::address_size::mask) == (ltr::address_size::mask >> ltr::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::address_size::get_if_exists() == (ltr::address_size::mask >> ltr::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::mem_reg::get() == (ltr::mem_reg::mask >> ltr::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::mem_reg::get(ltr::mem_reg::mask) == (ltr::mem_reg::mask >> ltr::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::mem_reg::get_if_exists() == (ltr::mem_reg::mask >> ltr::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::segment_register::get() == (ltr::segment_register::mask >> ltr::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::segment_register::get(ltr::segment_register::mask) == (ltr::segment_register::mask >> ltr::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::segment_register::get_if_exists() == (ltr::segment_register::mask >> ltr::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::index_reg::get() == (ltr::index_reg::mask >> ltr::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::index_reg::get(ltr::index_reg::mask) == (ltr::index_reg::mask >> ltr::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::index_reg::get_if_exists() == (ltr::index_reg::mask >> ltr::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::index_reg_invalid::mask;
    CHECK(ltr::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = ltr::index_reg_invalid::mask;
    CHECK(ltr::index_reg_invalid::is_enabled(ltr::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = ltr::index_reg_invalid::mask;
    CHECK(ltr::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::base_reg::get() == (ltr::base_reg::mask >> ltr::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::base_reg::get(ltr::base_reg::mask) == (ltr::base_reg::mask >> ltr::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::base_reg::get_if_exists() == (ltr::base_reg::mask >> ltr::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::base_reg_invalid::mask;
    CHECK(ltr::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = ltr::base_reg_invalid::mask;
    CHECK(ltr::base_reg_invalid::is_enabled(ltr::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = ltr::base_reg_invalid::mask;
    CHECK(ltr::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(ltr::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_ltr_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::instruction_identity::get() == (ltr::instruction_identity::mask >> ltr::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::instruction_identity::get(ltr::instruction_identity::mask) == (ltr::instruction_identity::mask >> ltr::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(ltr::instruction_identity::get_if_exists() == (ltr::instruction_identity::mask >> ltr::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::scaling::get() == (sldt::scaling::mask >> sldt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::scaling::get(sldt::scaling::mask) == (sldt::scaling::mask >> sldt::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::scaling::get_if_exists() == (sldt::scaling::mask >> sldt::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::reg1::get() == (sldt::reg1::mask >> sldt::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::reg1::get(sldt::reg1::mask) == (sldt::reg1::mask >> sldt::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::reg1::get_if_exists() == (sldt::reg1::mask >> sldt::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::address_size::get() == (sldt::address_size::mask >> sldt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::address_size::get(sldt::address_size::mask) == (sldt::address_size::mask >> sldt::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::address_size::get_if_exists() == (sldt::address_size::mask >> sldt::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::mem_reg::get() == (sldt::mem_reg::mask >> sldt::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::mem_reg::get(sldt::mem_reg::mask) == (sldt::mem_reg::mask >> sldt::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::mem_reg::get_if_exists() == (sldt::mem_reg::mask >> sldt::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::segment_register::get() == (sldt::segment_register::mask >> sldt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::segment_register::get(sldt::segment_register::mask) == (sldt::segment_register::mask >> sldt::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::segment_register::get_if_exists() == (sldt::segment_register::mask >> sldt::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::index_reg::get() == (sldt::index_reg::mask >> sldt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::index_reg::get(sldt::index_reg::mask) == (sldt::index_reg::mask >> sldt::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::index_reg::get_if_exists() == (sldt::index_reg::mask >> sldt::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::index_reg_invalid::mask;
    CHECK(sldt::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sldt::index_reg_invalid::mask;
    CHECK(sldt::index_reg_invalid::is_enabled(sldt::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sldt::index_reg_invalid::mask;
    CHECK(sldt::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::base_reg::get() == (sldt::base_reg::mask >> sldt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::base_reg::get(sldt::base_reg::mask) == (sldt::base_reg::mask >> sldt::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::base_reg::get_if_exists() == (sldt::base_reg::mask >> sldt::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::base_reg_invalid::mask;
    CHECK(sldt::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = sldt::base_reg_invalid::mask;
    CHECK(sldt::base_reg_invalid::is_enabled(sldt::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = sldt::base_reg_invalid::mask;
    CHECK(sldt::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(sldt::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_sldt_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::instruction_identity::get() == (sldt::instruction_identity::mask >> sldt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::instruction_identity::get(sldt::instruction_identity::mask) == (sldt::instruction_identity::mask >> sldt::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(sldt::instruction_identity::get_if_exists() == (sldt::instruction_identity::mask >> sldt::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::scaling::get() == (str::scaling::mask >> str::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::scaling::get(str::scaling::mask) == (str::scaling::mask >> str::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::scaling::get_if_exists() == (str::scaling::mask >> str::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::reg1::get() == (str::reg1::mask >> str::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::reg1::get(str::reg1::mask) == (str::reg1::mask >> str::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::reg1::get_if_exists() == (str::reg1::mask >> str::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::address_size::get() == (str::address_size::mask >> str::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::address_size::get(str::address_size::mask) == (str::address_size::mask >> str::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::address_size::get_if_exists() == (str::address_size::mask >> str::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::mem_reg::get() == (str::mem_reg::mask >> str::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::mem_reg::get(str::mem_reg::mask) == (str::mem_reg::mask >> str::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::mem_reg::get_if_exists() == (str::mem_reg::mask >> str::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::segment_register::get() == (str::segment_register::mask >> str::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::segment_register::get(str::segment_register::mask) == (str::segment_register::mask >> str::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::segment_register::get_if_exists() == (str::segment_register::mask >> str::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::index_reg::get() == (str::index_reg::mask >> str::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::index_reg::get(str::index_reg::mask) == (str::index_reg::mask >> str::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::index_reg::get_if_exists() == (str::index_reg::mask >> str::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::index_reg_invalid::mask;
    CHECK(str::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = str::index_reg_invalid::mask;
    CHECK(str::index_reg_invalid::is_enabled(str::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = str::index_reg_invalid::mask;
    CHECK(str::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::base_reg::get() == (str::base_reg::mask >> str::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::base_reg::get(str::base_reg::mask) == (str::base_reg::mask >> str::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::base_reg::get_if_exists() == (str::base_reg::mask >> str::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::base_reg_invalid::mask;
    CHECK(str::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = str::base_reg_invalid::mask;
    CHECK(str::base_reg_invalid::is_enabled(str::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = str::base_reg_invalid::mask;
    CHECK(str::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(str::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_str_instruction_identity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::instruction_identity::get() == (str::instruction_identity::mask >> str::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::instruction_identity::get(str::instruction_identity::mask) == (str::instruction_identity::mask >> str::instruction_identity::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(str::instruction_identity::get_if_exists() == (str::instruction_identity::mask >> str::instruction_identity::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand_destination_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::destination_register::get() == (rdrand::destination_register::mask >> rdrand::destination_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::destination_register::get(rdrand::destination_register::mask) == (rdrand::destination_register::mask >> rdrand::destination_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::destination_register::get_if_exists() == (rdrand::destination_register::mask >> rdrand::destination_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdrand_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::operand_size::get() == (rdrand::operand_size::mask >> rdrand::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::operand_size::get(rdrand::operand_size::mask) == (rdrand::operand_size::mask >> rdrand::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdrand::operand_size::get_if_exists() == (rdrand::operand_size::mask >> rdrand::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed_destination_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::destination_register::get() == (rdseed::destination_register::mask >> rdseed::destination_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::destination_register::get(rdseed::destination_register::mask) == (rdseed::destination_register::mask >> rdseed::destination_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::destination_register::get_if_exists() == (rdseed::destination_register::mask >> rdseed::destination_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_rdseed_operand_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::operand_size::get() == (rdseed::operand_size::mask >> rdseed::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::operand_size::get(rdseed::operand_size::mask) == (rdseed::operand_size::mask >> rdseed::operand_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(rdseed::operand_size::get_if_exists() == (rdseed::operand_size::mask >> rdseed::operand_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::scaling::get() == (vmclear::scaling::mask >> vmclear::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::scaling::get(vmclear::scaling::mask) == (vmclear::scaling::mask >> vmclear::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::scaling::get_if_exists() == (vmclear::scaling::mask >> vmclear::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::address_size::get() == (vmclear::address_size::mask >> vmclear::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::address_size::get(vmclear::address_size::mask) == (vmclear::address_size::mask >> vmclear::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::address_size::get_if_exists() == (vmclear::address_size::mask >> vmclear::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::segment_register::get() == (vmclear::segment_register::mask >> vmclear::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::segment_register::get(vmclear::segment_register::mask) == (vmclear::segment_register::mask >> vmclear::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::segment_register::get_if_exists() == (vmclear::segment_register::mask >> vmclear::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::index_reg::get() == (vmclear::index_reg::mask >> vmclear::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::index_reg::get(vmclear::index_reg::mask) == (vmclear::index_reg::mask >> vmclear::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::index_reg::get_if_exists() == (vmclear::index_reg::mask >> vmclear::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::mask;
    CHECK(vmclear::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::mask;
    CHECK(vmclear::index_reg_invalid::is_enabled(vmclear::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::mask;
    CHECK(vmclear::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::base_reg::get() == (vmclear::base_reg::mask >> vmclear::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::base_reg::get(vmclear::base_reg::mask) == (vmclear::base_reg::mask >> vmclear::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmclear::base_reg::get_if_exists() == (vmclear::base_reg::mask >> vmclear::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmclear_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::mask;
    CHECK(vmclear::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::mask;
    CHECK(vmclear::base_reg_invalid::is_enabled(vmclear::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::mask;
    CHECK(vmclear::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmclear::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::scaling::get() == (vmptrld::scaling::mask >> vmptrld::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::scaling::get(vmptrld::scaling::mask) == (vmptrld::scaling::mask >> vmptrld::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::scaling::get_if_exists() == (vmptrld::scaling::mask >> vmptrld::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::address_size::get() == (vmptrld::address_size::mask >> vmptrld::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::address_size::get(vmptrld::address_size::mask) == (vmptrld::address_size::mask >> vmptrld::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::address_size::get_if_exists() == (vmptrld::address_size::mask >> vmptrld::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::segment_register::get() == (vmptrld::segment_register::mask >> vmptrld::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::segment_register::get(vmptrld::segment_register::mask) == (vmptrld::segment_register::mask >> vmptrld::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::segment_register::get_if_exists() == (vmptrld::segment_register::mask >> vmptrld::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::index_reg::get() == (vmptrld::index_reg::mask >> vmptrld::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::index_reg::get(vmptrld::index_reg::mask) == (vmptrld::index_reg::mask >> vmptrld::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::index_reg::get_if_exists() == (vmptrld::index_reg::mask >> vmptrld::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::mask;
    CHECK(vmptrld::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::mask;
    CHECK(vmptrld::index_reg_invalid::is_enabled(vmptrld::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::mask;
    CHECK(vmptrld::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::base_reg::get() == (vmptrld::base_reg::mask >> vmptrld::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::base_reg::get(vmptrld::base_reg::mask) == (vmptrld::base_reg::mask >> vmptrld::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrld::base_reg::get_if_exists() == (vmptrld::base_reg::mask >> vmptrld::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrld_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::mask;
    CHECK(vmptrld::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::mask;
    CHECK(vmptrld::base_reg_invalid::is_enabled(vmptrld::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::mask;
    CHECK(vmptrld::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrld::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::scaling::get() == (vmptrst::scaling::mask >> vmptrst::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::scaling::get(vmptrst::scaling::mask) == (vmptrst::scaling::mask >> vmptrst::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::scaling::get_if_exists() == (vmptrst::scaling::mask >> vmptrst::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::address_size::get() == (vmptrst::address_size::mask >> vmptrst::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::address_size::get(vmptrst::address_size::mask) == (vmptrst::address_size::mask >> vmptrst::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::address_size::get_if_exists() == (vmptrst::address_size::mask >> vmptrst::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::segment_register::get() == (vmptrst::segment_register::mask >> vmptrst::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::segment_register::get(vmptrst::segment_register::mask) == (vmptrst::segment_register::mask >> vmptrst::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::segment_register::get_if_exists() == (vmptrst::segment_register::mask >> vmptrst::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::index_reg::get() == (vmptrst::index_reg::mask >> vmptrst::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::index_reg::get(vmptrst::index_reg::mask) == (vmptrst::index_reg::mask >> vmptrst::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::index_reg::get_if_exists() == (vmptrst::index_reg::mask >> vmptrst::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::mask;
    CHECK(vmptrst::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::mask;
    CHECK(vmptrst::index_reg_invalid::is_enabled(vmptrst::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::mask;
    CHECK(vmptrst::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::base_reg::get() == (vmptrst::base_reg::mask >> vmptrst::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::base_reg::get(vmptrst::base_reg::mask) == (vmptrst::base_reg::mask >> vmptrst::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmptrst::base_reg::get_if_exists() == (vmptrst::base_reg::mask >> vmptrst::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmptrst_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::mask;
    CHECK(vmptrst::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::mask;
    CHECK(vmptrst::base_reg_invalid::is_enabled(vmptrst::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::mask;
    CHECK(vmptrst::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmptrst::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::scaling::get() == (vmxon::scaling::mask >> vmxon::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::scaling::get(vmxon::scaling::mask) == (vmxon::scaling::mask >> vmxon::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::scaling::get_if_exists() == (vmxon::scaling::mask >> vmxon::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::address_size::get() == (vmxon::address_size::mask >> vmxon::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::address_size::get(vmxon::address_size::mask) == (vmxon::address_size::mask >> vmxon::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::address_size::get_if_exists() == (vmxon::address_size::mask >> vmxon::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::segment_register::get() == (vmxon::segment_register::mask >> vmxon::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::segment_register::get(vmxon::segment_register::mask) == (vmxon::segment_register::mask >> vmxon::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::segment_register::get_if_exists() == (vmxon::segment_register::mask >> vmxon::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::index_reg::get() == (vmxon::index_reg::mask >> vmxon::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::index_reg::get(vmxon::index_reg::mask) == (vmxon::index_reg::mask >> vmxon::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::index_reg::get_if_exists() == (vmxon::index_reg::mask >> vmxon::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::mask;
    CHECK(vmxon::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::mask;
    CHECK(vmxon::index_reg_invalid::is_enabled(vmxon::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::mask;
    CHECK(vmxon::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::base_reg::get() == (vmxon::base_reg::mask >> vmxon::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::base_reg::get(vmxon::base_reg::mask) == (vmxon::base_reg::mask >> vmxon::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmxon::base_reg::get_if_exists() == (vmxon::base_reg::mask >> vmxon::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmxon_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::mask;
    CHECK(vmxon::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::mask;
    CHECK(vmxon::base_reg_invalid::is_enabled(vmxon::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::mask;
    CHECK(vmxon::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmxon::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::scaling::get() == (xrstors::scaling::mask >> xrstors::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::scaling::get(xrstors::scaling::mask) == (xrstors::scaling::mask >> xrstors::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::scaling::get_if_exists() == (xrstors::scaling::mask >> xrstors::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::address_size::get() == (xrstors::address_size::mask >> xrstors::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::address_size::get(xrstors::address_size::mask) == (xrstors::address_size::mask >> xrstors::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::address_size::get_if_exists() == (xrstors::address_size::mask >> xrstors::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::segment_register::get() == (xrstors::segment_register::mask >> xrstors::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::segment_register::get(xrstors::segment_register::mask) == (xrstors::segment_register::mask >> xrstors::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::segment_register::get_if_exists() == (xrstors::segment_register::mask >> xrstors::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::index_reg::get() == (xrstors::index_reg::mask >> xrstors::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::index_reg::get(xrstors::index_reg::mask) == (xrstors::index_reg::mask >> xrstors::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::index_reg::get_if_exists() == (xrstors::index_reg::mask >> xrstors::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::mask;
    CHECK(xrstors::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::mask;
    CHECK(xrstors::index_reg_invalid::is_enabled(xrstors::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::mask;
    CHECK(xrstors::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::base_reg::get() == (xrstors::base_reg::mask >> xrstors::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::base_reg::get(xrstors::base_reg::mask) == (xrstors::base_reg::mask >> xrstors::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xrstors::base_reg::get_if_exists() == (xrstors::base_reg::mask >> xrstors::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xrstors_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::mask;
    CHECK(xrstors::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::mask;
    CHECK(xrstors::base_reg_invalid::is_enabled(xrstors::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::mask;
    CHECK(xrstors::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xrstors::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::scaling::get() == (xsaves::scaling::mask >> xsaves::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::scaling::get(xsaves::scaling::mask) == (xsaves::scaling::mask >> xsaves::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::scaling::get_if_exists() == (xsaves::scaling::mask >> xsaves::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::address_size::get() == (xsaves::address_size::mask >> xsaves::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::address_size::get(xsaves::address_size::mask) == (xsaves::address_size::mask >> xsaves::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::address_size::get_if_exists() == (xsaves::address_size::mask >> xsaves::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::segment_register::get() == (xsaves::segment_register::mask >> xsaves::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::segment_register::get(xsaves::segment_register::mask) == (xsaves::segment_register::mask >> xsaves::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::segment_register::get_if_exists() == (xsaves::segment_register::mask >> xsaves::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::index_reg::get() == (xsaves::index_reg::mask >> xsaves::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::index_reg::get(xsaves::index_reg::mask) == (xsaves::index_reg::mask >> xsaves::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::index_reg::get_if_exists() == (xsaves::index_reg::mask >> xsaves::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::mask;
    CHECK(xsaves::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::mask;
    CHECK(xsaves::index_reg_invalid::is_enabled(xsaves::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::mask;
    CHECK(xsaves::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::base_reg::get() == (xsaves::base_reg::mask >> xsaves::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::base_reg::get(xsaves::base_reg::mask) == (xsaves::base_reg::mask >> xsaves::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(xsaves::base_reg::get_if_exists() == (xsaves::base_reg::mask >> xsaves::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_xsaves_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::mask;
    CHECK(xsaves::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::mask;
    CHECK(xsaves::base_reg_invalid::is_enabled(xsaves::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::mask;
    CHECK(xsaves::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(xsaves::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::scaling::get() == (vmread::scaling::mask >> vmread::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::scaling::get(vmread::scaling::mask) == (vmread::scaling::mask >> vmread::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::scaling::get_if_exists() == (vmread::scaling::mask >> vmread::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg1::get() == (vmread::reg1::mask >> vmread::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg1::get(vmread::reg1::mask) == (vmread::reg1::mask >> vmread::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg1::get_if_exists() == (vmread::reg1::mask >> vmread::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::address_size::get() == (vmread::address_size::mask >> vmread::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::address_size::get(vmread::address_size::mask) == (vmread::address_size::mask >> vmread::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::address_size::get_if_exists() == (vmread::address_size::mask >> vmread::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::mem_reg::get() == (vmread::mem_reg::mask >> vmread::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::mem_reg::get(vmread::mem_reg::mask) == (vmread::mem_reg::mask >> vmread::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::mem_reg::get_if_exists() == (vmread::mem_reg::mask >> vmread::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::segment_register::get() == (vmread::segment_register::mask >> vmread::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::segment_register::get(vmread::segment_register::mask) == (vmread::segment_register::mask >> vmread::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::segment_register::get_if_exists() == (vmread::segment_register::mask >> vmread::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::index_reg::get() == (vmread::index_reg::mask >> vmread::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::index_reg::get(vmread::index_reg::mask) == (vmread::index_reg::mask >> vmread::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::index_reg::get_if_exists() == (vmread::index_reg::mask >> vmread::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::index_reg_invalid::mask;
    CHECK(vmread::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmread::index_reg_invalid::mask;
    CHECK(vmread::index_reg_invalid::is_enabled(vmread::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmread::index_reg_invalid::mask;
    CHECK(vmread::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::base_reg::get() == (vmread::base_reg::mask >> vmread::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::base_reg::get(vmread::base_reg::mask) == (vmread::base_reg::mask >> vmread::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::base_reg::get_if_exists() == (vmread::base_reg::mask >> vmread::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::base_reg_invalid::mask;
    CHECK(vmread::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmread::base_reg_invalid::mask;
    CHECK(vmread::base_reg_invalid::is_enabled(vmread::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmread::base_reg_invalid::mask;
    CHECK(vmread::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmread::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmread_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg2::get() == (vmread::reg2::mask >> vmread::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg2::get(vmread::reg2::mask) == (vmread::reg2::mask >> vmread::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmread::reg2::get_if_exists() == (vmread::reg2::mask >> vmread::reg2::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::get() == 0xFFFFFFFFFFFFFFFUL);

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::get_if_exists() == 0xFFFFFFFFFFFFFFFUL);
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_scaling")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::scaling::get() == (vmwrite::scaling::mask >> vmwrite::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::scaling::get(vmwrite::scaling::mask) == (vmwrite::scaling::mask >> vmwrite::scaling::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::scaling::get_if_exists() == (vmwrite::scaling::mask >> vmwrite::scaling::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_reg1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg1::get() == (vmwrite::reg1::mask >> vmwrite::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg1::get(vmwrite::reg1::mask) == (vmwrite::reg1::mask >> vmwrite::reg1::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg1::get_if_exists() == (vmwrite::reg1::mask >> vmwrite::reg1::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_address_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::address_size::get() == (vmwrite::address_size::mask >> vmwrite::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::address_size::get(vmwrite::address_size::mask) == (vmwrite::address_size::mask >> vmwrite::address_size::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::address_size::get_if_exists() == (vmwrite::address_size::mask >> vmwrite::address_size::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_mem_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::mem_reg::get() == (vmwrite::mem_reg::mask >> vmwrite::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::mem_reg::get(vmwrite::mem_reg::mask) == (vmwrite::mem_reg::mask >> vmwrite::mem_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::mem_reg::get_if_exists() == (vmwrite::mem_reg::mask >> vmwrite::mem_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_segment_register")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::segment_register::get() == (vmwrite::segment_register::mask >> vmwrite::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::segment_register::get(vmwrite::segment_register::mask) == (vmwrite::segment_register::mask >> vmwrite::segment_register::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::segment_register::get_if_exists() == (vmwrite::segment_register::mask >> vmwrite::segment_register::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_index_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::index_reg::get() == (vmwrite::index_reg::mask >> vmwrite::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::index_reg::get(vmwrite::index_reg::mask) == (vmwrite::index_reg::mask >> vmwrite::index_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::index_reg::get_if_exists() == (vmwrite::index_reg::mask >> vmwrite::index_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_index_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::mask;
    CHECK(vmwrite::index_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::index_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::mask;
    CHECK(vmwrite::index_reg_invalid::is_enabled(vmwrite::index_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::index_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::mask;
    CHECK(vmwrite::index_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::index_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_base_reg")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::base_reg::get() == (vmwrite::base_reg::mask >> vmwrite::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::base_reg::get(vmwrite::base_reg::mask) == (vmwrite::base_reg::mask >> vmwrite::base_reg::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::base_reg::get_if_exists() == (vmwrite::base_reg::mask >> vmwrite::base_reg::from));
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_base_reg_invalid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::mask;
    CHECK(vmwrite::base_reg_invalid::is_enabled());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::base_reg_invalid::is_disabled());

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::mask;
    CHECK(vmwrite::base_reg_invalid::is_enabled(vmwrite::base_reg_invalid::mask));
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::base_reg_invalid::is_disabled(0x0));

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::mask;
    CHECK(vmwrite::base_reg_invalid::is_enabled_if_exists());
    g_vmcs_fields[addr] = 0UL;
    CHECK(vmwrite::base_reg_invalid::is_disabled_if_exists());
}

TEST_CASE("vmcs_vm_exit_instruction_information_vmwrite_reg2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg2::get() == (vmwrite::reg2::mask >> vmwrite::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg2::get(vmwrite::reg2::mask) == (vmwrite::reg2::mask >> vmwrite::reg2::from));

    g_vmcs_fields[addr] = 0xFFFFFFFFFFFFFFFUL;
    CHECK(vmwrite::reg2::get_if_exists() == (vmwrite::reg2::mask >> vmwrite::reg2::from));
}

#endif
