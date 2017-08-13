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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace debug;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
}

void
proc_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= mask << 32; }

void
proc_ctl_disallow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~(mask << 32); }

TEST_CASE("debug_dump")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump());
}

TEST_CASE("debug_dump_16bit_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_16bit_control_fields());
}

TEST_CASE("debug_dump_16bit_guest_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_16bit_guest_state_fields());
}

TEST_CASE("debug_dump_16bit_host_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_16bit_host_state_fields());
}

TEST_CASE("debug_dump_64bit_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_64bit_control_fields());
}

TEST_CASE("debug_dump_64bit_read_only_data_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_64bit_read_only_data_field());
}

TEST_CASE("debug_dump_64bit_guest_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_64bit_guest_state_fields());
}

TEST_CASE("debug_dump_64bit_host_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_64bit_host_state_fields());
}

TEST_CASE("debug_dump_32bit_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_32bit_control_fields());
}

TEST_CASE("debug_dump_32bit_read_only_data_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_32bit_read_only_data_fields());
}

TEST_CASE("debug_dump_32bit_guest_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_32bit_guest_state_fields());
}

TEST_CASE("debug_dump_32bit_host_state_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_32bit_host_state_field());
}

TEST_CASE("debug_dump_natural_width_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_natural_width_control_fields());
}

TEST_CASE("debug_dump_natural_width_read_only_data_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_natural_width_read_only_data_fields());
}

TEST_CASE("debug_dump_natural_width_guest_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_natural_width_guest_state_fields());
}

TEST_CASE("debug_dump_natural_width_host_state_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_natural_width_host_state_fields());
}

TEST_CASE("debug_dump_vmx_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_vmx_controls());
}

TEST_CASE("debug_dump_pin_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_pin_based_vm_execution_controls());
}

TEST_CASE("debug_dump_primary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_primary_processor_based_vm_execution_controls());
}

TEST_CASE("debug_dump_secondary_processor_based_vm_execution_controls")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    CHECK_NOTHROW(dump_secondary_processor_based_vm_execution_controls());

    proc_ctl_disallow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    CHECK_NOTHROW(dump_secondary_processor_based_vm_execution_controls());
}

TEST_CASE("debug_dump_vm_exit_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_vm_exit_control_fields());
}

TEST_CASE("debug_dump_vm_entry_control_fields")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(dump_vm_entry_control_fields());
}

TEST_CASE("debug_dump_vmcs_field")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto addr = 0x00UL;
    auto name = "test";
    auto exists = true;

    CHECK_NOTHROW(dump_vmcs_field(addr, name, exists));
    CHECK_NOTHROW(dump_vmcs_field(addr, name, !exists));
}

TEST_CASE("debug_dump_vm_control")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto name = "test";
    auto is_set = true;

    CHECK_NOTHROW(dump_vm_control(name, is_set));
    CHECK_NOTHROW(dump_vm_control(name, !is_set));
}

#endif
