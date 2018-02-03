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

#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

auto
setup_vmcs_unhandled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64>();

    mocks.NeverCall(vmcs, vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs, vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs, vmcs_intel_x64::load);
    mocks.NeverCall(vmcs, vmcs_intel_x64::clear);
    mocks.ExpectCall(vmcs, vmcs_intel_x64::resume);

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    g_vmcs_fields[vmcs::exit_reason::addr] = reason;
    return vmcs;
}

auto
setup_vmcs_handled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64>();

    mocks.OnCall(vmcs, vmcs_intel_x64::launch);
    mocks.OnCall(vmcs, vmcs_intel_x64::promote);
    mocks.OnCall(vmcs, vmcs_intel_x64::load);
    mocks.OnCall(vmcs, vmcs_intel_x64::clear);

    if (reason != exit_reason::basic_exit_reason::vmxoff) {
        mocks.ExpectCall(vmcs, vmcs_intel_x64::resume);
    }

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFFFFFFFFFFUL;
    g_vmcs_fields[vmcs::exit_reason::addr] = reason;

    return vmcs;
}

auto
setup_vmcs_halt(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64>();

    mocks.NeverCall(vmcs, vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs, vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs, vmcs_intel_x64::load);
    mocks.NeverCall(vmcs, vmcs_intel_x64::clear);
    mocks.NeverCall(vmcs, vmcs_intel_x64::resume);

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFFFFFFFFFFUL;
    g_vmcs_fields[vmcs::exit_reason::addr] = reason;

    return vmcs;
}

auto
setup_vmcs_promote(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64>();

    mocks.NeverCall(vmcs, vmcs_intel_x64::launch);
    mocks.ExpectCall(vmcs, vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs, vmcs_intel_x64::load);
    mocks.NeverCall(vmcs, vmcs_intel_x64::clear);
    mocks.NeverCall(vmcs, vmcs_intel_x64::resume);

    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFFFFFFFFFFUL;
    g_vmcs_fields[vmcs::exit_reason::addr] = reason;

    return vmcs;
}

exit_handler_intel_x64
setup_ehlr(gsl::not_null<vmcs_intel_x64 *> vmcs)
{
    auto ehlr = exit_handler_intel_x64{};
    ehlr.set_vmcs(vmcs);
    ehlr.set_state_save(&g_state_save);

    g_rip = ehlr.m_state_save->rip + g_vmcs_fields[vmcs::vm_exit_instruction_length::addr];
    return ehlr;
}

TEST_CASE("exit_handler: stop")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_halt(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.stop());
}

TEST_CASE("exit_handler: promote")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_promote(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    auto addr = reinterpret_cast<const void *>(0x1000);
    CHECK_NOTHROW(ehlr.promote(addr));
}

TEST_CASE("exit_handler: resume")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_unhandled(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.resume());
}

TEST_CASE("exit_handler: advance_and_resume")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_unhandled(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.advance_and_resume());
}

TEST_CASE("exit_handler: vm_exit_reason_unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_unhandled(mocks, 0x0000BEEF);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.dispatch());
}

TEST_CASE("exit_handler: vm_exit_reason_cpuid")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::cpuid);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_invd")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::invd);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_invalid_opcode")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = 0x0000BEEF;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_invalid_magic")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = 0;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_protocol_version")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

    CHECK(ehlr.m_state_save->rbx == VMCALL_VERSION);
    CHECK(ehlr.m_state_save->rsi == 0);
    CHECK(ehlr.m_state_save->r08 == 0);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_bareflank_version")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 1;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

    CHECK(ehlr.m_state_save->rbx == BAREFLANK_VERSION_MAJOR);
    CHECK(ehlr.m_state_save->rsi == BAREFLANK_VERSION_MINOR);
    CHECK(ehlr.m_state_save->r08 == BAREFLANK_VERSION_PATCH);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_user_version")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 10;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

    CHECK(ehlr.m_state_save->rbx == USER_VERSION_MAJOR);
    CHECK(ehlr.m_state_save->rsi == USER_VERSION_MINOR);
    CHECK(ehlr.m_state_save->r08 == USER_VERSION_PATCH);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_unknown_version")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0x0000BEEF;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_registers")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_REGISTERS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 1;
    ehlr.m_state_save->rbx = 2;
    ehlr.m_state_save->rsi = 3;
    ehlr.m_state_save->r08 = 4;
    ehlr.m_state_save->r09 = 5;
    ehlr.m_state_save->r10 = 6;
    ehlr.m_state_save->r11 = 7;
    ehlr.m_state_save->r12 = 8;
    ehlr.m_state_save->r13 = 9;
    ehlr.m_state_save->r14 = 10;
    ehlr.m_state_save->r15 = 11;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_unittest")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_UNITTEST;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

#ifdef INCLUDE_LIBCXX_UNITTESTS
    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);

#else
    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

#endif
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_event")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_EVENT;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_start")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_START;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_stop")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_STOP;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = 0x0000BEEF;                         // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    memcpy(static_cast<char *>(g_map), g_msg.data(), g_msg.size());

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_input_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_output_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_input_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_output_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_output_size_too_small")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_input_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_output_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_map_fails")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    mocks.OnCallFunc(bfn::map_with_cr3).Throw(std::runtime_error("error"));

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_unformatted_success")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = reinterpret_cast<uint64_t>(g_map);  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = reinterpret_cast<uint64_t>(g_map);  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    memcpy(static_cast<char *>(g_map), g_msg.data(), g_msg.size());

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_input_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_output_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_input_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_output_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_output_size_too_small")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_input_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_output_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_map_fails")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    mocks.OnCallFunc(bfn::map_with_cr3).Throw(std::runtime_error("error"));

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_invalid")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = reinterpret_cast<uint64_t>(g_map);  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = reinterpret_cast<uint64_t>(g_map);  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    std::string msg = "hello world";
    memcpy(static_cast<char *>(g_map), msg.data(), msg.size());

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_string_json_success")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = reinterpret_cast<uint64_t>(g_map);  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = reinterpret_cast<uint64_t>(g_map);  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    memcpy(static_cast<char *>(g_map), g_msg.data(), g_msg.size());

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_input_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_output_nullptr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_input_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_output_size_0")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_output_size_too_small")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_input_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_output_size_too_big")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_map_fails")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    mocks.OnCallFunc(bfn::map_with_cr3).Throw(std::runtime_error("error"));

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_data_unformatted_success")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = reinterpret_cast<uint64_t>(g_map);  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = reinterpret_cast<uint64_t>(g_map);  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    memcpy(static_cast<char *>(g_map), g_msg.data(), g_msg.size());

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(ehlr.m_state_save->rip == g_rip);
    CHECK(bfscast(int64_t, ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_data_unknown_type")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_NONE;                   // r04
    ehlr.m_state_save->r08 = reinterpret_cast<uint64_t>(g_map);  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = reinterpret_cast<uint64_t>(g_map);  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    memcpy(static_cast<char *>(g_map), g_msg.data(), g_msg.size());
    CHECK_NOTHROW(ehlr.dispatch());
}

TEST_CASE("exit_handler: vm_exit_reason_vmcall_unittests")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01

    CHECK_NOTHROW(ehlr.dispatch());
}

TEST_CASE("exit_handler: vm_exit_reason_vmxoff")
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    g_vmcs_fields[vmcs::guest_cr3::addr] = 0x1000;
    g_vmcs_fields[vmcs::guest_gdtr_limit::addr] = 0x4;
    g_vmcs_fields[vmcs::guest_gdtr_base::addr] = 0x432000;

    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmxoff);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_THROWS(ehlr.dispatch());

    g_vmcs_fields[vmcs::guest_cr3::addr] = 0x0;
    g_vmcs_fields[vmcs::guest_gdtr_limit::addr] = 0x0;
    g_vmcs_fields[vmcs::guest_gdtr_base::addr] = 0x0;
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_debug_ctl")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_debugctl::addr] = 0x0000000200000001;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_debugctl::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x1);
    CHECK(ehlr.m_state_save->rdx == 0x2);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_pat")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_pat::addr] = 0x0000000300000002;
    ehlr.m_state_save->rcx = x64::msrs::ia32_pat::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x2);
    CHECK(ehlr.m_state_save->rdx == 0x3);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_efer")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_efer::addr] = 0x0000000400000003;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_efer::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x3);
    CHECK(ehlr.m_state_save->rdx == 0x4);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_perf")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_perf_global_ctrl::addr] = 0x0000000400000003;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_perf_global_ctrl::addr;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x3);
    CHECK(ehlr.m_state_save->rdx == 0x4);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_cs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_sysenter_cs::addr] = 0x0000000500000004;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_cs::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x4);
    CHECK(ehlr.m_state_save->rdx == 0x5);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_esp")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_sysenter_esp::addr] = 0x0000000600000005;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_esp::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x5);
    CHECK(ehlr.m_state_save->rdx == 0x6);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_eip")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_ia32_sysenter_eip::addr] = 0x0000000700000006;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_eip::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x6);
    CHECK(ehlr.m_state_save->rdx == 0x7);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_fs_base")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_fs_base::addr] = 0x0000000800000007;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_fs_base::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x7);
    CHECK(ehlr.m_state_save->rdx == 0x8);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_gs_base")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_vmcs_fields[vmcs::guest_gs_base::addr] = 0x0000000900000008;
    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_gs_base::addr;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x8);
    CHECK(ehlr.m_state_save->rdx == 0x9);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_default")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_msrs[0x10] = 0x0000000A00000009;
    ehlr.m_state_save->rcx = 0x10;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0x9);
    CHECK(ehlr.m_state_save->rdx == 0xA);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_rdmsr_ignore")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    g_msrs[0x31] = 0x0;
    ehlr.m_state_save->rcx = 0x31;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(ehlr.m_state_save->rax == 0);
    CHECK(ehlr.m_state_save->rdx == 0);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_debug_ctrl")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_debugctl::addr;
    ehlr.m_state_save->rax = 0x1;
    ehlr.m_state_save->rdx = 0x2;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[ vmcs::guest_ia32_debugctl::addr] == 0x0000000200000001);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_pat")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = x64::msrs::ia32_pat::addr;
    ehlr.m_state_save->rax = 0x2;
    ehlr.m_state_save->rdx = 0x3;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_pat::addr] == 0x0000000300000002);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_efer")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_efer::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_efer::addr] == 0x0000000400000003);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_perf")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_perf_global_ctrl::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] =
        intel_x64::msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_perf_global_ctrl::addr] == 0x0000000400000003);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_cs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_cs::addr;
    ehlr.m_state_save->rax = 0x4;
    ehlr.m_state_save->rdx = 0x5;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_sysenter_cs::addr] == 0x0000000500000004);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_esp")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_esp::addr;
    ehlr.m_state_save->rax = 0x5;
    ehlr.m_state_save->rdx = 0x6;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_sysenter_esp::addr] == 0x0000000600000005);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_eip")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_sysenter_eip::addr;
    ehlr.m_state_save->rax = 0x6;
    ehlr.m_state_save->rdx = 0x7;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_ia32_sysenter_eip::addr] == 0x0000000700000006);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_fs_base")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_fs_base::addr;
    ehlr.m_state_save->rax = 0x7;
    ehlr.m_state_save->rdx = 0x8;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_fs_base::addr] == 0x0000000800000007);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_gs_base")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = intel_x64::msrs::ia32_gs_base::addr;
    ehlr.m_state_save->rax = 0x8;
    ehlr.m_state_save->rdx = 0x9;

    CHECK_NOTHROW(ehlr.dispatch());

    CHECK(g_vmcs_fields[vmcs::guest_gs_base::addr] == 0x0000000900000008);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_reason_wrmsr_default")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = 0x10;
    ehlr.m_state_save->rax = 0x9;
    ehlr.m_state_save->rdx = 0xA;

    CHECK_NOTHROW(ehlr.dispatch());
    CHECK(g_msrs[0x10] == 0x0000000A00000009);
    CHECK(ehlr.m_state_save->rip == g_rip);
}

TEST_CASE("exit_handler: vm_exit_failure_check")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_unhandled(mocks, exit_reason::basic_exit_reason::xrstors | 0x80000000);
    auto ehlr = setup_ehlr(vmcs);

    mocks.OnCallFunc(bfvmm::intel_x64::check::all);

    CHECK_NOTHROW(ehlr.dispatch());
}

TEST_CASE("exit_handler: halt")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs_halt(mocks, exit_reason::basic_exit_reason::xrstors);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr.halt());
}

#endif
