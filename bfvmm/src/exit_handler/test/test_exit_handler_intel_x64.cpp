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

#include <test.h>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

#include <intrinsics/msrs_intel_x64.h>

using namespace x64;
using namespace intel_x64;

vmcs::field_type g_field = 0;
vmcs::value_type g_value = 0;
vmcs::value_type g_exit_reason = 0;
vmcs::value_type g_exit_qualification = 0;
vmcs::value_type g_exit_instruction_length = 8;
vmcs::value_type g_exit_instruction_information = 0;

static std::map<msrs::field_type, msrs::value_type> g_msrs;

uint64_t g_rip = 0;

extern "C" bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    switch (field)
    {
        case VMCS_EXIT_REASON:
            *val = g_exit_reason;
            break;
        case VMCS_EXIT_QUALIFICATION:
            *val = g_exit_qualification;
            break;
        case VMCS_VM_EXIT_INSTRUCTION_LENGTH:
            *val = g_exit_instruction_length;
            break;
        case VMCS_VM_EXIT_INSTRUCTION_INFORMATION:
            *val = g_exit_instruction_information;
            break;
        default:
            g_field = field;
            *val = g_value;
            break;
    }

    return true;
}

extern "C"  bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_field = field;
    g_value = val;

    return true;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" void
__stop(void) noexcept
{ }

extern "C" void
__wbinvd(void) noexcept
{ }

extern "C" void
__cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{ (void) eax; (void) ebx; (void) ecx; (void) edx; }

auto
setup_vmcs_unhandled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

auto
setup_vmcs_handled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.OnCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

auto
setup_vmcs_halt(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

exit_handler_intel_x64
setup_ehlr(const std::shared_ptr<vmcs_intel_x64> &vmcs)
{
    auto ehlr = exit_handler_intel_x64{};
    ehlr.set_vmcs(vmcs);
    ehlr.set_state_save(std::make_shared<state_save_intel_x64>());

    g_rip = ehlr.m_state_save->rip + g_exit_instruction_length;
    return ehlr;
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, 0x0000BEEF);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_exception_or_non_maskable_interrupt()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::exception_or_non_maskable_interrupt);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_external_interrupt()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::external_interrupt);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_triple_fault()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::triple_fault);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_init_signal()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::init_signal);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_sipi()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::sipi);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_smi()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::smi);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_other_smi()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::other_smi);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_interrupt_window()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::interrupt_window);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_nmi_window()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::nmi_window);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_task_switch()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::task_switch);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_cpuid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::cpuid);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_getsec()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::getsec);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_hlt()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::hlt);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invd()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::invd);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invlpg()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::invlpg);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdpmc()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rdpmc);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtsc()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rdtsc);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rsm()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rsm);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_invalid_opcode()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = 0x0000BEEF;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_invalid_magic()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_protocol_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == VMCALL_VERSION);
        this->expect_true(ehlr.m_state_save->rsi == 0);
        this->expect_true(ehlr.m_state_save->r08 == 0);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_bareflank_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 1;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == BAREFLANK_VERSION_MAJOR);
        this->expect_true(ehlr.m_state_save->rsi == BAREFLANK_VERSION_MINOR);
        this->expect_true(ehlr.m_state_save->r08 == BAREFLANK_VERSION_PATCH);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_user_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == USER_VERSION_MAJOR);
        this->expect_true(ehlr.m_state_save->rsi == USER_VERSION_MINOR);
        this->expect_true(ehlr.m_state_save->r08 == USER_VERSION_PATCH);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_unknown_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0x0000BEEF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_registers()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

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

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_unittest()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_UNITTEST;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_event()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_EVENT;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

auto g_msg = "{\"msg\":\"hello world\"}"_s;
auto g_map = std::make_unique<char[]>(100);

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    mocks.OnCall(mm, memory_manager_x64::alloc_map).Return(g_map.get());
    mocks.OnCall(mm, memory_manager_x64::free_map);

    return mm;
}

static auto
setup_pt(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_page_table_x64::instance).Return(pt);

    mocks.OnCall(pt, root_page_table_x64::map);
    mocks.OnCall(pt, root_page_table_x64::unmap);

    return pt;
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = 0x0000BEEF;                         // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_invalid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    auto msg = "hello world"_s;
    __builtin_memcpy(g_map.get(), msg.data(), msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmclear()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmclear);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmlaunch()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmlaunch);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrld()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmptrld);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrst()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmptrst);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmread()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmread);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmresume()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmresume);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmwrite()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmwrite);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxoff()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::vmxoff);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxon()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmxon);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_control_register_accesses()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::control_register_accesses);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mov_dr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::mov_dr);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_io_instruction()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::io_instruction);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_debug_ctl()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000200000001;
    ehlr.m_state_save->rcx = msrs::ia32_debugctl::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_debugctl::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x1);
        this->expect_true(ehlr.m_state_save->rdx == 0x2);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_pat()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000300000002;
    ehlr.m_state_save->rcx = msrs::ia32_pat::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_PAT);
        this->expect_true(ehlr.m_state_save->rax == 0x2);
        this->expect_true(ehlr.m_state_save->rdx == 0x3);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_efer()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000400000003;
    ehlr.m_state_save->rcx = msrs::ia32_efer::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_efer::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x3);
        this->expect_true(ehlr.m_state_save->rdx == 0x4);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_perf()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000400000003;
    ehlr.m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
        this->expect_true(ehlr.m_state_save->rax == 0x3);
        this->expect_true(ehlr.m_state_save->rdx == 0x4);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_cs()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000500000004;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_cs::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_cs::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x4);
        this->expect_true(ehlr.m_state_save->rdx == 0x5);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_esp()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000600000005;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_esp::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        this->expect_true(ehlr.m_state_save->rax == 0x5);
        this->expect_true(ehlr.m_state_save->rdx == 0x6);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_eip()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000700000006;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_eip::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        this->expect_true(ehlr.m_state_save->rax == 0x6);
        this->expect_true(ehlr.m_state_save->rdx == 0x7);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_fs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000800000007;
    ehlr.m_state_save->rcx = msrs::ia32_fs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_FS_BASE);
        this->expect_true(ehlr.m_state_save->rax == 0x7);
        this->expect_true(ehlr.m_state_save->rdx == 0x8);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_gs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000900000008;
    ehlr.m_state_save->rcx = msrs::ia32_gs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_GS_BASE);
        this->expect_true(ehlr.m_state_save->rax == 0x8);
        this->expect_true(ehlr.m_state_save->rdx == 0x9);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_default()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_msrs[0x10] = 0x0000000A00000009;
    ehlr.m_state_save->rcx = 0x10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(ehlr.m_state_save->rax == 0x9);
        this->expect_true(ehlr.m_state_save->rdx == 0xA);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_ignore()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_msrs[0x31] = 0x0;
    ehlr.m_state_save->rcx = 0x31;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(ehlr.m_state_save->rax == 0);
        this->expect_true(ehlr.m_state_save->rdx == 0);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_debug_ctrl()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_debugctl::addr;
    ehlr.m_state_save->rax = 0x1;
    ehlr.m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_debugctl::addr);
        this->expect_true(g_value == 0x0000000200000001);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_pat()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_pat::addr;
    ehlr.m_state_save->rax = 0x2;
    ehlr.m_state_save->rdx = 0x3;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_PAT);
        this->expect_true(g_value == 0x0000000300000002);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_efer()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_efer::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_efer::addr);
        this->expect_true(g_value == 0x0000000400000003);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_perf()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
        this->expect_true(g_value == 0x0000000400000003);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_cs()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_cs::addr;
    ehlr.m_state_save->rax = 0x4;
    ehlr.m_state_save->rdx = 0x5;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_cs::addr);
        this->expect_true(g_value == 0x0000000500000004);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_esp()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_esp::addr;
    ehlr.m_state_save->rax = 0x5;
    ehlr.m_state_save->rdx = 0x6;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        this->expect_true(g_value == 0x0000000600000005);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_eip()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_eip::addr;
    ehlr.m_state_save->rax = 0x6;
    ehlr.m_state_save->rdx = 0x7;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        this->expect_true(g_value == 0x0000000700000006);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_fs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_fs_base::addr;
    ehlr.m_state_save->rax = 0x7;
    ehlr.m_state_save->rdx = 0x8;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_FS_BASE);
        this->expect_true(g_value == 0x0000000800000007);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_gs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_gs_base::addr;
    ehlr.m_state_save->rax = 0x8;
    ehlr.m_state_save->rdx = 0x9;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == VMCS_GUEST_GS_BASE);
        this->expect_true(g_value == 0x0000000900000008);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_default()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = 0x10;
    ehlr.m_state_save->rax = 0x9;
    ehlr.m_state_save->rdx = 0xA;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(g_msrs[0x10] = 0x0000000A00000009);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_invalid_guest_state()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vm_entry_failure_invalid_guest_state);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_msr_loading()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vm_entry_failure_msr_loading);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mwait()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::mwait);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor_trap_flag()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::monitor_trap_flag);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::monitor);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_pause()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::pause);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_machine_check_event()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vm_entry_failure_machine_check_event);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_tpr_below_threshold()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::tpr_below_threshold);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_access()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::apic_access);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_virtualized_eoi()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::virtualized_eoi);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_gdtr_or_idtr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::access_to_gdtr_or_idtr);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_ldtr_or_tr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::access_to_ldtr_or_tr);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_violation()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::ept_violation);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_misconfiguration()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::ept_misconfiguration);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invept()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::invept);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtscp()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rdtscp);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmx_preemption_timer_expired()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmx_preemption_timer_expired);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invvpid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::invvpid);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wbinvd()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::wbinvd);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsetbv()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::xsetbv);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_write()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::apic_write);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdrand()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rdrand);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invpcid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::invpcid);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmfunc()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::vmfunc);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdseed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::rdseed);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsaves()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::xsaves);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xrstors()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::xrstors);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_failure_check()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::xrstors | 0x80000000);
    auto &&ehlr = setup_ehlr(vmcs);

    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_control_state);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_guest_state);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_host_state);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_to_string()
{
    auto ehlr = exit_handler_intel_x64{};

    this->expect_true(ehlr.exit_reason_to_str(exit_reason::exception_or_non_maskable_interrupt) == "exception_or_non_maskable_interrupt"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::external_interrupt) == "external_interrupt"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::triple_fault) == "triple_fault"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::init_signal) == "init_signal"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::sipi) == "sipi"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::smi) == "smi"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::other_smi) == "other_smi"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::interrupt_window) == "interrupt_window"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::nmi_window) == "nmi_window"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::task_switch) == "task_switch"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::cpuid) == "cpuid"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::getsec) == "getsec"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::hlt) == "hlt"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::invd) == "invd"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::invlpg) == "invlpg"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdpmc) == "rdpmc"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdtsc) == "rdtsc"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rsm) == "rsm"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmcall) == "vmcall"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmclear) == "vmclear"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmlaunch) == "vmlaunch"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmptrld) == "vmptrld"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmptrst) == "vmptrst"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmread) == "vmread"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmresume) == "vmresume"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmwrite) == "vmwrite"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmxoff) == "vmxoff"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmxon) == "vmxon"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::control_register_accesses) == "control_register_accesses"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::mov_dr) == "mov_dr"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::io_instruction) == "io_instruction"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdmsr) == "rdmsr"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::wrmsr) == "wrmsr"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vm_entry_failure_invalid_guest_state) == "vm_entry_failure_invalid_guest_state"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vm_entry_failure_msr_loading) == "vm_entry_failure_msr_loading"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::mwait) == "mwait"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::monitor_trap_flag) == "monitor_trap_flag"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::monitor) == "monitor"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::pause) == "pause"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vm_entry_failure_machine_check_event) == "vm_entry_failure_machine_check_event"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::tpr_below_threshold) == "tpr_below_threshold"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::apic_access) == "apic_access"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::virtualized_eoi) == "virtualized_eoi"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::access_to_gdtr_or_idtr) == "access_to_gdtr_or_idtr"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::access_to_ldtr_or_tr) == "access_to_ldtr_or_tr"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::ept_violation) == "ept_violation"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::ept_misconfiguration) == "ept_misconfiguration"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::invept) == "invept"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdtscp) == "rdtscp"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmx_preemption_timer_expired) == "vmx_preemption_timer_expired"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::invvpid) == "invvpid"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::wbinvd) == "wbinvd"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::xsetbv) == "xsetbv"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::apic_write) == "apic_write"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdrand) == "rdrand"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::invpcid) == "invpcid"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::vmfunc) == "vmfunc"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::rdseed) == "rdseed"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::xsaves) == "xsaves"_s);
    this->expect_true(ehlr.exit_reason_to_str(exit_reason::xrstors) == "xrstors"_s);
    this->expect_true(ehlr.exit_reason_to_str(0x100000) == "unknown"_s);
}

void
exit_handler_intel_x64_ut::test_halt()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_halt(mocks, exit_reason::xrstors);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.halt(); });
    });
}
