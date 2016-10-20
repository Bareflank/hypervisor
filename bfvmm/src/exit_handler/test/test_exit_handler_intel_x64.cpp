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
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

using namespace intel_x64;

uint64_t g_field = 0;
uint64_t g_value = 0;
uint64_t g_exit_reason = 0;
uint64_t g_exit_qualification = 0;
uint64_t g_exit_instruction_length = 0;
uint64_t g_exit_instruction_information = 0;

static std::map<uint32_t, uint64_t> g_msrs;

bool
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

bool
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
{
    (void) eax;
    (void) ebx;
    (void) ecx;
    (void) edx;
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_unknown()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = 0x0000BEEF;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_exception_or_non_maskable_interrupt()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::exception_or_non_maskable_interrupt;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_external_interrupt()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::external_interrupt;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_triple_fault()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::triple_fault;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_init_signal()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::init_signal;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_sipi()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::sipi;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_smi()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::smi;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_other_smi()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::other_smi;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_interrupt_window()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::interrupt_window;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_nmi_window()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::nmi_window;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_task_switch()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::task_switch;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_cpuid()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::cpuid;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_getsec()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::getsec;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_hlt()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::hlt;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invd()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::invd;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invlpg()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::invlpg;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdpmc()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdpmc;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtsc()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdtsc;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rsm()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rsm;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmcall;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmclear()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmclear;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmlaunch()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmlaunch;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrld()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmptrld;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrst()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmptrst;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmread()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmread;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmresume()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmresume;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmwrite()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmwrite;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxoff()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmxoff;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxon()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmxon;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_control_register_accesses()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::control_register_accesses;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mov_dr()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::mov_dr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_io_instruction()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::io_instruction;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_debug_ctl()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000200000001;
    eh->m_state_save->rcx = msrs::ia32_debugctl::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == vmcs::guest_ia32_debugctl::addr);
        EXPECT_TRUE(eh->m_state_save->rax == 0x1);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x2);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_pat()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000300000002;
    eh->m_state_save->rcx = msrs::ia32_pat::addr;;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PAT);
        EXPECT_TRUE(eh->m_state_save->rax == 0x2);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x3);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_efer()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = msrs::ia32_efer::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == vmcs::guest_ia32_efer::addr);
        EXPECT_TRUE(eh->m_state_save->rax == 0x3);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x4);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_perf()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
        EXPECT_TRUE(eh->m_state_save->rax == 0x3);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x4);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_cs()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000500000004;
    eh->m_state_save->rcx = msrs::ia32_sysenter_cs::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_CS);
        EXPECT_TRUE(eh->m_state_save->rax == 0x4);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x5);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_esp()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000600000005;
    eh->m_state_save->rcx = msrs::ia32_sysenter_esp::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        EXPECT_TRUE(eh->m_state_save->rax == 0x5);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x6);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_eip()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000700000006;
    eh->m_state_save->rcx = msrs::ia32_sysenter_eip::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        EXPECT_TRUE(eh->m_state_save->rax == 0x6);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x7);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_fs_base()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000800000007;
    eh->m_state_save->rcx = msrs::ia32_fs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_FS_BASE);
        EXPECT_TRUE(eh->m_state_save->rax == 0x7);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x8);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_gs_base()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000900000008;
    eh->m_state_save->rcx = msrs::ia32_gs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_GS_BASE);
        EXPECT_TRUE(eh->m_state_save->rax == 0x8);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x9);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_default()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_msrs[0x10] = 0x0000000A00000009;
    g_exit_reason = exit_reason::rdmsr;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    eh->m_state_save->rcx = 0x10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(eh->m_state_save->rax == 0x9);
        EXPECT_TRUE(eh->m_state_save->rdx == 0xA);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_ignore()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_msrs[0x31] = 0x0;
    g_exit_reason = exit_reason::rdmsr;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    eh->m_state_save->rcx = 0x31;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(eh->m_state_save->rax == 0);
        EXPECT_TRUE(eh->m_state_save->rdx == 0);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_debug_ctrl()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_debugctl::addr;
    eh->m_state_save->rax = 0x1;
    eh->m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == vmcs::guest_ia32_debugctl::addr);
        EXPECT_TRUE(g_value == 0x0000000200000001);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_pat()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_pat::addr;
    eh->m_state_save->rax = 0x2;
    eh->m_state_save->rdx = 0x3;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PAT);
        EXPECT_TRUE(g_value == 0x0000000300000002);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_efer()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_efer::addr;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == vmcs::guest_ia32_efer::addr);
        EXPECT_TRUE(g_value == 0x0000000400000003);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_perf()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
        EXPECT_TRUE(g_value == 0x0000000400000003);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_cs()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_sysenter_cs::addr;
    eh->m_state_save->rax = 0x4;
    eh->m_state_save->rdx = 0x5;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_CS);
        EXPECT_TRUE(g_value == 0x0000000500000004);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_esp()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_sysenter_esp::addr;
    eh->m_state_save->rax = 0x5;
    eh->m_state_save->rdx = 0x6;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        EXPECT_TRUE(g_value == 0x0000000600000005);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_eip()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_sysenter_eip::addr;
    eh->m_state_save->rax = 0x6;
    eh->m_state_save->rdx = 0x7;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        EXPECT_TRUE(g_value == 0x0000000700000006);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_fs_base()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_fs_base::addr;
    eh->m_state_save->rax = 0x7;
    eh->m_state_save->rdx = 0x8;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_FS_BASE);
        EXPECT_TRUE(g_value == 0x0000000800000007);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_gs_base()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = msrs::ia32_gs_base::addr;
    eh->m_state_save->rax = 0x8;
    eh->m_state_save->rdx = 0x9;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_GS_BASE);
        EXPECT_TRUE(g_value == 0x0000000900000008);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_default()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wrmsr;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    eh->m_state_save->rcx = 0x10;
    eh->m_state_save->rax = 0x9;
    eh->m_state_save->rdx = 0xA;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_invalid_guest_state()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vm_entry_failure_invalid_guest_state;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_msr_loading()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vm_entry_failure_msr_loading;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mwait()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::mwait;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor_trap_flag()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::monitor_trap_flag;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::monitor;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_pause()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::pause;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_machine_check_event()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vm_entry_failure_machine_check_event;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_tpr_below_threshold()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::tpr_below_threshold;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_access()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::apic_access;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_virtualized_eoi()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::virtualized_eoi;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_gdtr_or_idtr()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::access_to_gdtr_or_idtr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_ldtr_or_tr()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::access_to_ldtr_or_tr;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_violation()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::ept_violation;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_misconfiguration()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::ept_misconfiguration;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invept()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::invept;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtscp()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdtscp;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmx_preemption_timer_expired()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmx_preemption_timer_expired;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invvpid()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::invvpid;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wbinvd()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::wbinvd;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsetbv()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::xsetbv;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_write()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::apic_write;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdrand()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdrand;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invpcid()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::invpcid;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmfunc()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmfunc;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdseed()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::rdseed;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsaves()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::xsaves;
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xrstors()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::xrstors | 0x80000000;

    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_control_state);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_guest_state);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::check_vmcs_host_state);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_to_string()
{
    auto eh = std::make_unique<exit_handler_intel_x64>();

    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::exception_or_non_maskable_interrupt) == "exception_or_non_maskable_interrupt"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::external_interrupt) == "external_interrupt"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::triple_fault) == "triple_fault"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::init_signal) == "init_signal"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::sipi) == "sipi"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::smi) == "smi"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::other_smi) == "other_smi"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::interrupt_window) == "interrupt_window"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::nmi_window) == "nmi_window"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::task_switch) == "task_switch"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::cpuid) == "cpuid"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::getsec) == "getsec"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::hlt) == "hlt"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::invd) == "invd"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::invlpg) == "invlpg"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdpmc) == "rdpmc"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdtsc) == "rdtsc"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rsm) == "rsm"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmcall) == "vmcall"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmclear) == "vmclear"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmlaunch) == "vmlaunch"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmptrld) == "vmptrld"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmptrst) == "vmptrst"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmread) == "vmread"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmresume) == "vmresume"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmwrite) == "vmwrite"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmxoff) == "vmxoff"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmxon) == "vmxon"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::control_register_accesses) == "control_register_accesses"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::mov_dr) == "mov_dr"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::io_instruction) == "io_instruction"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdmsr) == "rdmsr"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::wrmsr) == "wrmsr"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vm_entry_failure_invalid_guest_state) == "vm_entry_failure_invalid_guest_state"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vm_entry_failure_msr_loading) == "vm_entry_failure_msr_loading"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::mwait) == "mwait"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::monitor_trap_flag) == "monitor_trap_flag"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::monitor) == "monitor"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::pause) == "pause"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vm_entry_failure_machine_check_event) == "vm_entry_failure_machine_check_event"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::tpr_below_threshold) == "tpr_below_threshold"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::apic_access) == "apic_access"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::virtualized_eoi) == "virtualized_eoi"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::access_to_gdtr_or_idtr) == "access_to_gdtr_or_idtr"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::access_to_ldtr_or_tr) == "access_to_ldtr_or_tr"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::ept_violation) == "ept_violation"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::ept_misconfiguration) == "ept_misconfiguration"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::invept) == "invept"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdtscp) == "rdtscp"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmx_preemption_timer_expired) == "vmx_preemption_timer_expired"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::invvpid) == "invvpid"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::wbinvd) == "wbinvd"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::xsetbv) == "xsetbv"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::apic_write) == "apic_write"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdrand) == "rdrand"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::invpcid) == "invpcid"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::vmfunc) == "vmfunc"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::rdseed) == "rdseed"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::xsaves) == "xsaves"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(exit_reason::xrstors) == "xrstors"_s);
    EXPECT_TRUE(eh->exit_reason_to_str(0x100000) == "unknown"_s);
}

void
exit_handler_intel_x64_ut::test_halt()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>();
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->halt();
    });
}
