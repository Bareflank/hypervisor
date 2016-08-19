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

uint64_t g_field = 0;
uint64_t g_value = 0;
uint64_t g_exit_reason = 0;
uint64_t g_exit_qualification = 0;
uint64_t g_exit_instruction_length = 0;
uint64_t g_exit_instruction_information = 0;

bool
stubbed_vmread(uint64_t field, uint64_t *value)
{
    switch (field)
    {
        case VMCS_EXIT_REASON:
            *value = g_exit_reason;
            break;
        case VMCS_EXIT_QUALIFICATION:
            *value = g_exit_qualification;
            break;
        case VMCS_VM_EXIT_INSTRUCTION_LENGTH:
            *value = g_exit_instruction_length;
            break;
        case VMCS_VM_EXIT_INSTRUCTION_INFORMATION:
            *value = g_exit_instruction_information;
            break;
        default:
            g_field = field;
            *value = g_value;
            break;
    }

    return true;
}

bool
stubbed_vmwrite(uint64_t field, uint64_t value)
{
    g_field = field;
    g_value = value;

    return true;
}

void
exit_handler_intel_x64_ut::test_invalid_intrinics()
{
    auto null_intrinsics = std::shared_ptr<intrinsics_intel_x64>();
    EXPECT_NO_EXCEPTION(std::make_unique<exit_handler_intel_x64>(null_intrinsics));
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_unknown()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = 0x0000BEEF;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_EXTERNAL_INTERRUPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_TRIPLE_FAULT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INIT_SIGNAL;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_SIPI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_SMI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_OTHER_SMI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INTERRUPT_WINDOW;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_NMI_WINDOW;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_TASK_SWITCH;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::cpuid);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_CPUID;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_GETSEC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_HLT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INVD;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::wbinvd);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INVLPG;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDPMC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDTSC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RSM;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMCALL;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMCLEAR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMLAUNCH;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMPTRLD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMPTRST;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMREAD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMRESUME;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMWRITE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMXOFF;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMXON;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_MOV_DR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_IO_INSTRUCTION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000200000001;
    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_DEBUGCTL_FULL);
        EXPECT_TRUE(eh->m_state_save->rax == 0x1);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x2);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_pat()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000300000002;
    eh->m_state_save->rcx = IA32_PAT_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PAT_FULL);
        EXPECT_TRUE(eh->m_state_save->rax == 0x2);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x3);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_efer()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = IA32_EFER_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_EFER_FULL);
        EXPECT_TRUE(eh->m_state_save->rax == 0x3);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x4);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_perf()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = IA32_PERF_GLOBAL_CTRL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
        EXPECT_TRUE(eh->m_state_save->rax == 0x3);
        EXPECT_TRUE(eh->m_state_save->rdx == 0x4);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_cs()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000500000004;
    eh->m_state_save->rcx = IA32_SYSENTER_CS_MSR;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000600000005;
    eh->m_state_save->rcx = IA32_SYSENTER_ESP_MSR;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000700000006;
    eh->m_state_save->rcx = IA32_SYSENTER_EIP_MSR;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000800000007;
    eh->m_state_save->rcx = IA32_FS_BASE_MSR;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000900000008;
    eh->m_state_save->rcx = IA32_GS_BASE_MSR;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::read_msr).With(0x10).Return(0x0000000A00000009);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::read_msr).With(0x31);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;
    eh->m_state_save->rax = 0x1;
    eh->m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_DEBUGCTL_FULL);
        EXPECT_TRUE(g_value == 0x0000000200000001);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_pat()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_PAT_MSR;
    eh->m_state_save->rax = 0x2;
    eh->m_state_save->rdx = 0x3;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PAT_FULL);
        EXPECT_TRUE(g_value == 0x0000000300000002);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_efer()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_EFER_MSR;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_EFER_FULL);
        EXPECT_TRUE(g_value == 0x0000000400000003);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_perf()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_PERF_GLOBAL_CTRL_MSR;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        EXPECT_TRUE(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
        EXPECT_TRUE(g_value == 0x0000000400000003);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_cs()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_CS_MSR;
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_ESP_MSR;
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_EIP_MSR;
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_FS_BASE_MSR;
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_GS_BASE_MSR;
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::write_msr).With(0x10, 0x0000000A00000009);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_MWAIT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_MONITOR_TRAP_FLAG;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_MONITOR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_PAUSE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_TPR_BELOW_THRESHOLD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_APIC_ACCESS;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VIRTUALIZED_EOI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_EPT_VIOLATION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_EPT_MISCONFIGURATION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INVEPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDTSCP;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INVVPID;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WBINVD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_XSETBV;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_APIC_WRITE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDRAND;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_INVPCID;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_VMFUNC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDSEED;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_XSAVES;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_XRSTORS | 0x80000000;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::check_vmcs_control_state);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::check_vmcs_guest_state);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::check_vmcs_host_state);
    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

#define STRINGIFY_MACRO(a) std::string(#a)

void
exit_handler_intel_x64_ut::test_vm_exit_reason_to_string()
{
    auto eh = std::make_unique<exit_handler_intel_x64>();

    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT) == STRINGIFY_MACRO(VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_EXTERNAL_INTERRUPT) == STRINGIFY_MACRO(VM_EXIT_REASON_EXTERNAL_INTERRUPT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_TRIPLE_FAULT) == STRINGIFY_MACRO(VM_EXIT_REASON_TRIPLE_FAULT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INIT_SIGNAL) == STRINGIFY_MACRO(VM_EXIT_REASON_INIT_SIGNAL));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_SIPI) == STRINGIFY_MACRO(VM_EXIT_REASON_SIPI));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_SMI) == STRINGIFY_MACRO(VM_EXIT_REASON_SMI));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_OTHER_SMI) == STRINGIFY_MACRO(VM_EXIT_REASON_OTHER_SMI));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INTERRUPT_WINDOW) == STRINGIFY_MACRO(VM_EXIT_REASON_INTERRUPT_WINDOW));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_NMI_WINDOW) == STRINGIFY_MACRO(VM_EXIT_REASON_NMI_WINDOW));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_TASK_SWITCH) == STRINGIFY_MACRO(VM_EXIT_REASON_TASK_SWITCH));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_CPUID) == STRINGIFY_MACRO(VM_EXIT_REASON_CPUID));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_GETSEC) == STRINGIFY_MACRO(VM_EXIT_REASON_GETSEC));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_HLT) == STRINGIFY_MACRO(VM_EXIT_REASON_HLT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INVD) == STRINGIFY_MACRO(VM_EXIT_REASON_INVD));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INVLPG) == STRINGIFY_MACRO(VM_EXIT_REASON_INVLPG));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDPMC) == STRINGIFY_MACRO(VM_EXIT_REASON_RDPMC));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDTSC) == STRINGIFY_MACRO(VM_EXIT_REASON_RDTSC));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RSM) == STRINGIFY_MACRO(VM_EXIT_REASON_RSM));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMCALL) == STRINGIFY_MACRO(VM_EXIT_REASON_VMCALL));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMCLEAR) == STRINGIFY_MACRO(VM_EXIT_REASON_VMCLEAR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMLAUNCH) == STRINGIFY_MACRO(VM_EXIT_REASON_VMLAUNCH));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMPTRLD) == STRINGIFY_MACRO(VM_EXIT_REASON_VMPTRLD));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMPTRST) == STRINGIFY_MACRO(VM_EXIT_REASON_VMPTRST));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMREAD) == STRINGIFY_MACRO(VM_EXIT_REASON_VMREAD));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMRESUME) == STRINGIFY_MACRO(VM_EXIT_REASON_VMRESUME));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMWRITE) == STRINGIFY_MACRO(VM_EXIT_REASON_VMWRITE));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMXOFF) == STRINGIFY_MACRO(VM_EXIT_REASON_VMXOFF));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMXON) == STRINGIFY_MACRO(VM_EXIT_REASON_VMXON));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES) == STRINGIFY_MACRO(VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_MOV_DR) == STRINGIFY_MACRO(VM_EXIT_REASON_MOV_DR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_IO_INSTRUCTION) == STRINGIFY_MACRO(VM_EXIT_REASON_IO_INSTRUCTION));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDMSR) == STRINGIFY_MACRO(VM_EXIT_REASON_RDMSR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_WRMSR) == STRINGIFY_MACRO(VM_EXIT_REASON_WRMSR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE) == STRINGIFY_MACRO(VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING) == STRINGIFY_MACRO(VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_MWAIT) == STRINGIFY_MACRO(VM_EXIT_REASON_MWAIT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_MONITOR_TRAP_FLAG) == STRINGIFY_MACRO(VM_EXIT_REASON_MONITOR_TRAP_FLAG));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_MONITOR) == STRINGIFY_MACRO(VM_EXIT_REASON_MONITOR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_PAUSE) == STRINGIFY_MACRO(VM_EXIT_REASON_PAUSE));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT) == STRINGIFY_MACRO(VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_TPR_BELOW_THRESHOLD) == STRINGIFY_MACRO(VM_EXIT_REASON_TPR_BELOW_THRESHOLD));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_APIC_ACCESS) == STRINGIFY_MACRO(VM_EXIT_REASON_APIC_ACCESS));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VIRTUALIZED_EOI) == STRINGIFY_MACRO(VM_EXIT_REASON_VIRTUALIZED_EOI));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR) == STRINGIFY_MACRO(VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR) == STRINGIFY_MACRO(VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_EPT_VIOLATION) == STRINGIFY_MACRO(VM_EXIT_REASON_EPT_VIOLATION));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_EPT_MISCONFIGURATION) == STRINGIFY_MACRO(VM_EXIT_REASON_EPT_MISCONFIGURATION));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INVEPT) == STRINGIFY_MACRO(VM_EXIT_REASON_INVEPT));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDTSCP) == STRINGIFY_MACRO(VM_EXIT_REASON_RDTSCP));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED) == STRINGIFY_MACRO(VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INVVPID) == STRINGIFY_MACRO(VM_EXIT_REASON_INVVPID));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_WBINVD) == STRINGIFY_MACRO(VM_EXIT_REASON_WBINVD));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_XSETBV) == STRINGIFY_MACRO(VM_EXIT_REASON_XSETBV));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_APIC_WRITE) == STRINGIFY_MACRO(VM_EXIT_REASON_APIC_WRITE));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDRAND) == STRINGIFY_MACRO(VM_EXIT_REASON_RDRAND));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_INVPCID) == STRINGIFY_MACRO(VM_EXIT_REASON_INVPCID));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_VMFUNC) == STRINGIFY_MACRO(VM_EXIT_REASON_VMFUNC));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_RDSEED) == STRINGIFY_MACRO(VM_EXIT_REASON_RDSEED));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_XSAVES) == STRINGIFY_MACRO(VM_EXIT_REASON_XSAVES));
    EXPECT_TRUE(eh->exit_reason_to_str(VM_EXIT_REASON_XRSTORS) == STRINGIFY_MACRO(VM_EXIT_REASON_XRSTORS));
    EXPECT_TRUE(eh->exit_reason_to_str(0x100000) == STRINGIFY_MACRO(UNKNOWN));
}

void
exit_handler_intel_x64_ut::test_halt()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->halt();
    });
}

void
exit_handler_intel_x64_ut::test_vmread_failure()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Return(false);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000200000001;
    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(eh->dispatch(), std::runtime_error);
    });
}

void
exit_handler_intel_x64_ut::test_vmwrite_failure()
{
    MockRepository mocks;
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Return(false);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;
    eh->m_state_save->rax = 0x1;
    eh->m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(eh->dispatch(), std::runtime_error);
    });
}
