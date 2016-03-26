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
#include <vcpu/vcpu_manager.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

uint64_t g_exit_reason = 0;
uint64_t g_exit_qualification = 0;
uint64_t g_exit_instruction_length = 0;
uint64_t g_exit_instruction_information = 0;

bool
stubbed_vmread(uint64_t field, uint64_t *value)
{
    if (field == VMCS_EXIT_REASON)
        *value = g_exit_reason;

    if (field == VMCS_EXIT_QUALIFICATION)
        *value = g_exit_qualification;

    if (field == VMCS_VM_EXIT_INSTRUCTION_LENGTH)
        *value = g_exit_instruction_length;

    if (field == VMCS_VM_EXIT_INSTRUCTION_INFORMATION)
        *value = g_exit_instruction_information;

    return true;
}

bool
stubbed_vmwrite(uint64_t field, uint64_t value)
{
    if (field == VMCS_EXIT_REASON)
        g_exit_reason = value;

    if (field == VMCS_EXIT_QUALIFICATION)
        g_exit_qualification = value;

    if (field == VMCS_VM_EXIT_INSTRUCTION_LENGTH)
        g_exit_instruction_length = value;

    if (field == VMCS_VM_EXIT_INSTRUCTION_INFORMATION)
        g_exit_instruction_information = value;

    return true;
}

void
exit_handler_intel_x64_ut::test_invalid_intrinics()
{
    auto null_intrinsics = std::shared_ptr<intrinsics_intel_x64>();
    EXPECT_EXCEPTION(std::make_unique<exit_handler_intel_x64>(null_intrinsics), std::invalid_argument);
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_unknown()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = 0xDEADBEEF;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_exception_or_non_maskable_interrupt()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_external_interrupt()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_EXTERNAL_INTERRUPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_triple_fault()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_TRIPLE_FAULT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_init_signal()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INIT_SIGNAL;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_sipi()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_SIPI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_smi()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_SMI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_other_smi()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_OTHER_SMI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_interrupt_window()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INTERRUPT_WINDOW;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_nmi_window()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_NMI_WINDOW;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_task_switch()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_TASK_SWITCH;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_cpuid()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::cpuid);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_CPUID;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_getsec()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_GETSEC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_hlt()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_HLT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invd()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INVD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invlpg()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INVLPG;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdpmc()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDPMC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtsc()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDTSC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rsm()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RSM;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMCALL;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmclear()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMCLEAR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmlaunch()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMLAUNCH;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrld()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMPTRLD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmptrst()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMPTRST;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmread()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMREAD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmresume()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMRESUME;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmwrite()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMWRITE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxoff()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    vcpu_manager *vcm = mocks.Mock<vcpu_manager>();
    mocks.OnCallFunc(vcpu_manager::instance).Return(vcm);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMXOFF;

    mocks.ExpectCall(vcm, vcpu_manager::promote);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxon()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMXON;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_control_register_accesses()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mov_dr()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_MOV_DR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_io_instruction()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_IO_INSTRUCTION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDMSR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_WRMSR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_invalid_guest_state()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_msr_loading()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_mwait()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_MWAIT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor_trap_flag()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_MONITOR_TRAP_FLAG;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_monitor()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_MONITOR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_pause()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_PAUSE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vm_entry_failure_machine_check_event()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_tpr_below_threshold()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_TPR_BELOW_THRESHOLD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_access()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_APIC_ACCESS;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_virtualized_eoi()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VIRTUALIZED_EOI;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_gdtr_or_idtr()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_access_to_ldtr_or_tr()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_violation()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_EPT_VIOLATION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_ept_misconfiguration()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_EPT_MISCONFIGURATION;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invept()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INVEPT;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdtscp()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDTSCP;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmx_preemption_timer_expired()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invvpid()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INVVPID;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wbinvd()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_WBINVD;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsetbv()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_XSETBV;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_apic_write()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_APIC_WRITE;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdrand()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDRAND;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invpcid()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_INVPCID;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmfunc()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_VMFUNC;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdseed()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_RDSEED;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xsaves()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_XSAVES;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_xrstors()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    g_exit_reason = VM_EXIT_REASON_XRSTORS;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();
    });
}
