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
    this->expect_no_exception([&] { std::make_unique<exit_handler_intel_x64>(null_intrinsics); });
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

    g_exit_reason = exit_reason::exception_or_non_maskable_interrupt;

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

    g_exit_reason = exit_reason::external_interrupt;

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

    g_exit_reason = exit_reason::triple_fault;

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

    g_exit_reason = exit_reason::init_signal;

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

    g_exit_reason = exit_reason::sipi;

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

    g_exit_reason = exit_reason::smi;

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

    g_exit_reason = exit_reason::other_smi;

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

    g_exit_reason = exit_reason::interrupt_window;

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

    g_exit_reason = exit_reason::nmi_window;

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

    g_exit_reason = exit_reason::task_switch;

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

    g_exit_reason = exit_reason::cpuid;

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

    g_exit_reason = exit_reason::getsec;

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

    g_exit_reason = exit_reason::hlt;

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

    g_exit_reason = exit_reason::invd;

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

    g_exit_reason = exit_reason::invlpg;

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

    g_exit_reason = exit_reason::rdpmc;

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

    g_exit_reason = exit_reason::rdtsc;

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

    g_exit_reason = exit_reason::rsm;

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

    g_exit_reason = exit_reason::vmcall;

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

    g_exit_reason = exit_reason::vmclear;

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

    g_exit_reason = exit_reason::vmlaunch;

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

    g_exit_reason = exit_reason::vmptrld;

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

    g_exit_reason = exit_reason::vmptrst;

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

    g_exit_reason = exit_reason::vmread;

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

    g_exit_reason = exit_reason::vmresume;

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

    g_exit_reason = exit_reason::vmwrite;

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
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmread).Do(stubbed_vmread);
    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::vmwrite).Do(stubbed_vmwrite);

    auto ss = std::make_shared<state_save_intel_x64>();
    auto eh = std::make_unique<exit_handler_intel_x64>(intrinsics);
    eh->set_vmcs(vmcs);
    eh->set_state_save(ss);

    g_exit_reason = exit_reason::vmxon;

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

    g_exit_reason = exit_reason::control_register_accesses;

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

    g_exit_reason = exit_reason::mov_dr;

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

    g_exit_reason = exit_reason::io_instruction;

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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000200000001;
    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_DEBUGCTL_FULL);
        this->expect_true(eh->m_state_save->rax == 0x1);
        this->expect_true(eh->m_state_save->rdx == 0x2);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000300000002;
    eh->m_state_save->rcx = IA32_PAT_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_PAT_FULL);
        this->expect_true(eh->m_state_save->rax == 0x2);
        this->expect_true(eh->m_state_save->rdx == 0x3);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = IA32_EFER_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_EFER_FULL);
        this->expect_true(eh->m_state_save->rax == 0x3);
        this->expect_true(eh->m_state_save->rdx == 0x4);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000400000003;
    eh->m_state_save->rcx = IA32_PERF_GLOBAL_CTRL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
        this->expect_true(eh->m_state_save->rax == 0x3);
        this->expect_true(eh->m_state_save->rdx == 0x4);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000500000004;
    eh->m_state_save->rcx = IA32_SYSENTER_CS_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_CS);
        this->expect_true(eh->m_state_save->rax == 0x4);
        this->expect_true(eh->m_state_save->rdx == 0x5);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000600000005;
    eh->m_state_save->rcx = IA32_SYSENTER_ESP_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        this->expect_true(eh->m_state_save->rax == 0x5);
        this->expect_true(eh->m_state_save->rdx == 0x6);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000700000006;
    eh->m_state_save->rcx = IA32_SYSENTER_EIP_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        this->expect_true(eh->m_state_save->rax == 0x6);
        this->expect_true(eh->m_state_save->rdx == 0x7);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000800000007;
    eh->m_state_save->rcx = IA32_FS_BASE_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_FS_BASE);
        this->expect_true(eh->m_state_save->rax == 0x7);
        this->expect_true(eh->m_state_save->rdx == 0x8);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000900000008;
    eh->m_state_save->rcx = IA32_GS_BASE_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_GS_BASE);
        this->expect_true(eh->m_state_save->rax == 0x8);
        this->expect_true(eh->m_state_save->rdx == 0x9);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::read_msr).With(0x10).Return(0x0000000A00000009);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

    eh->m_state_save->rcx = 0x10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(eh->m_state_save->rax == 0x9);
        this->expect_true(eh->m_state_save->rdx == 0xA);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::read_msr).With(0x31);
    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);

    eh->m_state_save->rcx = 0x31;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(eh->m_state_save->rax == 0);
        this->expect_true(eh->m_state_save->rdx == 0);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;
    eh->m_state_save->rax = 0x1;
    eh->m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_DEBUGCTL_FULL);
        this->expect_true(g_value == 0x0000000200000001);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_PAT_MSR;
    eh->m_state_save->rax = 0x2;
    eh->m_state_save->rdx = 0x3;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_PAT_FULL);
        this->expect_true(g_value == 0x0000000300000002);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_EFER_MSR;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_EFER_FULL);
        this->expect_true(g_value == 0x0000000400000003);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_PERF_GLOBAL_CTRL_MSR;
    eh->m_state_save->rax = 0x3;
    eh->m_state_save->rdx = 0x4;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
        this->expect_true(g_value == 0x0000000400000003);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_CS_MSR;
    eh->m_state_save->rax = 0x4;
    eh->m_state_save->rdx = 0x5;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_CS);
        this->expect_true(g_value == 0x0000000500000004);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_ESP_MSR;
    eh->m_state_save->rax = 0x5;
    eh->m_state_save->rdx = 0x6;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_ESP);
        this->expect_true(g_value == 0x0000000600000005);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_SYSENTER_EIP_MSR;
    eh->m_state_save->rax = 0x6;
    eh->m_state_save->rdx = 0x7;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_IA32_SYSENTER_EIP);
        this->expect_true(g_value == 0x0000000700000006);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_FS_BASE_MSR;
    eh->m_state_save->rax = 0x7;
    eh->m_state_save->rdx = 0x8;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_FS_BASE);
        this->expect_true(g_value == 0x0000000800000007);
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_GS_BASE_MSR;
    eh->m_state_save->rax = 0x8;
    eh->m_state_save->rdx = 0x9;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        eh->dispatch();

        this->expect_true(g_field == VMCS_GUEST_GS_BASE);
        this->expect_true(g_value == 0x0000000900000008);
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

    g_exit_reason = exit_reason::wrmsr;

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

    g_exit_reason = exit_reason::vm_entry_failure_invalid_guest_state;

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

    g_exit_reason = exit_reason::vm_entry_failure_msr_loading;

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

    g_exit_reason = exit_reason::mwait;

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

    g_exit_reason = exit_reason::monitor_trap_flag;

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

    g_exit_reason = exit_reason::monitor;

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

    g_exit_reason = exit_reason::pause;

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

    g_exit_reason = exit_reason::vm_entry_failure_machine_check_event;

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

    g_exit_reason = exit_reason::tpr_below_threshold;

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

    g_exit_reason = exit_reason::apic_access;

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

    g_exit_reason = exit_reason::virtualized_eoi;

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

    g_exit_reason = exit_reason::access_to_gdtr_or_idtr;

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

    g_exit_reason = exit_reason::access_to_ldtr_or_tr;

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

    g_exit_reason = exit_reason::ept_violation;

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

    g_exit_reason = exit_reason::ept_misconfiguration;

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

    g_exit_reason = exit_reason::invept;

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

    g_exit_reason = exit_reason::rdtscp;

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

    g_exit_reason = exit_reason::vmx_preemption_timer_expired;

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

    g_exit_reason = exit_reason::invvpid;

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

    g_exit_reason = exit_reason::wbinvd;

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

    g_exit_reason = exit_reason::xsetbv;

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

    g_exit_reason = exit_reason::apic_write;

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

    g_exit_reason = exit_reason::rdrand;

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

    g_exit_reason = exit_reason::invpcid;

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

    g_exit_reason = exit_reason::vmfunc;

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

    g_exit_reason = exit_reason::rdseed;

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

    g_exit_reason = exit_reason::xsaves;

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

    g_exit_reason = exit_reason::xrstors | 0x80000000;

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

void
exit_handler_intel_x64_ut::test_vm_exit_reason_to_string()
{
    auto eh = std::make_unique<exit_handler_intel_x64>();

    this->expect_true(eh->exit_reason_to_str(exit_reason::exception_or_non_maskable_interrupt) == "exception_or_non_maskable_interrupt"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::external_interrupt) == "external_interrupt"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::triple_fault) == "triple_fault"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::init_signal) == "init_signal"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::sipi) == "sipi"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::smi) == "smi"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::other_smi) == "other_smi"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::interrupt_window) == "interrupt_window"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::nmi_window) == "nmi_window"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::task_switch) == "task_switch"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::cpuid) == "cpuid"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::getsec) == "getsec"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::hlt) == "hlt"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::invd) == "invd"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::invlpg) == "invlpg"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdpmc) == "rdpmc"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdtsc) == "rdtsc"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rsm) == "rsm"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmcall) == "vmcall"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmclear) == "vmclear"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmlaunch) == "vmlaunch"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmptrld) == "vmptrld"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmptrst) == "vmptrst"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmread) == "vmread"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmresume) == "vmresume"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmwrite) == "vmwrite"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmxoff) == "vmxoff"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmxon) == "vmxon"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::control_register_accesses) == "control_register_accesses"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::mov_dr) == "mov_dr"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::io_instruction) == "io_instruction"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdmsr) == "rdmsr"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::wrmsr) == "wrmsr"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vm_entry_failure_invalid_guest_state) == "vm_entry_failure_invalid_guest_state"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vm_entry_failure_msr_loading) == "vm_entry_failure_msr_loading"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::mwait) == "mwait"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::monitor_trap_flag) == "monitor_trap_flag"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::monitor) == "monitor"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::pause) == "pause"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vm_entry_failure_machine_check_event) == "vm_entry_failure_machine_check_event"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::tpr_below_threshold) == "tpr_below_threshold"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::apic_access) == "apic_access"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::virtualized_eoi) == "virtualized_eoi"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::access_to_gdtr_or_idtr) == "access_to_gdtr_or_idtr"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::access_to_ldtr_or_tr) == "access_to_ldtr_or_tr"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::ept_violation) == "ept_violation"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::ept_misconfiguration) == "ept_misconfiguration"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::invept) == "invept"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdtscp) == "rdtscp"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmx_preemption_timer_expired) == "vmx_preemption_timer_expired"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::invvpid) == "invvpid"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::wbinvd) == "wbinvd"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::xsetbv) == "xsetbv"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::apic_write) == "apic_write"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdrand) == "rdrand"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::invpcid) == "invpcid"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::vmfunc) == "vmfunc"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::rdseed) == "rdseed"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::xsaves) == "xsaves"_s);
    this->expect_true(eh->exit_reason_to_str(exit_reason::xrstors) == "xrstors"_s);
    this->expect_true(eh->exit_reason_to_str(0x100000) == "unknown"_s);
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

    g_exit_reason = exit_reason::rdmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    g_value = 0x0000000200000001;
    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { eh->dispatch(); }, std::make_shared<std::runtime_error>("vmread failed"));
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

    g_exit_reason = exit_reason::wrmsr;

    mocks.NeverCall(intrinsics.get(), intrinsics_intel_x64::stop);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    eh->m_state_save->rcx = IA32_DEBUGCTL_MSR;
    eh->m_state_save->rax = 0x1;
    eh->m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&] { eh->dispatch(); }, std::make_shared<std::runtime_error>("vmwrite failed"));
    });
}
