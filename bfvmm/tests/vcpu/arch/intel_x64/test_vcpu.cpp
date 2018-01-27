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

TEST_CASE("vcpu_intel_x64: invalid_id")
{
    CHECK_THROWS(std::make_unique<vcpu_intel_x64>(vcpuid::reserved));
}

TEST_CASE("vcpu_intel_x64: valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    auto test = [&] {
        auto on = mock_unique<vmxon_intel_x64>(mocks);
        auto cs = mock_unique<vmcs_intel_x64>(mocks);
        auto eh = mock_unique<exit_handler_intel_x64>(mocks);
        auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
        auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);
        std::make_unique<vcpu_intel_x64>(
            0,
            std::move(on),
            std::move(cs),
            std::move(eh),
            std::move(vs),
            std::move(gs)
        );
    };

    CHECK_NOTHROW(test());
}

TEST_CASE("vcpu_intel_x64: init_null_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_valid_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_vmcs_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save).Throw(std::logic_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->init());
}

TEST_CASE("vcpu_intel_x64: fini_null_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_valid_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: run_launch")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_launch_is_host_vcpu")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_resume")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_vmxon_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start).Throw(std::runtime_error("error"));
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_vmcs_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch).Throw(std::runtime_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: hlt_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_no_run")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_valid_is_host_vcpu")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_vmxon_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop).Throw(std::runtime_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();

    CHECK_THROWS(vc->hlt());
}

#endif
