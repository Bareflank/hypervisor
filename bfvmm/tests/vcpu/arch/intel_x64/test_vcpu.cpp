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

TEST_CASE("bfvmm::intel_x64::vcpu: invalid_id")
{
    CHECK_THROWS(std::make_unique<bfvmm::intel_x64::vcpu>(vcpuid::reserved));
}

TEST_CASE("bfvmm::intel_x64::vcpu: valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();

    auto test = [&] {
        auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
        auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
        auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
        auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
        auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);
        std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: init_null_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("bfvmm::intel_x64::vcpu: init_valid_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("bfvmm::intel_x64::vcpu: init_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("bfvmm::intel_x64::vcpu: init_vmcs_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save).Throw(std::logic_error("error"));
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->init());
}

TEST_CASE("bfvmm::intel_x64::vcpu: fini_null_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("bfvmm::intel_x64::vcpu: fini_valid_params")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: fini_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: fini_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("bfvmm::intel_x64::vcpu: run_launch")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: run_launch_is_host_vcpu")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: run_resume")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: run_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->run());
}

TEST_CASE("bfvmm::intel_x64::vcpu: run_vmxon_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start).Throw(std::runtime_error("error"));
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: run_vmcs_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch).Throw(std::runtime_error("error"));
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: hlt_no_init")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("bfvmm::intel_x64::vcpu: hlt_no_run")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: hlt_valid")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: hlt_valid_is_host_vcpu")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop);

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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

TEST_CASE("bfvmm::intel_x64::vcpu: hlt_vmxon_throws")
{
    MockRepository mocks;
    setup_gdt();
    setup_idt();
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<bfvmm::intel_x64::vmxon>(mocks);
    auto cs = mock_unique<bfvmm::intel_x64::vmcs>(mocks);
    auto eh = mock_unique<bfvmm::intel_x64::exit_handler>(mocks);
    auto vs = mock_unique<bfvmm::intel_x64::vmcs_state_vmm>(mocks);
    auto gs = mock_unique<bfvmm::intel_x64::vmcs_state_hvm>(mocks);

    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_state_save);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::set_exit_handler_entry);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::launch);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::load);
    mocks.OnCall(cs.get(), bfvmm::intel_x64::vmcs::resume);

    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::start);
    mocks.OnCall(on.get(), bfvmm::intel_x64::vmxon::stop).Throw(std::runtime_error("error"));

    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_vmcs);
    mocks.OnCall(eh.get(), bfvmm::intel_x64::exit_handler::set_state_save);

    auto vc = std::make_unique<bfvmm::intel_x64::vcpu>(
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
