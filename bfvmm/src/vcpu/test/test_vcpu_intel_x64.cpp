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
#include <stdlib.h>
#include <vcpu/vcpu_intel_x64.h>
#include <debug_ring/debug_ring.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ (void) addr; return 0; }

extern "C" uint64_t
__read_cr0(void) noexcept
{ return 0; }

extern "C" uint64_t
__read_cr3(void) noexcept
{ return 0; }

extern "C" uint64_t
__read_cr4(void) noexcept
{ return 0; }

extern "C" uint64_t
__read_rflags(void) noexcept
{ return 0; }

extern "C" uint64_t
__read_dr7(void) noexcept
{ return 0; }

extern "C" void
__read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ (void) gdt_reg; }

extern "C" void
__read_idt(idt_reg_x64_t *idt_reg) noexcept
{ (void) idt_reg; }

extern "C" uint16_t
__read_es(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_cs(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_ss(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_ds(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_fs(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_gs(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_ldtr(void) noexcept
{ return 0; }

extern "C" uint16_t
__read_tr(void) noexcept
{ return 0; }

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

static auto
setup_pt(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_page_table_x64::instance).Return(pt);
    mocks.OnCall(pt, root_page_table_x64::phys_addr).Return(0x0000000ABCDEF0000);

    return pt;
}

void
vcpu_ut::test_vcpu_intel_x64_invalid_id()
{
    this->expect_exception([&] { std::make_unique<vcpu_intel_x64>(vcpuid::reserved); }, ""_ut_iae);
}

void
vcpu_ut::test_vcpu_intel_x64_valid()
{
    MockRepository mocks;
    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] {
            std::make_unique<vcpu_intel_x64>(0,
            std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));
        });
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_null_params()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_valid_params()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_vmcs_throws()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save).Throw(std::logic_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        this->expect_exception([&] { vc->init(); }, ""_ut_lee);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_null_params()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0, nullptr, nullptr, nullptr, nullptr, nullptr);

        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_valid_params()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_no_init()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_launch()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0x0001000000000000,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_launch_is_host_vcpu()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_resume()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_no_init()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        this->expect_exception([&] { vc->run(); }, ""_ut_ffe);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_vmxon_throws()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start).Throw(std::runtime_error("error"));
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        this->expect_exception([&] { vc->run(); }, ""_ut_ree);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_vmcs_throws()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch).Throw(std::runtime_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        this->expect_exception([&] { vc->run(); }, ""_ut_ree);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_no_init()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0x0001000000000000,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_no_run()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0x0001000000000000,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));
        vc->init();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0x0001000000000000,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_valid_is_host_vcpu()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_vmxon_throws()
{
    MockRepository mocks;
    setup_mm(mocks);
    setup_pt(mocks);

    auto &&dr = bfn::mock_unique<debug_ring>(mocks);
    auto &&on = bfn::mock_unique<vmxon_intel_x64>(mocks);
    auto &&cs = bfn::mock_unique<vmcs_intel_x64>(mocks);
    auto &&eh = bfn::mock_unique<exit_handler_intel_x64>(mocks);
    auto &&vs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto &&gs = bfn::mock_unique<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop).Throw(std::runtime_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_unique<vcpu_intel_x64>(0,
        std::move(dr), std::move(on), std::move(cs), std::move(eh), std::move(vs), std::move(gs));

        vc->init();
        vc->run();

        this->expect_exception([&] { vc->hlt(); }, ""_ut_ree);
    });
}
