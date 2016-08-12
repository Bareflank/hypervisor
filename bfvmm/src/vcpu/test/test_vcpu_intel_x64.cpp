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
#include <memory_manager/memory_manager.h>

static void *
malloc_aligned(size_t size, uint64_t alignment)
{
    void *ptr = 0;
    if (posix_memalign(&ptr, alignment, size) != 0)
        return 0;
    return ptr;
}

static void *
virt_to_phys(void *)
{
    static uintptr_t phys = 0x0000000ABCDEF0000;
    return reinterpret_cast<void *>(phys + 0x1000);
}

static const std::map<uintptr_t, memory_descriptor> &
virt_to_phys_map() noexcept
{
    static std::map<uintptr_t, memory_descriptor> m_virt_to_phys_map;
    return m_virt_to_phys_map;
}

void
vcpu_ut::test_vcpu_intel_x64_invalid_id()
{
    EXPECT_EXCEPTION(std::make_shared<vcpu_intel_x64>(VCPUID_RESERVED), std::invalid_argument);
}

void
vcpu_ut::test_vcpu_intel_x64_null_params_valid_intrinsics()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0, nullptr, in, nullptr, nullptr, nullptr, nullptr, nullptr));
    });
}

void
vcpu_ut::test_vcpu_intel_x64_valid_params_null_intrinsics()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0, dr, nullptr, on, cs, eh, vs, gs));
    });
}

void
vcpu_ut::test_vcpu_intel_x64_valid()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs));
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_null_params_valid_intrinsics()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_es).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ss).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ds).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_fs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_gs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ldtr).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_tr).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr0).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr3).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_dr7).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_rflags).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_gdt);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_idt);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).Return(0);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, nullptr, in, nullptr, nullptr, nullptr, nullptr, nullptr);
        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_valid_params_null_intrinsics()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, nullptr, on, cs, eh, vs, gs);
        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_valid()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_init_vmcs_throws()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save).Throw(std::logic_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, nullptr, on, cs, eh, vs, gs);
        EXPECT_EXCEPTION(vc->init(), std::logic_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_null_params_valid_intrinsics()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_es).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ss).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ds).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_fs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_gs).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_ldtr).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_tr).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr0).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr3).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_dr7).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_rflags).Return(0);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_gdt);
    mocks.OnCall(in.get(), intrinsics_intel_x64::read_idt);

    mocks.OnCall(in.get(), intrinsics_intel_x64::read_msr).Return(0);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, nullptr, in, nullptr, nullptr, nullptr, nullptr, nullptr);
        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_valid_params_null_intrinsics()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, nullptr, on, cs, eh, vs, gs);
        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_valid()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_fini_no_init()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->fini();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_launch()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0x0001000000000000, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_launch_is_host_vcpu()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_resume()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
        vc->run();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_no_init()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        EXPECT_EXCEPTION(vc->run(), std::runtime_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_vmxon_throws()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start).Throw(std::runtime_error("error"));
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        EXPECT_EXCEPTION(vc->run(), std::runtime_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_run_vmcs_throws()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch).Throw(std::runtime_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        EXPECT_EXCEPTION(vc->run(), std::runtime_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_no_init()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0x0001000000000000, dr, in, on, cs, eh, vs, gs);
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_no_run()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0x0001000000000000, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_valid()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0x0001000000000000, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_valid_is_host_vcpu()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
        vc->hlt();
    });
}

void
vcpu_ut::test_vcpu_intel_x64_hlt_vmxon_throws()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto vs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = bfn::mock_shared<vmcs_intel_x64_vmm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop).Throw(std::runtime_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::malloc_aligned).Do(malloc_aligned);
    mocks.OnCall(mm, memory_manager::virt_to_phys).Do(virt_to_phys);
    mocks.OnCall(mm, memory_manager::virt_to_phys_map).Do(virt_to_phys_map);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto vc = std::make_shared<vcpu_intel_x64>(0, dr, in, on, cs, eh, vs, gs);
        vc->init();
        vc->run();
        EXPECT_EXCEPTION(vc->hlt(), std::runtime_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_coveralls_cleanup()
{
    MockRepository mocks;
    mocks.OnCallFunc(posix_memalign).Return(-1);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto ptr = malloc_aligned(4096, 4096);
        EXPECT_TRUE(ptr == nullptr);

        if (ptr)
            free(ptr);
    });
}
