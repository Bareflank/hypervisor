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
#include <vcpu/vcpu_intel_x64.h>
#include <debug_ring/debug_ring.h>

void
vcpu_ut::test_vcpu_intel_x64_negative_id()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(std::make_shared<vcpu_intel_x64>(-1), bfn::invalid_argument_error);
        EXPECT_EXCEPTION(std::make_shared<vcpu_intel_x64>(-1, dr, on, cs, eh, in), bfn::invalid_argument_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_id_too_large()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(std::make_shared<vcpu_intel_x64>(10000), bfn::invalid_argument_error);
        EXPECT_EXCEPTION(std::make_shared<vcpu_intel_x64>(10000, dr, on, cs, eh, in), bfn::invalid_argument_error);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_invalid_objects()
{
    auto dr = std::shared_ptr<debug_ring>();
    auto on = std::shared_ptr<vmxon_intel_x64>();
    auto cs = std::shared_ptr<vmcs_intel_x64>();
    auto eh = std::shared_ptr<exit_handler_intel_x64>();
    auto in = std::shared_ptr<intrinsics_intel_x64>();

    EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in));
}

void
vcpu_ut::test_vcpu_intel_x64_valid()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0));
        EXPECT_NO_EXCEPTION(std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in));
    });
}

void
vcpu_ut::test_vcpu_intel_x64_start_vmxon_start_failed()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(on.get(), vmxon_intel_x64::start).Throw(bfn::general_exception());
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vc->start(), bfn::general_exception);
    });
}

static void
setup_intrinsics(MockRepository &mocks, intrinsics_intel_x64 *in)
{
    mocks.OnCall(in, intrinsics_intel_x64::read_es).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_cs).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_ss).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_ds).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_fs).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_gs).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_tr).Return(0);

    mocks.OnCall(in, intrinsics_intel_x64::read_cr0).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_cr3).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_cr4).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_dr7).Return(0);

    mocks.OnCall(in, intrinsics_intel_x64::read_rflags).Return(0);

    mocks.OnCall(in, intrinsics_intel_x64::read_gdt);
    mocks.OnCall(in, intrinsics_intel_x64::read_idt);

    mocks.OnCall(in, intrinsics_intel_x64::segment_descriptor_limit).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::segment_descriptor_access).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::segment_descriptor_base).Return(0);

    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Return(0);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr32).Return(0);
}

void
vcpu_ut::test_vcpu_intel_x64_start_vmcs_launch_failed()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch).Throw(bfn::general_exception());

    setup_intrinsics(mocks, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_EXCEPTION(vc->start(), bfn::general_exception);
    });
}

void
vcpu_ut::test_vcpu_intel_x64_start_success()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);

    setup_intrinsics(mocks, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vc->start());
    });
}

void
vcpu_ut::test_vcpu_intel_x64_dispatch()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::dispatch);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vc->dispatch());
    });
}

void
vcpu_ut::test_vcpu_intel_x64_stop()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vc->stop());
    });
}

void
vcpu_ut::test_vcpu_intel_x64_halt()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(in.get(), intrinsics_intel_x64::stop);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vc->halt());
    });
}

void
vcpu_ut::test_vcpu_intel_x64_promote()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto on = bfn::mock_shared<vmxon_intel_x64>(mocks);
    auto cs = bfn::mock_shared<vmcs_intel_x64>(mocks);
    auto eh = bfn::mock_shared<exit_handler_intel_x64>(mocks);
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    auto vc = std::make_shared<vcpu_intel_x64>(0, dr, on, cs, eh, in);

    mocks.OnCall(cs.get(), vmcs_intel_x64::promote);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_NO_EXCEPTION(vc->promote());
    });
}
