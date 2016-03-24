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
#include <vcpu/vcpu.h>
#include <debug_ring/debug_ring.h>

void
vcpu_ut::test_vcpu_negative_id()
{
    auto dr = std::make_shared<debug_ring>(0);

    EXPECT_EXCEPTION(std::make_shared<vcpu>(-1), std::out_of_range);
    EXPECT_EXCEPTION(std::make_shared<vcpu>(-1, dr), std::out_of_range);
}

void
vcpu_ut::test_vcpu_id_too_large()
{
    auto dr = std::make_shared<debug_ring>(0);

    EXPECT_EXCEPTION(std::make_shared<vcpu>(10000), std::out_of_range);
    EXPECT_EXCEPTION(std::make_shared<vcpu>(10000, dr), std::out_of_range);
}

void
vcpu_ut::test_vcpu_invalid_debug_ring()
{
    auto dr = std::shared_ptr<debug_ring>();

    EXPECT_NO_EXCEPTION(std::make_shared<vcpu>(0, dr));
}

void
vcpu_ut::test_vcpu_valid()
{
    auto dr = std::make_shared<debug_ring>(0);

    EXPECT_NO_EXCEPTION(std::make_shared<vcpu>(0, dr));
}

void
vcpu_ut::test_vcpu_write()
{
    MockRepository mocks;
    auto dr = bfn::mock_shared<debug_ring>(mocks);
    auto vc = std::make_shared<vcpu>(0, dr);

    mocks.ExpectCall(dr.get(), debug_ring::write);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vc->write("hello world");
    });
}
