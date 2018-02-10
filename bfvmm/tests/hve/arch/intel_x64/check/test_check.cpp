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

#include "test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("check")
{
    MockRepository mocks;

    mocks.OnCallFunc(bfvmm::intel_x64::check::vmx_controls_all);
    mocks.OnCallFunc(bfvmm::intel_x64::check::host_state_all);
    mocks.OnCallFunc(bfvmm::intel_x64::check::guest_state_all);

    CHECK_NOTHROW(bfvmm::intel_x64::check::all());
}

#endif
