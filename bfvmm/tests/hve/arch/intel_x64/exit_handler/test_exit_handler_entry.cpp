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

TEST_CASE("exit_handler: entry_valid")
{
    MockRepository mocks;
    auto eh = mocks.Mock<bfvmm::intel_x64::exit_handler>();

    mocks.OnCall(eh, bfvmm::intel_x64::exit_handler::halt);
    mocks.OnCall(eh, bfvmm::intel_x64::exit_handler::dispatch);

    CHECK_NOTHROW(exit_handler(eh));
}

TEST_CASE("exit_handler: entry_throws_invalid_argument")
{
    MockRepository mocks;
    auto eh = mocks.Mock<bfvmm::intel_x64::exit_handler>();

    mocks.ExpectCall(eh, bfvmm::intel_x64::exit_handler::halt);
    mocks.OnCall(eh, bfvmm::intel_x64::exit_handler::dispatch).Throw(std::invalid_argument(""));

    CHECK_NOTHROW(exit_handler(eh));
}

TEST_CASE("exit_handler: entry_throws_standard_exception")
{
    MockRepository mocks;
    auto eh = mocks.Mock<bfvmm::intel_x64::exit_handler>();

    mocks.ExpectCall(eh, bfvmm::intel_x64::exit_handler::halt);
    mocks.OnCall(eh, bfvmm::intel_x64::exit_handler::dispatch).Throw(std::exception());

    CHECK_NOTHROW(exit_handler(eh));
}

TEST_CASE("exit_handler: entry_throws_any_exception")
{
    MockRepository mocks;
    auto eh = mocks.Mock<bfvmm::intel_x64::exit_handler>();

    mocks.ExpectCall(eh, bfvmm::intel_x64::exit_handler::halt);
    mocks.OnCall(eh, bfvmm::intel_x64::exit_handler::dispatch).Throw(10);

    CHECK_NOTHROW(exit_handler(eh));
}

#endif
