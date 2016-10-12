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
#include <intrinsics/idt_x64.h>

std::unique_ptr<uint64_t[]> g_idt;

void set_idt(void *idt)
{
    if (!g_idt)
        g_idt = std::make_unique<uint64_t[]>(4);

    g_idt[0] = 0xFFFFFFFFFFFFFFFF;
    g_idt[1] = 0xFFFFFFFFFFFFFFFF;
    g_idt[2] = 0xFFFFFFFFFFFFFFFF;
    g_idt[3] = 0xFFFFFFFFFFFFFFFF;

    auto idt_reg = reinterpret_cast<idt_reg_x64_t *>(idt);
    idt_reg->limit = (4 * sizeof(uint64_t)) - 1;
    idt_reg->base = reinterpret_cast<uint64_t>(g_idt.get());
}

void
intrinsics_ut::test_idt_constructor_no_size()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_idt).Do(set_idt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        idt_x64 idt(intrinsics);
    });
}

void
intrinsics_ut::test_idt_constructor_zero_size()
{
    idt_x64 idt(0);
    this->expect_true(idt.base() == 0);
    this->expect_true(idt.limit() == 0);
}

void
intrinsics_ut::test_idt_constructor_size()
{
    idt_x64 idt(4);
    this->expect_true(idt.base() != 0);
    this->expect_true(idt.limit() == (4 * sizeof(uint64_t)) - 1);
}

void
intrinsics_ut::test_idt_constructor_null_intrinsics()
{
    auto e = std::make_shared<std::invalid_argument>("idt_x64: intrinsics == nullptr");
    this->expect_exception([&] { idt_x64(std::shared_ptr<intrinsics_x64>()); }, e);
}

void
intrinsics_ut::test_idt_base()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_idt).Do(set_idt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        idt_x64 idt(intrinsics);

        this->expect_true(idt.base() == reinterpret_cast<uint64_t>(g_idt.get()));
    });
}

void
intrinsics_ut::test_idt_limit()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_idt).Do(set_idt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        idt_x64 idt(intrinsics);

        this->expect_true(idt.limit() == (4 * sizeof(uint64_t)) - 1);
    });
}
