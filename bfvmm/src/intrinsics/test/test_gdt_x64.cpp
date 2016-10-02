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
#include <intrinsics/gdt_x64.h>

std::unique_ptr<uint64_t[]> g_gdt;

void set_gdt(void *gdt)
{
    if (!g_gdt)
        g_gdt = std::make_unique<uint64_t[]>(4);

    g_gdt[0] = 0x0;
    g_gdt[1] = 0xFFFFFFFFFFFFFFFF;
    g_gdt[2] = 0xFFFF8FFFFFFFFFFF;
    g_gdt[3] = 0x00000000FFFFFFFF;

    auto gdt_reg = reinterpret_cast<gdt_reg_x64_t *>(gdt);
    gdt_reg->limit = 4 * sizeof(uint64_t);
    gdt_reg->base = reinterpret_cast<uint64_t>(g_gdt.get());
}

void
intrinsics_ut::test_gdt_constructor_no_size()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);
    });
}

void
intrinsics_ut::test_gdt_constructor_zero_size()
{
    gdt_x64 gdt(0);
    this->expect_true(gdt.base() == 0);
    this->expect_true(gdt.limit() == 0);
}

void
intrinsics_ut::test_gdt_constructor_size()
{
    gdt_x64 gdt(4);
    this->expect_true(gdt.base() != 0);
    this->expect_true(gdt.limit() == 4 * sizeof(uint64_t));
}

void
intrinsics_ut::test_gdt_constructor_null_intrinsics()
{
    auto e = std::make_shared<std::invalid_argument>("gdt_x64: intrinsics == nullptr");
    this->expect_exception([&] { gdt_x64(std::shared_ptr<intrinsics_x64>()); }, e);
}

void
intrinsics_ut::test_gdt_base()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_true(gdt.base() == reinterpret_cast<uint64_t>(g_gdt.get()));
    });
}

void
intrinsics_ut::test_gdt_limit()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.ExpectCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_true(gdt.limit() == 4 * sizeof(uint64_t));
    });
}

void
intrinsics_ut::test_gdt_set_base_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_base(0, 0x10); });
    });
}

void
intrinsics_ut::test_gdt_set_base_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.set_base(1000, 0x10); }, e);
    });
}

void
intrinsics_ut::test_gdt_set_base_tss_at_end_of_gdt()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index does not point to a valid TSS");
        this->expect_exception([&] { gdt.set_base(3, 0x10); }, e);
    });
}

void
intrinsics_ut::test_gdt_set_base_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_base(1, 0xBBBBBBBB12345678); });
        this->expect_true(g_gdt[1] == 0x12FFFF345678FFFF);
    });
}

void
intrinsics_ut::test_gdt_set_base_tss_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_base(2, 0x1234567812345678); });
        this->expect_true(g_gdt[2] == 0x12FF8F345678FFFF);
        this->expect_true(g_gdt[3] == 0x0000000012345678);
    });
}

void
intrinsics_ut::test_gdt_base_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_true(gdt.base(0) == 0);
    });
}

void
intrinsics_ut::test_gdt_base_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.base(1000); }, e);
    });
}

void
intrinsics_ut::test_gdt_base_tss_at_end_of_gdt()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index does not point to a valid TSS");
        this->expect_exception([&] { gdt.base(3); }, e);
    });
}

void
intrinsics_ut::test_gdt_base_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        g_gdt[1] = 0x12FFFF345678FFFF;
        this->expect_true(gdt.base(1) == 0x0000000012345678);
    });
}

void
intrinsics_ut::test_gdt_base_tss_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        g_gdt[2] = 0x12FF8F345678FFFF;
        g_gdt[3] = 0x0000000012345678;
        this->expect_true(gdt.base(2) == 0x1234567812345678);
    });
}

void
intrinsics_ut::test_gdt_set_limit_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_limit(0, 0x10); });
    });
}

void
intrinsics_ut::test_gdt_set_limit_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.set_limit(1000, 0x10); }, e);
    });
}

void
intrinsics_ut::test_gdt_set_limit_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_limit(1, 0x12345678); });
        this->expect_true(g_gdt[1] == 0xFFF1FFFFFFFF2345);
    });
}

void
intrinsics_ut::test_gdt_limit_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_true(gdt.limit(0) == 0);
    });
}

void
intrinsics_ut::test_gdt_limit_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.limit(1000); }, e);
    });
}

void
intrinsics_ut::test_gdt_limit_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        g_gdt[1] = 0xFFF4FFFFFFFF5678;
        this->expect_true(gdt.limit(1) == 0x0000000045678FFF);
    });
}

void
intrinsics_ut::test_gdt_limit_descriptor_in_bytes_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        g_gdt[1] = 0xFF74FFFFFFFF5678;
        this->expect_true(gdt.limit(1) == 0x0000000000045678);
    });
}

void
intrinsics_ut::test_gdt_set_access_rights_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_access_rights(0, 0x10); });
    });
}

void
intrinsics_ut::test_gdt_set_access_rights_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.set_access_rights(1000, 0x10); }, e);
    });
}

void
intrinsics_ut::test_gdt_set_access_rights_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_no_exception([&] { gdt.set_access_rights(1, 0x12345678); });
        this->expect_true(g_gdt[1] == 0xFF5F78FFFFFFFFFF);
    });
}

void
intrinsics_ut::test_gdt_access_rights_zero_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        this->expect_true(gdt.access_rights(0) == 0x10000);
    });
}

void
intrinsics_ut::test_gdt_access_rights_invalid_index()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        auto e = std::make_shared<std::invalid_argument>("index out of range");
        this->expect_exception([&] { gdt.access_rights(1000); }, e);
    });
}

void
intrinsics_ut::test_gdt_access_rights_descriptor_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_x64>(mocks);

    mocks.OnCall(intrinsics.get(), intrinsics_x64::read_gdt).Do(set_gdt);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        gdt_x64 gdt(intrinsics);

        g_gdt[1] = 0xFF5F78FFFFFFFFFF;
        this->expect_true(gdt.access_rights(1) == 0x0000000000005078);
    });
}
