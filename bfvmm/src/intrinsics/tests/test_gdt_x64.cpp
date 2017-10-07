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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/common_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("test name goes here")
{
    CHECK(true);
}

std::vector<gdt_x64::segment_descriptor_type> g_gdt = {
    0x0,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF
};

gdt_reg_x64_t g_gdt_reg;

void
test_read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ *gdt_reg = g_gdt_reg; }

void
test_write_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ g_gdt_reg = *gdt_reg; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_gdt).Do(test_read_gdt);
    mocks.OnCallFunc(_write_gdt).Do(test_write_gdt);
}

TEST_CASE("gdt_reg_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::gdt::set(g_gdt.data(), 4 << 3);

    CHECK(x64::gdt::get().base == g_gdt.data());
    CHECK(x64::gdt::get().limit == 4 << 3);
}

TEST_CASE("gdt_reg_base_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::gdt::base::set(g_gdt.data());
    CHECK(x64::gdt::base::get() == g_gdt.data());
}

TEST_CASE("gdt_reg_limit_set_get")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    x64::gdt::limit::set(4 << 3);
    CHECK(x64::gdt::limit::get() == 4 << 3);
}

TEST_CASE("gdt_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    uint64_t bytes = 0x0;
    CHECK(x64::gdt::size(bytes) == 0U);

    bytes = 0x2;
    CHECK(x64::gdt::size(bytes) == 1U);

    bytes = 0x1000;
    CHECK(x64::gdt::size(bytes) == 1U * x64::page_size);

    bytes = 0x2001;
    CHECK(x64::gdt::size(bytes) == 2U * x64::page_size + 1U);
}

TEST_CASE("gdt_constructor_no_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    gdt_x64 gdt;
}

TEST_CASE("gdt_constructor_zero_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(gdt_x64{0});
}

TEST_CASE("gdt_constructor_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    gdt_x64 gdt{4};
    CHECK(gdt.base() != 0);
    CHECK(gdt.limit() == 4 * sizeof(gdt_x64::segment_descriptor_type) - 1);
}

TEST_CASE("gdt_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    gdt_x64 gdt;
    CHECK(gdt.base() == reinterpret_cast<gdt_x64::integer_pointer>(g_gdt.data()));
}

TEST_CASE("gdt_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    gdt_x64 gdt;
    CHECK(gdt.limit() == 4 * sizeof(gdt_x64::segment_descriptor_type));
}

//TEST_CASE("gdt_set_base_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_base(0, 0x10));
//}
//
//TEST_CASE("gdt_set_base_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_base(1000, 0x10));
//}
//
//TEST_CASE("gdt_set_base_tss_at_end_of_gdt")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_base(3, 0x10));
//}
//
//TEST_CASE("gdt_set_base_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    CHECK_NOTHROW(gdt.set_base(1, 0xBBBBBBBB12345678));
//    CHECK(gdt.m_gdt.at(1) == 0x12FFFF345678FFFF);
//}
//
//TEST_CASE("gdt_set_base_tss_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    CHECK_NOTHROW(gdt.set_base(2, 0x1234567812345678));
//    CHECK(gdt.m_gdt.at(2) == 0x12FF8F345678FFFF);
//    CHECK(gdt.m_gdt.at(3) == 0x0000000012345678);
//}
//
//TEST_CASE("gdt_base_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.base(0));
//}
//
//TEST_CASE("gdt_base_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.base(1000));
//}
//
//TEST_CASE("gdt_base_tss_at_end_of_gdt")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.base(3));
//}
//
//TEST_CASE("gdt_base_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    gdt.m_gdt.at(1) = 0x12FFFF345678FFFF;
//    CHECK(gdt.base(1) == 0x0000000012345678);
//}
//
//TEST_CASE("gdt_base_tss_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    gdt.m_gdt.at(2) = 0x12FF8F345678FFFF;
//    gdt.m_gdt.at(3) = 0x0000000012345678;
//    CHECK(gdt.base(2) == 0x1234567812345678);
//}
//
//TEST_CASE("gdt_set_limit_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_limit(0, 0x10));
//}
//
//TEST_CASE("gdt_set_limit_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_limit(1000, 0x10));
//}
//
//TEST_CASE("gdt_set_limit_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    CHECK_NOTHROW(gdt.set_limit(1, 0x12345678));
//    CHECK(gdt.m_gdt.at(1) == 0xFFF1FFFFFFFF2345);
//}
//
//TEST_CASE("gdt_limit_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.limit(0));
//}
//
//TEST_CASE("gdt_limit_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.limit(1000));
//}
//
//TEST_CASE("gdt_limit_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    gdt.m_gdt.at(1) = 0xFFF4FFFFFFFF5678;
//    CHECK(gdt.limit(1) == 0x0000000045678FFF);
//}
//
//TEST_CASE("gdt_limit_descriptor_in_bytes_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    gdt.m_gdt.at(1) = 0xFF74FFFFFFFF5678;
//    CHECK(gdt.limit(1) == 0x0000000000045678);
//}
//
//TEST_CASE("gdt_set_access_rights_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_access_rights(0, 0x10));
//}
//
//TEST_CASE("gdt_set_access_rights_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.set_access_rights(1000, 0x10));
//}
//
//TEST_CASE("gdt_set_access_rights_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    CHECK_NOTHROW(gdt.set_access_rights(1, 0x12345678));
//    CHECK(gdt.m_gdt.at(1) == 0xFF5F78FFFFFFFFFF);
//}
//
//TEST_CASE("gdt_access_rights_zero_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.access_rights(0));
//}
//
//TEST_CASE("gdt_access_rights_invalid_index")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//    CHECK_THROWS(gdt.access_rights(1000));
//}
//
//TEST_CASE("gdt_access_rights_descriptor_success")
//{
//    MockRepository mocks;
//    setup_intrinsics(mocks);
//
//    gdt_x64 gdt;
//
//    gdt.m_gdt.at(1) = 0xFF5F78FFFFFFFFFF;
//    CHECK(gdt.access_rights(1) == 0x0000000000005078);
//}

#endif
