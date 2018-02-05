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

TEST_CASE("gdt_constructor_no_size")
{
    setup_gdt();
    gdt_x64 gdt;
}

TEST_CASE("gdt_constructor_zero_size")
{
    CHECK_NOTHROW(gdt_x64{0});
}

TEST_CASE("gdt_constructor_size")
{
    gdt_x64 gdt{4};
    CHECK(gdt.base() != 0);
    CHECK(gdt.limit() == 4 * sizeof(gdt_x64::segment_descriptor_type) - 1);
}

TEST_CASE("gdt_base")
{
    g_gdtr.base = reinterpret_cast<gdt_x64::integer_pointer>(g_gdt.data());

    gdt_x64 gdt;
    CHECK(gdt.base() == reinterpret_cast<gdt_x64::integer_pointer>(g_gdt.data()));
}

TEST_CASE("gdt_limit")
{
    g_gdtr.limit = 42;

    gdt_x64 gdt;
    CHECK(gdt.limit() == 42);
}

TEST_CASE("gdt_set_base_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_base(0, 0x10));
}

TEST_CASE("gdt_set_base_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_base(1000, 0x10));
}

TEST_CASE("gdt_set_base_tss_at_end_of_gdt")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_base(7, 0x10));
}

TEST_CASE("gdt_set_base_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_NOTHROW(gdt.set_base(5, 0xBBBBBBBB12345678));
    CHECK(gdt.m_gdt.at(5) == 0x12FFFF345678FFFF);
}

TEST_CASE("gdt_set_base_tss_success")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_NOTHROW(gdt.set_base(6, 0x1234567812345678));
    CHECK(gdt.m_gdt.at(6) == 0x12FF8F345678FFFF);
    CHECK(gdt.m_gdt.at(7) == 0x0000000012345678);
}

TEST_CASE("gdt_base_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.base(0));
}

TEST_CASE("gdt_base_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.base(1000));
}

TEST_CASE("gdt_base_tss_at_end_of_gdt")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.base(7));
}

TEST_CASE("gdt_base_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    gdt.m_gdt.at(5) = 0x12FFFF345678FFFF;
    CHECK(gdt.base(5) == 0x0000000012345678);
}

TEST_CASE("gdt_base_tss_success")
{
    setup_gdt();

    gdt_x64 gdt;
    gdt.m_gdt.at(6) = 0x12FF8F345678FFFF;
    gdt.m_gdt.at(7) = 0x0000000012345678;
    CHECK(gdt.base(6) == 0x1234567812345678);
}

TEST_CASE("gdt_set_limit_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_limit(0, 0x10));
}

TEST_CASE("gdt_set_limit_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_limit(1000, 0x10));
}

TEST_CASE("gdt_set_limit_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_NOTHROW(gdt.set_limit(5, 0x12345678));
    CHECK(gdt.m_gdt.at(5) == 0xFFF1FFFFFFFF2345);
}

TEST_CASE("gdt_limit_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.limit(0));
}

TEST_CASE("gdt_limit_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.limit(1000));
}

TEST_CASE("gdt_limit_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    gdt.m_gdt.at(5) = 0xFFF4FFFFFFFF5678;
    CHECK(gdt.limit(5) == 0x0000000045678FFF);
}

TEST_CASE("gdt_limit_descriptor_in_bytes_success")
{
    setup_gdt();

    gdt_x64 gdt;
    gdt.m_gdt.at(5) = 0xFF74FFFFFFFF5678;
    CHECK(gdt.limit(5) == 0x0000000000045678);
}

TEST_CASE("gdt_set_access_rights_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_access_rights(0, 0x10));
}

TEST_CASE("gdt_set_access_rights_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.set_access_rights(1000, 0x10));
}

TEST_CASE("gdt_set_access_rights_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_NOTHROW(gdt.set_access_rights(5, 0x12345678));
    CHECK(gdt.m_gdt.at(5) == 0xFF5F78FFFFFFFFFF);
}

TEST_CASE("gdt_access_rights_zero_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.access_rights(0));
}

TEST_CASE("gdt_access_rights_invalid_index")
{
    setup_gdt();

    gdt_x64 gdt;
    CHECK_THROWS(gdt.access_rights(1000));
}

TEST_CASE("gdt_access_rights_descriptor_success")
{
    setup_gdt();

    gdt_x64 gdt;
    gdt.m_gdt.at(5) = 0xFF5F78FFFFFFFFFF;
    CHECK(gdt.access_rights(5) == 0x0000000000005078);
}
