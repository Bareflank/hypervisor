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

#include <gsl/gsl>

#include <test.h>
#include <intrinsics/gdt_x64.h>

std::vector<gdt_x64::segment_descriptor_type> g_gdt =
{
    0x0,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF
};

gdt_reg_x64_t g_gdt_reg;

extern "C" void
__read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ *gdt_reg = g_gdt_reg; }

extern "C" void
__write_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ g_gdt_reg = *gdt_reg; }

void
intrinsics_ut::test_gdt_reg_set_get()
{
    x64::gdt::set(g_gdt.data(), 4 << 3);

    this->expect_true(x64::gdt::get().base == g_gdt.data());
    this->expect_true(x64::gdt::get().limit == 4 << 3);
}

void
intrinsics_ut::test_gdt_reg_base_set_get()
{
    x64::gdt::base::set(g_gdt.data());
    this->expect_true(x64::gdt::base::get() == g_gdt.data());
}

void
intrinsics_ut::test_gdt_reg_limit_set_get()
{
    x64::gdt::limit::set(4 << 3);
    this->expect_true(x64::gdt::limit::get() == 4 << 3);
}

void
intrinsics_ut::test_gdt_constructor_no_size()
{
    gdt_x64 gdt;
}

void
intrinsics_ut::test_gdt_constructor_zero_size()
{
    this->expect_exception([&] { gdt_x64{0}; }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_constructor_size()
{
    gdt_x64 gdt{4};
    this->expect_true(gdt.base() != 0);
    this->expect_true(gdt.limit() == 4 * sizeof(gdt_x64::segment_descriptor_type));
}

void
intrinsics_ut::test_gdt_base()
{
    gdt_x64 gdt;
    this->expect_true(gdt.base() == reinterpret_cast<gdt_x64::integer_pointer>(g_gdt.data()));
}

void
intrinsics_ut::test_gdt_limit()
{
    gdt_x64 gdt;
    this->expect_true(gdt.limit() == 4 * sizeof(gdt_x64::segment_descriptor_type));
}

void
intrinsics_ut::test_gdt_set_base_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_base(0, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_base_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_base(1000, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_base_tss_at_end_of_gdt()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_base(3, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_base_descriptor_success()
{
    gdt_x64 gdt;

    this->expect_no_exception([&] { gdt.set_base(1, 0xBBBBBBBB12345678); });
    this->expect_true(gdt.m_gdt.at(1) == 0x12FFFF345678FFFF);
}

void
intrinsics_ut::test_gdt_set_base_tss_success()
{
    gdt_x64 gdt;

    this->expect_no_exception([&] { gdt.set_base(2, 0x1234567812345678); });
    this->expect_true(gdt.m_gdt.at(2) == 0x12FF8F345678FFFF);
    this->expect_true(gdt.m_gdt.at(3) == 0x0000000012345678);
}

void
intrinsics_ut::test_gdt_base_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.base(0); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_base_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.base(1000); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_base_tss_at_end_of_gdt()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.base(3); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_base_descriptor_success()
{
    gdt_x64 gdt;

    gdt.m_gdt.at(1) = 0x12FFFF345678FFFF;
    this->expect_true(gdt.base(1) == 0x0000000012345678);
}

void
intrinsics_ut::test_gdt_base_tss_success()
{
    gdt_x64 gdt;

    gdt.m_gdt.at(2) = 0x12FF8F345678FFFF;
    gdt.m_gdt.at(3) = 0x0000000012345678;
    this->expect_true(gdt.base(2) == 0x1234567812345678);
}

void
intrinsics_ut::test_gdt_set_limit_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_limit(0, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_limit_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_limit(1000, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_limit_descriptor_success()
{
    gdt_x64 gdt;

    this->expect_no_exception([&] { gdt.set_limit(1, 0x12345678); });
    this->expect_true(gdt.m_gdt.at(1) == 0xFFF1FFFFFFFF2345);
}

void
intrinsics_ut::test_gdt_limit_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.limit(0); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_limit_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.limit(1000); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_limit_descriptor_success()
{
    gdt_x64 gdt;

    gdt.m_gdt.at(1) = 0xFFF4FFFFFFFF5678;
    this->expect_true(gdt.limit(1) == 0x0000000045678FFF);
}

void
intrinsics_ut::test_gdt_limit_descriptor_in_bytes_success()
{
    gdt_x64 gdt;

    gdt.m_gdt.at(1) = 0xFF74FFFFFFFF5678;
    this->expect_true(gdt.limit(1) == 0x0000000000045678);
}

void
intrinsics_ut::test_gdt_set_access_rights_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_access_rights(0, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_access_rights_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.set_access_rights(1000, 0x10); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_set_access_rights_descriptor_success()
{
    gdt_x64 gdt;

    this->expect_no_exception([&] { gdt.set_access_rights(1, 0x12345678); });
    this->expect_true(gdt.m_gdt.at(1) == 0xFF5F78FFFFFFFFFF);
}

void
intrinsics_ut::test_gdt_access_rights_zero_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.access_rights(0); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_access_rights_invalid_index()
{
    gdt_x64 gdt;
    this->expect_exception([&] { gdt.access_rights(1000); }, ""_ut_ffe);
}

void
intrinsics_ut::test_gdt_access_rights_descriptor_success()
{
    gdt_x64 gdt;

    gdt.m_gdt.at(1) = 0xFF5F78FFFFFFFFFF;
    this->expect_true(gdt.access_rights(1) == 0x0000000000005078);
}
