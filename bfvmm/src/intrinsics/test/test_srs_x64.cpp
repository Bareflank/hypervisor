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
#include <intrinsics/srs_x64.h>

using namespace x64;

segment_register::type g_es = 0;
segment_register::type g_cs = 0;
segment_register::type g_ss = 0;
segment_register::type g_ds = 0;
segment_register::type g_fs = 0;
segment_register::type g_gs = 0;
segment_register::type g_ldtr = 0;
segment_register::type g_tr = 0;

extern "C" uint16_t
__read_es(void) noexcept
{ return g_es; }

extern "C" void
__write_es(uint16_t val) noexcept
{ g_es = val; }

extern "C" uint16_t
__read_cs(void) noexcept
{ return g_cs; }

extern "C" void
__write_cs(uint16_t val) noexcept
{ g_cs = val; }

extern "C" uint16_t
__read_ss(void) noexcept
{ return g_ss; }

extern "C" void
__write_ss(uint16_t val) noexcept
{ g_ss = val; }

extern "C" uint16_t
__read_ds(void) noexcept
{ return g_ds; }

extern "C" void
__write_ds(uint16_t val) noexcept
{ g_ds = val; }

extern "C" uint16_t
__read_fs(void) noexcept
{ return g_fs; }

extern "C" void
__write_fs(uint16_t val) noexcept
{ g_fs = val; }

extern "C" uint16_t
__read_gs(void) noexcept
{ return g_gs; }

extern "C" void
__write_gs(uint16_t val) noexcept
{ g_gs = val; }

extern "C" uint16_t
__read_ldtr(void) noexcept
{ return g_ldtr; }

extern "C" void
__write_ldtr(uint16_t val) noexcept
{ g_ldtr = val; }

extern "C" uint16_t
__read_tr(void) noexcept
{ return g_tr; }

extern "C" void
__write_tr(uint16_t val) noexcept
{ g_tr = val; }

void
intrinsics_ut::test_srs_x64_es()
{
    segment_register::es::set(0xFFFFU);
    this->expect_true(segment_register::es::get() == 0xFFFFU);

    segment_register::es::set(0x0U);
    this->expect_true(segment_register::es::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_es_rpl()
{
    segment_register::es::rpl::set(0x3U);
    this->expect_true(segment_register::es::rpl::get() == 0x3U);

    segment_register::es::rpl::set(0x2U);
    this->expect_true(segment_register::es::rpl::get() == 0x2U);

    segment_register::es::rpl::set(0x1U);
    this->expect_true(segment_register::es::rpl::get() == 0x1U);

    segment_register::es::rpl::set(0x0U);
    this->expect_true(segment_register::es::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_es_ti()
{
    segment_register::es::ti::set(true);
    this->expect_true(segment_register::es::ti::get());

    segment_register::es::ti::set(false);
    this->expect_false(segment_register::es::ti::get());
}

void
intrinsics_ut::test_srs_x64_es_index()
{
    segment_register::es::index::set(0x3U);
    this->expect_true(segment_register::es::index::get() == 0x3U);

    segment_register::es::index::set(0x2U);
    this->expect_true(segment_register::es::index::get() == 0x2U);

    segment_register::es::index::set(0x1U);
    this->expect_true(segment_register::es::index::get() == 0x1U);

    segment_register::es::index::set(0x0U);
    this->expect_true(segment_register::es::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_cs()
{
    segment_register::cs::set(0xFFFFU);
    this->expect_true(segment_register::cs::get() == 0xFFFFU);

    segment_register::cs::set(0x0U);
    this->expect_true(segment_register::cs::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_cs_rpl()
{
    segment_register::cs::rpl::set(0x3U);
    this->expect_true(segment_register::cs::rpl::get() == 0x3U);

    segment_register::cs::rpl::set(0x2U);
    this->expect_true(segment_register::cs::rpl::get() == 0x2U);

    segment_register::cs::rpl::set(0x1U);
    this->expect_true(segment_register::cs::rpl::get() == 0x1U);

    segment_register::cs::rpl::set(0x0U);
    this->expect_true(segment_register::cs::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_cs_ti()
{
    segment_register::cs::ti::set(true);
    this->expect_true(segment_register::cs::ti::get());

    segment_register::cs::ti::set(false);
    this->expect_false(segment_register::cs::ti::get());
}

void
intrinsics_ut::test_srs_x64_cs_index()
{
    segment_register::cs::index::set(0x3U);
    this->expect_true(segment_register::cs::index::get() == 0x3U);

    segment_register::cs::index::set(0x2U);
    this->expect_true(segment_register::cs::index::get() == 0x2U);

    segment_register::cs::index::set(0x1U);
    this->expect_true(segment_register::cs::index::get() == 0x1U);

    segment_register::cs::index::set(0x0U);
    this->expect_true(segment_register::cs::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ss()
{
    segment_register::ss::set(0xFFFFU);
    this->expect_true(segment_register::ss::get() == 0xFFFFU);

    segment_register::ss::set(0x0U);
    this->expect_true(segment_register::ss::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ss_rpl()
{
    segment_register::ss::rpl::set(0x3U);
    this->expect_true(segment_register::ss::rpl::get() == 0x3U);

    segment_register::ss::rpl::set(0x2U);
    this->expect_true(segment_register::ss::rpl::get() == 0x2U);

    segment_register::ss::rpl::set(0x1U);
    this->expect_true(segment_register::ss::rpl::get() == 0x1U);

    segment_register::ss::rpl::set(0x0U);
    this->expect_true(segment_register::ss::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ss_ti()
{
    segment_register::ss::ti::set(true);
    this->expect_true(segment_register::ss::ti::get());

    segment_register::ss::ti::set(false);
    this->expect_false(segment_register::ss::ti::get());
}

void
intrinsics_ut::test_srs_x64_ss_index()
{
    segment_register::ss::index::set(0x3U);
    this->expect_true(segment_register::ss::index::get() == 0x3U);

    segment_register::ss::index::set(0x2U);
    this->expect_true(segment_register::ss::index::get() == 0x2U);

    segment_register::ss::index::set(0x1U);
    this->expect_true(segment_register::ss::index::get() == 0x1U);

    segment_register::ss::index::set(0x0U);
    this->expect_true(segment_register::ss::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ds()
{
    segment_register::ds::set(0xFFFFU);
    this->expect_true(segment_register::ds::get() == 0xFFFFU);

    segment_register::ds::set(0x0U);
    this->expect_true(segment_register::ds::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ds_rpl()
{
    segment_register::ds::rpl::set(0x3U);
    this->expect_true(segment_register::ds::rpl::get() == 0x3U);

    segment_register::ds::rpl::set(0x2U);
    this->expect_true(segment_register::ds::rpl::get() == 0x2U);

    segment_register::ds::rpl::set(0x1U);
    this->expect_true(segment_register::ds::rpl::get() == 0x1U);

    segment_register::ds::rpl::set(0x0U);
    this->expect_true(segment_register::ds::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ds_ti()
{
    segment_register::ds::ti::set(true);
    this->expect_true(segment_register::ds::ti::get());

    segment_register::ds::ti::set(false);
    this->expect_false(segment_register::ds::ti::get());
}

void
intrinsics_ut::test_srs_x64_ds_index()
{
    segment_register::ds::index::set(0x3U);
    this->expect_true(segment_register::ds::index::get() == 0x3U);

    segment_register::ds::index::set(0x2U);
    this->expect_true(segment_register::ds::index::get() == 0x2U);

    segment_register::ds::index::set(0x1U);
    this->expect_true(segment_register::ds::index::get() == 0x1U);

    segment_register::ds::index::set(0x0U);
    this->expect_true(segment_register::ds::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_fs()
{
    segment_register::fs::set(0xFFFFU);
    this->expect_true(segment_register::fs::get() == 0xFFFFU);

    segment_register::fs::set(0x0U);
    this->expect_true(segment_register::fs::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_fs_rpl()
{
    segment_register::fs::rpl::set(0x3U);
    this->expect_true(segment_register::fs::rpl::get() == 0x3U);

    segment_register::fs::rpl::set(0x2U);
    this->expect_true(segment_register::fs::rpl::get() == 0x2U);

    segment_register::fs::rpl::set(0x1U);
    this->expect_true(segment_register::fs::rpl::get() == 0x1U);

    segment_register::fs::rpl::set(0x0U);
    this->expect_true(segment_register::fs::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_fs_ti()
{
    segment_register::fs::ti::set(true);
    this->expect_true(segment_register::fs::ti::get());

    segment_register::fs::ti::set(false);
    this->expect_false(segment_register::fs::ti::get());
}

void
intrinsics_ut::test_srs_x64_fs_index()
{
    segment_register::fs::index::set(0x3U);
    this->expect_true(segment_register::fs::index::get() == 0x3U);

    segment_register::fs::index::set(0x2U);
    this->expect_true(segment_register::fs::index::get() == 0x2U);

    segment_register::fs::index::set(0x1U);
    this->expect_true(segment_register::fs::index::get() == 0x1U);

    segment_register::fs::index::set(0x0U);
    this->expect_true(segment_register::fs::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_gs()
{
    segment_register::gs::set(0xFFFFU);
    this->expect_true(segment_register::gs::get() == 0xFFFFU);

    segment_register::gs::set(0x0U);
    this->expect_true(segment_register::gs::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_gs_rpl()
{
    segment_register::gs::rpl::set(0x3U);
    this->expect_true(segment_register::gs::rpl::get() == 0x3U);

    segment_register::gs::rpl::set(0x2U);
    this->expect_true(segment_register::gs::rpl::get() == 0x2U);

    segment_register::gs::rpl::set(0x1U);
    this->expect_true(segment_register::gs::rpl::get() == 0x1U);

    segment_register::gs::rpl::set(0x0U);
    this->expect_true(segment_register::gs::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_gs_ti()
{
    segment_register::gs::ti::set(true);
    this->expect_true(segment_register::gs::ti::get());

    segment_register::gs::ti::set(false);
    this->expect_false(segment_register::gs::ti::get());
}

void
intrinsics_ut::test_srs_x64_gs_index()
{
    segment_register::gs::index::set(0x3U);
    this->expect_true(segment_register::gs::index::get() == 0x3U);

    segment_register::gs::index::set(0x2U);
    this->expect_true(segment_register::gs::index::get() == 0x2U);

    segment_register::gs::index::set(0x1U);
    this->expect_true(segment_register::gs::index::get() == 0x1U);

    segment_register::gs::index::set(0x0U);
    this->expect_true(segment_register::gs::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ldtr()
{
    segment_register::ldtr::set(0xFFFFU);
    this->expect_true(segment_register::ldtr::get() == 0xFFFFU);

    segment_register::ldtr::set(0x0U);
    this->expect_true(segment_register::ldtr::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ldtr_rpl()
{
    segment_register::ldtr::rpl::set(0x3U);
    this->expect_true(segment_register::ldtr::rpl::get() == 0x3U);

    segment_register::ldtr::rpl::set(0x2U);
    this->expect_true(segment_register::ldtr::rpl::get() == 0x2U);

    segment_register::ldtr::rpl::set(0x1U);
    this->expect_true(segment_register::ldtr::rpl::get() == 0x1U);

    segment_register::ldtr::rpl::set(0x0U);
    this->expect_true(segment_register::ldtr::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_ldtr_ti()
{
    segment_register::ldtr::ti::set(true);
    this->expect_true(segment_register::ldtr::ti::get());

    segment_register::ldtr::ti::set(false);
    this->expect_false(segment_register::ldtr::ti::get());
}

void
intrinsics_ut::test_srs_x64_ldtr_index()
{
    segment_register::ldtr::index::set(0x3U);
    this->expect_true(segment_register::ldtr::index::get() == 0x3U);

    segment_register::ldtr::index::set(0x2U);
    this->expect_true(segment_register::ldtr::index::get() == 0x2U);

    segment_register::ldtr::index::set(0x1U);
    this->expect_true(segment_register::ldtr::index::get() == 0x1U);

    segment_register::ldtr::index::set(0x0U);
    this->expect_true(segment_register::ldtr::index::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_tr()
{
    segment_register::tr::set(0xFFFFU);
    this->expect_true(segment_register::tr::get() == 0xFFFFU);

    segment_register::tr::set(0x0U);
    this->expect_true(segment_register::tr::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_tr_rpl()
{
    segment_register::tr::rpl::set(0x3U);
    this->expect_true(segment_register::tr::rpl::get() == 0x3U);

    segment_register::tr::rpl::set(0x2U);
    this->expect_true(segment_register::tr::rpl::get() == 0x2U);

    segment_register::tr::rpl::set(0x1U);
    this->expect_true(segment_register::tr::rpl::get() == 0x1U);

    segment_register::tr::rpl::set(0x0U);
    this->expect_true(segment_register::tr::rpl::get() == 0x0U);
}

void
intrinsics_ut::test_srs_x64_tr_ti()
{
    segment_register::tr::ti::set(true);
    this->expect_true(segment_register::tr::ti::get());

    segment_register::tr::ti::set(false);
    this->expect_false(segment_register::tr::ti::get());
}

void
intrinsics_ut::test_srs_x64_tr_index()
{
    segment_register::tr::index::set(0x3U);
    this->expect_true(segment_register::tr::index::get() == 0x3U);

    segment_register::tr::index::set(0x2U);
    this->expect_true(segment_register::tr::index::get() == 0x2U);

    segment_register::tr::index::set(0x1U);
    this->expect_true(segment_register::tr::index::get() == 0x1U);

    segment_register::tr::index::set(0x0U);
    this->expect_true(segment_register::tr::index::get() == 0x0U);
}
