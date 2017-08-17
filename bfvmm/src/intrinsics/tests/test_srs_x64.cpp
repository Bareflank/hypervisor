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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/common_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

segment_register::type g_es = 0;
segment_register::type g_cs = 0;
segment_register::type g_ss = 0;
segment_register::type g_ds = 0;
segment_register::type g_fs = 0;
segment_register::type g_gs = 0;
segment_register::type g_ldtr = 0;
segment_register::type g_tr = 0;

uint16_t
test_read_es() noexcept
{ return g_es; }

void
test_write_es(uint16_t val) noexcept
{ g_es = val; }

uint16_t
test_read_cs() noexcept
{ return g_cs; }

void
test_write_cs(uint16_t val) noexcept
{ g_cs = val; }

uint16_t
test_read_ss() noexcept
{ return g_ss; }

void
test_write_ss(uint16_t val) noexcept
{ g_ss = val; }

uint16_t
test_read_ds() noexcept
{ return g_ds; }

void
test_write_ds(uint16_t val) noexcept
{ g_ds = val; }

uint16_t
test_read_fs() noexcept
{ return g_fs; }

void
test_write_fs(uint16_t val) noexcept
{ g_fs = val; }

uint16_t
test_read_gs() noexcept
{ return g_gs; }

void
test_write_gs(uint16_t val) noexcept
{ g_gs = val; }

uint16_t
test_read_ldtr() noexcept
{ return g_ldtr; }

void
test_write_ldtr(uint16_t val) noexcept
{ g_ldtr = val; }

uint16_t
test_read_tr() noexcept
{ return g_tr; }

void
test_write_tr(uint16_t val) noexcept
{ g_tr = val; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_es).Do(test_read_es);
    mocks.OnCallFunc(_write_es).Do(test_write_es);
    mocks.OnCallFunc(_read_cs).Do(test_read_cs);
    mocks.OnCallFunc(_write_cs).Do(test_write_cs);
    mocks.OnCallFunc(_read_ss).Do(test_read_ss);
    mocks.OnCallFunc(_write_ss).Do(test_write_ss);
    mocks.OnCallFunc(_read_ds).Do(test_read_ds);
    mocks.OnCallFunc(_write_ds).Do(test_write_ds);
    mocks.OnCallFunc(_read_fs).Do(test_read_fs);
    mocks.OnCallFunc(_write_fs).Do(test_write_fs);
    mocks.OnCallFunc(_read_gs).Do(test_read_gs);
    mocks.OnCallFunc(_write_gs).Do(test_write_gs);
    mocks.OnCallFunc(_read_ldtr).Do(test_read_ldtr);
    mocks.OnCallFunc(_write_ldtr).Do(test_write_ldtr);
    mocks.OnCallFunc(_read_tr).Do(test_read_tr);
    mocks.OnCallFunc(_write_tr).Do(test_write_tr);
}

TEST_CASE("srs_x64_es")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::es::set(0xFFFFU);
    CHECK(segment_register::es::get() == 0xFFFFU);

    segment_register::es::set(0x0U);
    CHECK(segment_register::es::get() == 0x0U);
}

TEST_CASE("srs_x64_es_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::es::rpl::set(0x3U);
    CHECK(segment_register::es::rpl::get() == 0x3U);

    segment_register::es::rpl::set(0x2U);
    CHECK(segment_register::es::rpl::get() == 0x2U);

    segment_register::es::rpl::set(0x1U);
    CHECK(segment_register::es::rpl::get() == 0x1U);

    segment_register::es::rpl::set(0x0U);
    CHECK(segment_register::es::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_es_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::es::ti::set(true);
    CHECK(segment_register::es::ti::get());

    segment_register::es::ti::set(false);
    CHECK_FALSE(segment_register::es::ti::get());
}

TEST_CASE("srs_x64_es_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::es::index::set(0x3U);
    CHECK(segment_register::es::index::get() == 0x3U);

    segment_register::es::index::set(0x2U);
    CHECK(segment_register::es::index::get() == 0x2U);

    segment_register::es::index::set(0x1U);
    CHECK(segment_register::es::index::get() == 0x1U);

    segment_register::es::index::set(0x0U);
    CHECK(segment_register::es::index::get() == 0x0U);
}

TEST_CASE("srs_x64_cs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::cs::set(0xFFFFU);
    CHECK(segment_register::cs::get() == 0xFFFFU);

    segment_register::cs::set(0x0U);
    CHECK(segment_register::cs::get() == 0x0U);
}

TEST_CASE("srs_x64_cs_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::cs::rpl::set(0x3U);
    CHECK(segment_register::cs::rpl::get() == 0x3U);

    segment_register::cs::rpl::set(0x2U);
    CHECK(segment_register::cs::rpl::get() == 0x2U);

    segment_register::cs::rpl::set(0x1U);
    CHECK(segment_register::cs::rpl::get() == 0x1U);

    segment_register::cs::rpl::set(0x0U);
    CHECK(segment_register::cs::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_cs_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::cs::ti::set(true);
    CHECK(segment_register::cs::ti::get());

    segment_register::cs::ti::set(false);
    CHECK_FALSE(segment_register::cs::ti::get());
}

TEST_CASE("srs_x64_cs_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::cs::index::set(0x3U);
    CHECK(segment_register::cs::index::get() == 0x3U);

    segment_register::cs::index::set(0x2U);
    CHECK(segment_register::cs::index::get() == 0x2U);

    segment_register::cs::index::set(0x1U);
    CHECK(segment_register::cs::index::get() == 0x1U);

    segment_register::cs::index::set(0x0U);
    CHECK(segment_register::cs::index::get() == 0x0U);
}

TEST_CASE("srs_x64_ss")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ss::set(0xFFFFU);
    CHECK(segment_register::ss::get() == 0xFFFFU);

    segment_register::ss::set(0x0U);
    CHECK(segment_register::ss::get() == 0x0U);
}

TEST_CASE("srs_x64_ss_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ss::rpl::set(0x3U);
    CHECK(segment_register::ss::rpl::get() == 0x3U);

    segment_register::ss::rpl::set(0x2U);
    CHECK(segment_register::ss::rpl::get() == 0x2U);

    segment_register::ss::rpl::set(0x1U);
    CHECK(segment_register::ss::rpl::get() == 0x1U);

    segment_register::ss::rpl::set(0x0U);
    CHECK(segment_register::ss::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_ss_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ss::ti::set(true);
    CHECK(segment_register::ss::ti::get());

    segment_register::ss::ti::set(false);
    CHECK_FALSE(segment_register::ss::ti::get());
}

TEST_CASE("srs_x64_ss_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ss::index::set(0x3U);
    CHECK(segment_register::ss::index::get() == 0x3U);

    segment_register::ss::index::set(0x2U);
    CHECK(segment_register::ss::index::get() == 0x2U);

    segment_register::ss::index::set(0x1U);
    CHECK(segment_register::ss::index::get() == 0x1U);

    segment_register::ss::index::set(0x0U);
    CHECK(segment_register::ss::index::get() == 0x0U);
}

TEST_CASE("srs_x64_ds")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ds::set(0xFFFFU);
    CHECK(segment_register::ds::get() == 0xFFFFU);

    segment_register::ds::set(0x0U);
    CHECK(segment_register::ds::get() == 0x0U);
}

TEST_CASE("srs_x64_ds_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ds::rpl::set(0x3U);
    CHECK(segment_register::ds::rpl::get() == 0x3U);

    segment_register::ds::rpl::set(0x2U);
    CHECK(segment_register::ds::rpl::get() == 0x2U);

    segment_register::ds::rpl::set(0x1U);
    CHECK(segment_register::ds::rpl::get() == 0x1U);

    segment_register::ds::rpl::set(0x0U);
    CHECK(segment_register::ds::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_ds_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ds::ti::set(true);
    CHECK(segment_register::ds::ti::get());

    segment_register::ds::ti::set(false);
    CHECK_FALSE(segment_register::ds::ti::get());
}

TEST_CASE("srs_x64_ds_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ds::index::set(0x3U);
    CHECK(segment_register::ds::index::get() == 0x3U);

    segment_register::ds::index::set(0x2U);
    CHECK(segment_register::ds::index::get() == 0x2U);

    segment_register::ds::index::set(0x1U);
    CHECK(segment_register::ds::index::get() == 0x1U);

    segment_register::ds::index::set(0x0U);
    CHECK(segment_register::ds::index::get() == 0x0U);
}

TEST_CASE("srs_x64_fs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::fs::set(0xFFFFU);
    CHECK(segment_register::fs::get() == 0xFFFFU);

    segment_register::fs::set(0x0U);
    CHECK(segment_register::fs::get() == 0x0U);
}

TEST_CASE("srs_x64_fs_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::fs::rpl::set(0x3U);
    CHECK(segment_register::fs::rpl::get() == 0x3U);

    segment_register::fs::rpl::set(0x2U);
    CHECK(segment_register::fs::rpl::get() == 0x2U);

    segment_register::fs::rpl::set(0x1U);
    CHECK(segment_register::fs::rpl::get() == 0x1U);

    segment_register::fs::rpl::set(0x0U);
    CHECK(segment_register::fs::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_fs_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::fs::ti::set(true);
    CHECK(segment_register::fs::ti::get());

    segment_register::fs::ti::set(false);
    CHECK_FALSE(segment_register::fs::ti::get());
}

TEST_CASE("srs_x64_fs_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::fs::index::set(0x3U);
    CHECK(segment_register::fs::index::get() == 0x3U);

    segment_register::fs::index::set(0x2U);
    CHECK(segment_register::fs::index::get() == 0x2U);

    segment_register::fs::index::set(0x1U);
    CHECK(segment_register::fs::index::get() == 0x1U);

    segment_register::fs::index::set(0x0U);
    CHECK(segment_register::fs::index::get() == 0x0U);
}

TEST_CASE("srs_x64_gs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::gs::set(0xFFFFU);
    CHECK(segment_register::gs::get() == 0xFFFFU);

    segment_register::gs::set(0x0U);
    CHECK(segment_register::gs::get() == 0x0U);
}

TEST_CASE("srs_x64_gs_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::gs::rpl::set(0x3U);
    CHECK(segment_register::gs::rpl::get() == 0x3U);

    segment_register::gs::rpl::set(0x2U);
    CHECK(segment_register::gs::rpl::get() == 0x2U);

    segment_register::gs::rpl::set(0x1U);
    CHECK(segment_register::gs::rpl::get() == 0x1U);

    segment_register::gs::rpl::set(0x0U);
    CHECK(segment_register::gs::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_gs_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::gs::ti::set(true);
    CHECK(segment_register::gs::ti::get());

    segment_register::gs::ti::set(false);
    CHECK_FALSE(segment_register::gs::ti::get());
}

TEST_CASE("srs_x64_gs_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::gs::index::set(0x3U);
    CHECK(segment_register::gs::index::get() == 0x3U);

    segment_register::gs::index::set(0x2U);
    CHECK(segment_register::gs::index::get() == 0x2U);

    segment_register::gs::index::set(0x1U);
    CHECK(segment_register::gs::index::get() == 0x1U);

    segment_register::gs::index::set(0x0U);
    CHECK(segment_register::gs::index::get() == 0x0U);
}

TEST_CASE("srs_x64_ldtr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ldtr::set(0xFFFFU);
    CHECK(segment_register::ldtr::get() == 0xFFFFU);

    segment_register::ldtr::set(0x0U);
    CHECK(segment_register::ldtr::get() == 0x0U);
}

TEST_CASE("srs_x64_ldtr_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ldtr::rpl::set(0x3U);
    CHECK(segment_register::ldtr::rpl::get() == 0x3U);

    segment_register::ldtr::rpl::set(0x2U);
    CHECK(segment_register::ldtr::rpl::get() == 0x2U);

    segment_register::ldtr::rpl::set(0x1U);
    CHECK(segment_register::ldtr::rpl::get() == 0x1U);

    segment_register::ldtr::rpl::set(0x0U);
    CHECK(segment_register::ldtr::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_ldtr_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ldtr::ti::set(true);
    CHECK(segment_register::ldtr::ti::get());

    segment_register::ldtr::ti::set(false);
    CHECK_FALSE(segment_register::ldtr::ti::get());
}

TEST_CASE("srs_x64_ldtr_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::ldtr::index::set(0x3U);
    CHECK(segment_register::ldtr::index::get() == 0x3U);

    segment_register::ldtr::index::set(0x2U);
    CHECK(segment_register::ldtr::index::get() == 0x2U);

    segment_register::ldtr::index::set(0x1U);
    CHECK(segment_register::ldtr::index::get() == 0x1U);

    segment_register::ldtr::index::set(0x0U);
    CHECK(segment_register::ldtr::index::get() == 0x0U);
}

TEST_CASE("srs_x64_tr")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::tr::set(0xFFFFU);
    CHECK(segment_register::tr::get() == 0xFFFFU);

    segment_register::tr::set(0x0U);
    CHECK(segment_register::tr::get() == 0x0U);
}

TEST_CASE("srs_x64_tr_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::tr::rpl::set(0x3U);
    CHECK(segment_register::tr::rpl::get() == 0x3U);

    segment_register::tr::rpl::set(0x2U);
    CHECK(segment_register::tr::rpl::get() == 0x2U);

    segment_register::tr::rpl::set(0x1U);
    CHECK(segment_register::tr::rpl::get() == 0x1U);

    segment_register::tr::rpl::set(0x0U);
    CHECK(segment_register::tr::rpl::get() == 0x0U);
}

TEST_CASE("srs_x64_tr_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::tr::ti::set(true);
    CHECK(segment_register::tr::ti::get());

    segment_register::tr::ti::set(false);
    CHECK_FALSE(segment_register::tr::ti::get());
}

TEST_CASE("srs_x64_tr_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::tr::index::set(0x3U);
    CHECK(segment_register::tr::index::get() == 0x3U);

    segment_register::tr::index::set(0x2U);
    CHECK(segment_register::tr::index::get() == 0x2U);

    segment_register::tr::index::set(0x1U);
    CHECK(segment_register::tr::index::get() == 0x1U);

    segment_register::tr::index::set(0x0U);
    CHECK(segment_register::tr::index::get() == 0x0U);
}

#endif
