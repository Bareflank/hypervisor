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
#include <intrinsics.h>

using namespace x64;

segment_register::value_type g_es = 0;
segment_register::value_type g_cs = 0;
segment_register::value_type g_ss = 0;
segment_register::value_type g_ds = 0;
segment_register::value_type g_fs = 0;
segment_register::value_type g_gs = 0;
segment_register::value_type g_ldtr = 0;
segment_register::value_type g_tr = 0;

extern "C" uint16_t
_read_es() noexcept
{ return g_es; }

extern "C" void
_write_es(uint16_t val) noexcept
{ g_es = val; }

extern "C" uint16_t
_read_cs() noexcept
{ return g_cs; }

extern "C" void
_write_cs(uint16_t val) noexcept
{ g_cs = val; }

extern "C" uint16_t
_read_ss() noexcept
{ return g_ss; }

extern "C" void
_write_ss(uint16_t val) noexcept
{ g_ss = val; }

extern "C" uint16_t
_read_ds() noexcept
{ return g_ds; }

extern "C" void
_write_ds(uint16_t val) noexcept
{ g_ds = val; }

extern "C" uint16_t
_read_fs() noexcept
{ return g_fs; }

extern "C" void
_write_fs(uint16_t val) noexcept
{ g_fs = val; }

extern "C" uint16_t
_read_gs() noexcept
{ return g_gs; }

extern "C" void
_write_gs(uint16_t val) noexcept
{ g_gs = val; }

extern "C" uint16_t
_read_ldtr() noexcept
{ return g_ldtr; }

extern "C" void
_write_ldtr(uint16_t val) noexcept
{ g_ldtr = val; }

extern "C" uint16_t
_read_tr() noexcept
{ return g_tr; }

extern "C" void
_write_tr(uint16_t val) noexcept
{ g_tr = val; }

TEST_CASE("srs_x64_es")
{
    using namespace segment_register::es;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_es_rpl")
{
    using namespace segment_register::es;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_es_ti")
{
    using namespace segment_register::es;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_es_index")
{
    using namespace segment_register::es;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_cs")
{
    using namespace segment_register::cs;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_cs_rpl")
{
    using namespace segment_register::cs;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_cs_ti")
{
    using namespace segment_register::cs;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_cs_index")
{
    using namespace segment_register::cs;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_ss")
{
    using namespace segment_register::ss;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_ss_rpl")
{
    using namespace segment_register::ss;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_ss_ti")
{
    using namespace segment_register::ss;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_ss_index")
{
    using namespace segment_register::ss;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_ds")
{
    using namespace segment_register::ds;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_ds_rpl")
{
    using namespace segment_register::ds;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_ds_ti")
{
    using namespace segment_register::ds;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_ds_index")
{
    using namespace segment_register::ds;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_fs")
{
    using namespace segment_register::fs;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_fs_rpl")
{
    using namespace segment_register::fs;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_fs_ti")
{
    using namespace segment_register::fs;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_fs_index")
{
    using namespace segment_register::fs;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_gs")
{
    using namespace segment_register::gs;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_gs_rpl")
{
    using namespace segment_register::gs;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_gs_ti")
{
    using namespace segment_register::gs;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_gs_index")
{
    using namespace segment_register::gs;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_ldtr")
{
    using namespace segment_register::ldtr;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_ldtr_rpl")
{
    using namespace segment_register::ldtr;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_ldtr_ti")
{
    using namespace segment_register::ldtr;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_ldtr_index")
{
    using namespace segment_register::ldtr;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}

TEST_CASE("srs_x64_tr")
{
    using namespace segment_register::tr;

    set(0xFFFFU);
    CHECK(get() == 0xFFFFU);
    dump(0);
}

TEST_CASE("srs_x64_tr_rpl")
{
    using namespace segment_register::tr;

    rpl::set(0xFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));
}

TEST_CASE("srs_x64_tr_ti")
{
    using namespace segment_register::tr;

    ti::enable();
    CHECK(ti::is_enabled());
    ti::disable();
    CHECK(ti::is_disabled());

    ti::enable(ti::mask);
    CHECK(ti::is_enabled(ti::mask));
    ti::disable(0x0);
    CHECK(ti::is_disabled(0x0));
}

TEST_CASE("srs_x64_tr_index")
{
    using namespace segment_register::tr;

    index::set(0xFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));
}
