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

TEST_CASE("mem_type_to_attr")
{
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::uncacheable) == ::x64::memory_attr::rw_uc);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::write_combining) == ::x64::memory_attr::rw_wc);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::write_through) == ::x64::memory_attr::rw_wt);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::write_protected) == ::x64::memory_attr::rw_wp);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::write_back) == ::x64::memory_attr::rw_wb);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, memory_type::uncacheable_minus) == ::x64::memory_attr::rw_uc_m);

    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::uncacheable) == ::x64::memory_attr::re_uc);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::write_combining) == ::x64::memory_attr::re_wc);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::write_through) == ::x64::memory_attr::re_wt);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::write_protected) == ::x64::memory_attr::re_wp);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::write_back) == ::x64::memory_attr::re_wb);
    CHECK(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::re, memory_type::uncacheable_minus) == ::x64::memory_attr::re_uc_m);

    CHECK_THROWS(::x64::memory_attr::mem_type_to_attr(0UL, ::x64::memory_type::uncacheable));
    CHECK_THROWS(::x64::memory_attr::mem_type_to_attr(::x64::memory_attr::rw, 9UL));
}

TEST_CASE("mem_attr_to_pat_index")
{
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_uc) == ::x64::pat::uncacheable_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_wc) == ::x64::pat::write_combining_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_wt) == ::x64::pat::write_through_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_wp) == ::x64::pat::write_protected_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_wb) == ::x64::pat::write_back_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::rw_uc_m) == ::x64::pat::uncacheable_minus_index);

    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_uc) == ::x64::pat::uncacheable_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_wc) == ::x64::pat::write_combining_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_wt) == ::x64::pat::write_through_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_wp) == ::x64::pat::write_protected_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_wb) == ::x64::pat::write_back_index);
    CHECK(::x64::pat::mem_attr_to_pat_index(::x64::memory_attr::re_uc_m) == ::x64::pat::uncacheable_minus_index);

    CHECK_THROWS(::x64::pat::mem_attr_to_pat_index(9));
}

TEST_CASE("page_table::index")
{
    CHECK(::x64::page_table::index(0x1ULL, 0x0ULL) == 0x1ULL);
}
