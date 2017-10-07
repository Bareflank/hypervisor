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

TEST_CASE("test name goes here")
{
    CHECK(true);
}

// #include <bfgsl.h>

// #include <test.h>
// #include <memory_manager/pat_x64.h>
// #include <memory_manager/mem_attr_x64.h>

// void
// memory_manager_ut::test_pat_x64_mem_attr_to_pat_index()
// {
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_uc) == x64::pat::uncacheable_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_wc) == x64::pat::write_combining_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_wt) == x64::pat::write_through_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_wp) == x64::pat::write_protected_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_wb) == x64::pat::write_back_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::rw_uc_m) == x64::pat::uncacheable_minus_index);

//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_uc) == x64::pat::uncacheable_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_wc) == x64::pat::write_combining_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_wt) == x64::pat::write_through_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_wp) == x64::pat::write_protected_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_wb) == x64::pat::write_back_index);
//     this->expect_true(x64::pat::mem_attr_to_pat_index(x64::memory_attr::re_uc_m) == x64::pat::uncacheable_minus_index);

//     this->expect_exception([&] { x64::pat::mem_attr_to_pat_index(9); }, ""_ut_ree);
// }
