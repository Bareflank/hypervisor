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
// #include <intrinsics/x64.h>
// #include <memory_manager/mem_attr_x64.h>

// using namespace x64;

// void
// memory_manager_ut::test_mem_attr_x64_mem_type_to_attr()
// {
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::uncacheable) == memory_attr::rw_uc);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::write_combining) == memory_attr::rw_wc);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::write_through) == memory_attr::rw_wt);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::write_protected) == memory_attr::rw_wp);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::write_back) == memory_attr::rw_wb);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::rw, memory_type::uncacheable_minus) == memory_attr::rw_uc_m);

//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::uncacheable) == memory_attr::re_uc);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::write_combining) == memory_attr::re_wc);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::write_through) == memory_attr::re_wt);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::write_protected) == memory_attr::re_wp);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::write_back) == memory_attr::re_wb);
//     this->expect_true(memory_attr::mem_type_to_attr(memory_attr::re, memory_type::uncacheable_minus) == memory_attr::re_uc_m);

//     this->expect_exception([&] { memory_attr::mem_type_to_attr(0UL, memory_type::uncacheable); }, ""_ut_ree);
//     this->expect_exception([&] { memory_attr::mem_type_to_attr(memory_attr::rw, 9UL); }, ""_ut_ree);
// }
