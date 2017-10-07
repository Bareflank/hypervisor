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

// #define TESTING_MEM_POOL

// #include <bfgsl.h>

// #include <vector>

// #include <test.h>
// #include <memory_manager/mem_pool.h>

// void
// memory_manager_ut::test_mem_pool_free_zero()
// {
//     mem_pool<128, 3> pool{100};

//     pool.free(0);
//     pool.free(0xFFFFFFFFFFFFFFFF);
// }

// void
// memory_manager_ut::test_mem_pool_free_heap_twice()
// {
//     mem_pool<128, 3> pool{100};

//     auto &&addr1 = pool.alloc(1 << 3);
//     pool.free(addr1);
//     pool.free(addr1);
// }

// void
// memory_manager_ut::test_mem_pool_invalid_pool()
// {
//     using pool_type = mem_pool<128, 3>;
//     this->expect_exception([&] { pool_type pool{0}; }, ""_ut_lee);
//     this->expect_exception([&] { pool_type pool{0xFFFFFFFFFFFFFFF0}; }, ""_ut_lee);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_zero()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_exception([&] { pool.alloc(0); }, ""_ut_ffe);
// }

// void
// memory_manager_ut::test_mem_pool_multiple_malloc_heap_should_be_contiguous()
// {
//     mem_pool<128, 3> pool{100};
//     mem_pool<128, 3>::integer_pointer addr1 = 0;
//     mem_pool<128, 3>::integer_pointer addr2 = 0;
//     mem_pool<128, 3>::integer_pointer addr3 = 0;
//     mem_pool<128, 3>::integer_pointer addr4 = 0;

//     addr1 = pool.alloc((1 << 3));
//     addr2 = pool.alloc((1 << 3));
//     addr3 = pool.alloc((1 << 3));
//     addr4 = pool.alloc((1 << 3));

//     this->expect_true(addr1 == 100 + ((1 << 3) * 0));  // 100
//     this->expect_true(addr2 == 100 + ((1 << 3) * 1));  // 108
//     this->expect_true(addr3 == 100 + ((1 << 3) * 2));  // 116
//     this->expect_true(addr4 == 100 + ((1 << 3) * 3));  // 124

//     pool.free(addr1);
//     pool.free(addr2);
//     pool.free(addr3);
//     pool.free(addr4);

//     addr1 = pool.alloc((1 << 3) + 2);
//     addr2 = pool.alloc((1 << 3) + 2);
//     addr3 = pool.alloc((1 << 3) + 2);
//     addr4 = pool.alloc((1 << 3) * 4);

//     this->expect_true(addr1 == 132 + ((1 << 3) * 0));  // 132
//     this->expect_true(addr2 == 132 + ((1 << 3) * 2));  // 148
//     this->expect_true(addr3 == 132 + ((1 << 3) * 4));  // 164
//     this->expect_true(addr4 == 132 + ((1 << 3) * 6));  // 180

//     pool.free(addr1);
//     pool.free(addr2);
//     pool.free(addr3);
//     pool.free(addr4);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_all_of_memory()
// {
//     mem_pool<128, 3> pool{100};
//     std::vector<mem_pool<128, 3>::integer_pointer> addrs;

//     for (auto i = 0; i < 16; i++)
//         addrs.push_back(pool.alloc(1 << 3));

//     this->expect_exception([&] { pool.alloc(1 << 3); }, ""_ut_bae);

//     for (const auto &addr : addrs)
//         pool.free(addr);

//     for (auto i = 0; i < 16; i++)
//         addrs.push_back(pool.alloc(1 << 3));

//     this->expect_exception([&] { pool.alloc(1 << 3); }, ""_ut_bae);

//     for (const auto &addr : addrs)
//         pool.free(addr);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_all_of_memory_one_block()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_true(pool.alloc(128) == 100);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_all_memory_fragmented()
// {
//     mem_pool<128, 3> pool{100};
//     std::vector<mem_pool<128, 3>::integer_pointer> addrs;

//     for (auto i = 0; i < 16; i++)
//         addrs.push_back(pool.alloc(1 << 3));

//     for (const auto &addr : addrs)
//         pool.free(addr);

//     this->expect_true(pool.alloc(128) == 100);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_too_much_memory_one_block()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_exception([&] { pool.alloc(136); }, ""_ut_ffe);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_too_much_memory_non_block_size()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_exception([&] { pool.alloc(129); }, ""_ut_ffe);
// }

// void
// memory_manager_ut::test_mem_pool_malloc_heap_massive()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_exception([&] { pool.alloc(0xFFFFFFFFFFFFFFFF); }, ""_ut_ffe);
// }

// void
// memory_manager_ut::test_mem_pool_size_out_of_bounds()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_true(pool.size(0) == 0);
// }

// void
// memory_manager_ut::test_mem_pool_size_unallocated()
// {
//     mem_pool<128, 3> pool{100};
//     this->expect_true(pool.size(100) == 0);
// }

// void
// memory_manager_ut::test_mem_pool_size()
// {
//     mem_pool<128, 3> pool{100};

//     pool.alloc(8);
//     this->expect_true(pool.size(100) == 8);
// }

// void
// memory_manager_ut::test_mem_pool_contains_out_of_bounds()
// {
//     mem_pool<128, 3> pool{100};

//     this->expect_false(pool.contains(0));
//     this->expect_false(pool.contains(99));
//     this->expect_false(pool.contains(228));
//     this->expect_false(pool.contains(500));
// }

// void
// memory_manager_ut::test_mem_pool_contains()
// {
//     mem_pool<128, 3> pool{100};

//     this->expect_true(pool.contains(100));
//     this->expect_true(pool.contains(227));
// }
