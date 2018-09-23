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

#include <test/support.h>
#include <memory_manager/arch/x64/unique_map.h>

namespace bfvmm::x64
{
gsl::not_null<cr3::mmap *> mmap()
{
    bfignored(g_mm);

    static auto g_mmap = std::make_unique<cr3::mmap>();
    return g_mmap.get();
}
}

TEST_CASE("default constructor")
{
    CHECK_NOTHROW(bfvmm::x64::unique_map_ptr<int>());
    CHECK_NOTHROW(bfvmm::x64::unique_map_ptr<int>(nullptr));
}

TEST_CASE("map singel page: invalid args")
{
    CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(0, 0x54321000));
    CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(0x12345000, 0));
    CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(0x12345123, 0x54321000));
    CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(0x12345000, 0x54321123));
}

TEST_CASE("map single page: success")
{
    CHECK_NOTHROW(bfvmm::x64::unique_map_ptr<int>(0x12345000, 0x54321000));
}

// TEST_CASE("map cr3 page: success")
// {
//     auto cr3 = std::make_unique<bfvmm::x64::cr3::mmap>();
//     cr3->map_4k(0x12345000, 0x54321000);

//         integer_pointer vmap, integer_pointer virt, integer_pointer cr3, size_type size

//     CHECK_NOTHROW(bfvmm::x64::unique_map_ptr<int>(0x1000, 0x12345000, bfn::upper(cr3->cr3(), 0x1000)));
// }

// void
// memory_manager_ut::test_unique_map_ptr_phys_constructor_mm_map_fails()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     auto &&pt = setup_pt(mocks);

//     mocks.OnCall(pt, root_page_table_x64::map_4k).Throw(std::runtime_error("error"));

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write));
//     });
// }






























// #include <test.h>
// #include <memory_manager/map_ptr_x64.h>
// #include <memory_manager/memory_manager_x64.h>

// #include <map>
// #include <exception>

// #include <intrinsics/x64.h>

// constexpr const auto valid_virt = 0x0000111100000000UL;
// constexpr const auto valid_phys = 0x0000222200000000UL;
// constexpr const auto invalid_virt = 0x0U;
// constexpr const auto invalid_phys = 0x0U;
// constexpr const auto phys_offset = 0x10U;
// constexpr const auto valid_map = valid_virt + phys_offset;

// std::map<const void *, bool> g_freed;
// std::map<const void *, bool> g_flushed;
// std::map<const void *, bool> g_cache_flushed;
// std::map<memory_manager_x64::integer_pointer, memory_manager_x64::integer_pointer> g_mapped;
// std::map<memory_manager_x64::integer_pointer, bool> g_unmapped;

// x64::memory_attr::attr_type read_write = x64::memory_attr::rw_wb;

// extern "C" void
// __invlpg(const void *virt) noexcept
// { g_flushed[virt] = true; }

// extern "C" void
// __clflush(void *addr) noexcept
// { g_cache_flushed[addr] = true; }

// auto g_pte_valid_present = true;
// auto g_pte_valid_phys_addr = true;
// auto g_pte_large_page = false;
// auto g_pte_large_page_count = 0;
// auto g_pte_large_page_reset = 0;

// static auto dummy_pt = std::make_unique<memory_manager_x64::integer_pointer[]>(x64::page_table::num_entries);
// static auto dummy_pt_span = gsl::make_span(dummy_pt, x64::page_table::num_entries);

// static memory_manager_x64::pointer
// mm_alloc_map(memory_manager_x64::size_type size) noexcept
// {
//     (void) size;

//     g_pte_large_page_count--;

//     for (auto &element : dummy_pt_span)
//     {
//         element = 0;

//         auto pte = page_table_entry_x64{&element};
//         if (g_pte_valid_present) pte.set_present(true);
//         if (g_pte_valid_phys_addr) pte.set_phys_addr(valid_phys);
//         if (g_pte_large_page)
//         {
//             if (g_pte_large_page_count == 0)
//                 pte.set_ps(true);
//         }
//     }

//     if (g_pte_large_page_count == 0)
//         g_pte_large_page_count = g_pte_large_page_reset;

//     return reinterpret_cast<memory_manager_x64::pointer>(dummy_pt.get());
// }

// static void
// mm_free_map(memory_manager_x64::pointer ptr) noexcept
// { g_freed[ptr] = true; }

// static void
// pt_map(memory_manager_x64::integer_pointer virt,
//        memory_manager_x64::integer_pointer phys,
//        memory_manager_x64::attr_type attr)
// {
//     (void) attr;
//     g_mapped[virt] = phys;
// }

// static void
// pt_unmap(memory_manager_x64::integer_pointer virt)
// {
//     (void) virt;
//     g_unmapped[virt] = true;
// }

// static auto
// setup_mm(MockRepository &mocks)
// {
//     auto mm = mocks.Mock<memory_manager_x64>();
//     mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

//     mocks.OnCall(mm, memory_manager_x64::alloc_map).Do(mm_alloc_map);
//     mocks.OnCall(mm, memory_manager_x64::free_map).Do(mm_free_map);

//     g_freed.clear();

//     return mm;
// }

// static auto
// setup_pt(MockRepository &mocks)
// {
//     auto pt = mocks.Mock<root_page_table_x64>();
//     mocks.OnCallFunc(root_pt).Return(pt);

//     mocks.OnCall(pt, root_page_table_x64::map_4k).Do(pt_map);
//     mocks.OnCall(pt, root_page_table_x64::unmap).Do(pt_unmap);

//     g_flushed.clear();
//     g_mapped.clear();
//     g_unmapped.clear();

//     return pt;
// }


// void
// memory_manager_ut::test_unique_map_ptr_phys_constructor_success()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_virt));
//         CHECK(map.size() == x64::page_size);
//         CHECK(g_flushed[make_ptr(valid_virt)]);
//         CHECK(g_mapped[valid_virt] == valid_phys);

//         map.reset();

//         CHECK(g_unmapped[valid_virt]);
//         CHECK(g_freed[make_ptr(valid_virt)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_phys_range_constructor_invalid_args()
// TEST_CASE("alloc null")
// {
//     auto &&phys_range_1 = std::make_pair(0x1111000000000010UL, x64::page_size * 2UL);
//     auto &&phys_range_2 = std::make_pair(0x1111000000004000UL, x64::page_size * 2UL);
//     auto &&phys_range_3 = std::make_pair(0x1111000000008000UL, x64::page_size * 2UL);
//     auto &&list = {phys_range_1, phys_range_2, phys_range_3};

//     auto &&invalid_phys_range_1 = std::make_pair(0UL, x64::page_size * 2UL);
//     auto &&invalid_phys_range_2 = std::make_pair(0x1111000000000010UL, 0UL);
//     auto &&invalid_phys_range_3 = std::make_pair(0x1111000000000010UL, 2UL);
//     auto &&invalid_list1 = {phys_range_1, invalid_phys_range_1, phys_range_3};
//     auto &&invalid_list2 = {phys_range_1, invalid_phys_range_2, phys_range_3};
//     auto &&invalid_list3 = {phys_range_1, invalid_phys_range_3, phys_range_3};

//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(invalid_virt, list, read_write));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt + 0x10U, list, read_write));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, {}, read_write));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, invalid_list1, read_write));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, invalid_list2, read_write));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, invalid_list3, read_write));
// }

// void
// memory_manager_ut::test_unique_map_ptr_phys_range_constructor_mm_map_fails()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     auto &&pt = setup_pt(mocks);

//     mocks.OnCall(pt, root_page_table_x64::map_4k).Throw(std::runtime_error("error"));

//     auto &&phys_range_1 = std::make_pair(0x1111000000000010UL, x64::page_size * 2UL);
//     auto &&phys_range_2 = std::make_pair(0x1111000000004000UL, x64::page_size * 2UL);
//     auto &&phys_range_3 = std::make_pair(0x1111000000008000UL, x64::page_size * 2UL);
//     auto &&list = {phys_range_1, phys_range_2, phys_range_3};

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, list, read_write));
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_phys_range_constructor_success()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&phys_range_1 = std::make_pair(0x1111000000000010UL, x64::page_size * 2UL);
//     auto &&phys_range_2 = std::make_pair(0x1111000000004000UL, x64::page_size * 2UL);
//     auto &&phys_range_3 = std::make_pair(0x1111000000008000UL, x64::page_size * 2UL);
//     auto &&list = {phys_range_1, phys_range_2, phys_range_3};

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);
//     auto &&virt4 = valid_virt + (3 * x64::page_size);
//     auto &&virt5 = valid_virt + (4 * x64::page_size);
//     auto &&virt6 = valid_virt + (5 * x64::page_size);

//     auto &&phys1 = 0x1111000000000000UL;
//     auto &&phys2 = 0x1111000000001000UL;
//     auto &&phys3 = 0x1111000000004000UL;
//     auto &&phys4 = 0x1111000000005000UL;
//     auto &&phys5 = 0x1111000000008000UL;
//     auto &&phys6 = 0x1111000000009000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, list, read_write);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_map));
//         CHECK(map.size() == x64::page_size * 6UL);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);
//         CHECK(g_flushed[make_ptr(virt3)]);
//         CHECK(g_flushed[make_ptr(virt4)]);
//         CHECK(g_flushed[make_ptr(virt5)]);
//         CHECK(g_flushed[make_ptr(virt6)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);
//         CHECK(g_mapped[virt3] == phys3);
//         CHECK(g_mapped[virt4] == phys4);
//         CHECK(g_mapped[virt5] == phys5);
//         CHECK(g_mapped[virt6] == phys6);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);
//         CHECK(g_unmapped[virt3]);
//         CHECK(g_unmapped[virt4]);
//         CHECK(g_unmapped[virt5]);
//         CHECK(g_unmapped[virt6]);

//         CHECK(g_freed[make_ptr(valid_virt)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_invalid_args()
// TEST_CASE("alloc null")
// {
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(invalid_virt, valid_virt, valid_phys, x64::page_size, 0x0));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt + 0x10U, valid_virt, valid_phys, x64::page_size, 0x0));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, invalid_virt, valid_phys, x64::page_size, 0x0));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt, invalid_phys, x64::page_size, 0x0));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt, valid_phys + 0x10U, x64::page_size, 0x0));
//     CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt, valid_phys, 0, 0x0));
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_mm_map_fails()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     auto &&pt = setup_pt(mocks);

//     mocks.OnCall(pt, root_page_table_x64::map_4k).Throw(std::runtime_error("error"));

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt, valid_phys, x64::page_size,);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_success_1g()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);

//     auto &&phys1 = 0x0000222200000000UL;
//     auto &&phys2 = 0x0000222200001000UL;

//     g_pte_large_page = true;
//     g_pte_large_page_count = 2;
//     g_pte_large_page_reset = 2;
//     auto ___ = gsl::finally([&] { g_pte_large_page = false; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt + phys_offset, valid_phys, x64::page_size * 2UL, 0x0);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_map));
//         CHECK(map.size() == x64::page_size * 2UL);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);

//         CHECK(g_freed[make_ptr(virt1)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_success_2m()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);

//     auto &&phys1 = 0x0000222200000000UL;
//     auto &&phys2 = 0x0000222200001000UL;

//     g_pte_large_page = true;
//     g_pte_large_page_count = 3;
//     g_pte_large_page_reset = 3;
//     auto ___ = gsl::finally([&] { g_pte_large_page = false; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt + phys_offset, valid_phys, x64::page_size * 2UL, 0x0);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_map));
//         CHECK(map.size() == x64::page_size * 2UL);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);

//         CHECK(g_freed[make_ptr(virt1)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_success_4k()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);

//     auto &&phys1 = 0x0000222200000000UL;
//     auto &&phys2 = 0x0000222200000000UL;
//     auto &&phys3 = 0x0000222200000000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt + phys_offset, valid_phys, x64::page_size * 2UL, 0x0);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_map));
//         CHECK(map.size() == x64::page_size * 2UL);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);
//         CHECK(g_flushed[make_ptr(virt3)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);
//         CHECK(g_mapped[virt3] == phys3);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);
//         CHECK(g_unmapped[virt3]);

//         CHECK(g_freed[make_ptr(virt1)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_success_4k_aligned_addr()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);

//     auto &&phys1 = 0x0000222200000000UL;
//     auto &&phys2 = 0x0000222200000000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt, valid_phys, x64::page_size * 2UL, 0x0);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_virt));
//         CHECK(map.size() == x64::page_size * 2UL);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);
//         this->expect_false(g_flushed[make_ptr(virt3)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);
//         CHECK(g_mapped[virt3] == 0);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);
//         this->expect_false(g_unmapped[virt3]);

//         CHECK(g_freed[make_ptr(virt1)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_success_4k_aligned_size()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);

//     auto &&phys1 = 0x0000222200000000UL;
//     auto &&phys2 = 0x0000222200000000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_virt + phys_offset, valid_phys, x64::page_size * 2UL - phys_offset, 0x0);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_map));
//         CHECK(map.size() == x64::page_size * 2UL - phys_offset);

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);
//         this->expect_false(g_flushed[make_ptr(virt3)]);

//         CHECK(g_mapped[virt1] == phys1);
//         CHECK(g_mapped[virt2] == phys2);
//         CHECK(g_mapped[virt3] == 0);

//         map.reset();

//         CHECK(g_unmapped[virt1]);
//         CHECK(g_unmapped[virt2]);
//         this->expect_false(g_unmapped[virt3]);

//         CHECK(g_freed[make_ptr(virt1)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_not_present()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     g_pte_valid_present = false;
//     auto ___ = gsl::finally([&] { g_pte_valid_present = true; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_map, valid_phys, x64::page_size,);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_virt_cr3_constructor_invalid_phys_addr()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     g_pte_valid_phys_addr = false;
//     auto ___ = gsl::finally([&] { g_pte_valid_phys_addr = true; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         CHECK_THROWS(bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_map, valid_phys, x64::page_size,);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_copy_constructor()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map1 = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);
//         auto &&map2 = bfvmm::x64::unique_map_ptr<int>(std::move(map1));

//         this->expect_false(map1);
//         CHECK(map2);
//         CHECK(map1.get() == nullptr);
//         CHECK(map2.get() == make_ptr(valid_virt));
//         CHECK(map1.size() == 0);
//         CHECK(map2.size() == x64::page_size);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_move_operator_valid()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map1 = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);
//         auto map2 = std::move(map1);

//         this->expect_false(map1);
//         CHECK(map2);
//         CHECK(map1.get() == nullptr);
//         CHECK(map2.get() == make_ptr(valid_virt));
//         CHECK(map1.size() == 0);
//         CHECK(map2.size() == x64::page_size);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_move_operator_invalid()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);
//         map = nullptr;

//         this->expect_false(map);
//         CHECK(map.get() == nullptr);
//         CHECK(map.size() == 0);
//     });
// }

// struct foo_t
// { int test; };

// void
// memory_manager_ut::test_unique_map_ptr_reference_operators()
// TEST_CASE("alloc null")
// {
//     // MockRepository mocks;
//     // setup_mm(mocks);
//     // setup_pt(mocks);

//     // foo_t foo{10};

//     // auto &&lower = make_uintptr(&foo) & (x64::page_size - 1);
//     // auto &&upper = make_uintptr(&foo) & ~(x64::page_size - 1);

//     // RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     // {
//     //     auto &&map = bfvmm::x64::unique_map_ptr<foo_t>(upper, valid_phys + lower, read_write);
//     //     auto &&foo2 = *map;

//     //     CHECK(map);
//     //     CHECK(map.get() == &foo);
//     //     CHECK((*map).test == 10);
//     //     CHECK(map->test == 10);
//     //     CHECK(foo2.test == 10);
//     // });
// }

// void
// memory_manager_ut::test_unique_map_ptr_release()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);
//         auto &&ret = map.release();

//         this->expect_false(map);
//         CHECK(map.get() == nullptr);
//         CHECK(map.size() == 0);
//         CHECK(std::get<0>(ret) == make_ptr(valid_virt));
//         CHECK(std::get<1>(ret) == x64::page_size);
//         CHECK(std::get<2>(ret) == x64::page_size);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_reset()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, valid_phys, read_write);
//         map.reset(make_ptr<int>(valid_virt), x64::page_size, x64::page_size);

//         CHECK(g_unmapped[valid_virt]);
//         CHECK(g_freed[make_ptr(valid_virt)]);

//         CHECK(map);
//         CHECK(map.get() == make_ptr(valid_virt));
//         CHECK(map.size() == x64::page_size);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_swap()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);

//     auto &&phys1 = 0x1111000000000000UL;
//     auto &&phys2 = 0x1111000000001000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map1 = bfvmm::x64::unique_map_ptr<int>(virt1, phys1, read_write);
//         auto &&map2 = bfvmm::x64::unique_map_ptr<int>(virt2, phys2, read_write);

//         map1.swap(map2);
//         CHECK(map1.get() == make_ptr(virt2));
//         CHECK(map2.get() == make_ptr(virt1));

//         bfvmm::x64::swap(map1, map2);
//         CHECK(map1.get() == make_ptr(virt1));
//         CHECK(map2.get() == make_ptr(virt2));
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_flush()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&phys_range_1 = std::make_pair(0x1111000000000010UL, x64::page_size * 2UL);
//     auto &&phys_range_2 = std::make_pair(0x1111000000004000UL, x64::page_size * 2UL);
//     auto &&phys_range_3 = std::make_pair(0x1111000000008000UL, x64::page_size * 2UL);
//     auto &&list = {phys_range_1, phys_range_2, phys_range_3};

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);
//     auto &&virt4 = valid_virt + (3 * x64::page_size);
//     auto &&virt5 = valid_virt + (4 * x64::page_size);
//     auto &&virt6 = valid_virt + (5 * x64::page_size);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, list, read_write);

//         g_flushed.clear();
//         map.flush();

//         CHECK(g_flushed[make_ptr(virt1)]);
//         CHECK(g_flushed[make_ptr(virt2)]);
//         CHECK(g_flushed[make_ptr(virt3)]);
//         CHECK(g_flushed[make_ptr(virt4)]);
//         CHECK(g_flushed[make_ptr(virt5)]);
//         CHECK(g_flushed[make_ptr(virt6)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_cache_flush()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&phys_range_1 = std::make_pair(0x1111000000000010UL, x64::page_size * 2UL);
//     auto &&phys_range_2 = std::make_pair(0x1111000000004000UL, x64::page_size * 2UL);
//     auto &&phys_range_3 = std::make_pair(0x1111000000008000UL, x64::page_size * 2UL);
//     auto &&list = {phys_range_1, phys_range_2, phys_range_3};

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);
//     auto &&virt3 = valid_virt + (2 * x64::page_size);
//     auto &&virt4 = valid_virt + (3 * x64::page_size);
//     auto &&virt5 = valid_virt + (4 * x64::page_size);
//     auto &&virt6 = valid_virt + (5 * x64::page_size);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map = bfvmm::x64::unique_map_ptr<int>(valid_virt, list, read_write);

//         g_cache_flushed.clear();
//         map.cache_flush();

//         CHECK(g_cache_flushed[make_ptr(virt1)]);
//         CHECK(g_cache_flushed[make_ptr(virt2)]);
//         CHECK(g_cache_flushed[make_ptr(virt3)]);
//         CHECK(g_cache_flushed[make_ptr(virt4)]);
//         CHECK(g_cache_flushed[make_ptr(virt5)]);
//         CHECK(g_cache_flushed[make_ptr(virt6)]);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_comparison()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     auto &&virt1 = valid_virt + (0 * x64::page_size);
//     auto &&virt2 = valid_virt + (1 * x64::page_size);

//     auto &&phys1 = 0x1111000000000000UL;
//     auto &&phys2 = 0x1111000000001000UL;

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&map1 = bfvmm::x64::unique_map_ptr<int>(virt1, phys1, read_write);
//         auto &&map2 = bfvmm::x64::unique_map_ptr<int>(virt1, phys1, read_write);
//         auto &&map3 = bfvmm::x64::unique_map_ptr<int>(virt2, phys2, read_write);
//         auto &&map4 = bfvmm::x64::unique_map_ptr<int>(virt2, phys2, read_write);

//         CHECK(map1 == map2);
//         CHECK(map3 == map4);
//         CHECK(map1 != map4);
//         CHECK(map3 != map2);
//         CHECK(map1 <  map3);
//         CHECK(map3 >  map1);
//         CHECK(map1 <= map2);
//         CHECK(map1 <= map3);
//         CHECK(map2 >= map1);
//         CHECK(map3 >= map1);
//         this->expect_false(map1 == nullptr);
//         CHECK(map1 != nullptr);
//         this->expect_false(nullptr == map1);
//         CHECK(nullptr != map1);
//     });
// }

// void
// memory_manager_ut::test_unique_map_ptr_make_failure()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         g_freed.clear();
//         CHECK_THROWS(bfvmm::x64::make_unique_map_x64<int>(nul);
//         CHECK(g_freed[dummy_pt.get()]);

//         g_freed.clear();
//         CHECK_THROWS(bfvmm::x64::make_unique_map_x64<int>);
//         CHECK(g_freed[dummy_pt.get()]);

//         g_freed.clear();
//         CHECK_THROWS(bfvmm::x64::make_unique_map_x64<int>({std::make_pair(0UL, 0);
//         CHECK(g_freed[dummy_pt.get()]);

//         g_freed.clear();
//         CHECK_THROWS(bfvmm::x64::make_unique_map_x64<int>(0UL, 0UL, 0UL,);
//         CHECK(g_freed[dummy_pt.get()]);
//     });
// }

// void
// memory_manager_ut::test_virt_to_phys_with_cr3_invalid()
// TEST_CASE("alloc null")
// {
//     CHECK_THROWS(bfvmm::x64::virt_to_phys_with_cr3(invalid_virt, valid_phys));
//     CHECK_THROWS(bfvmm::x64::virt_to_phys_with_cr3(valid_virt, invalid_phys));
//     CHECK_THROWS(bfvmm::x64::virt_to_phys_with_cr3(valid_virt, valid_phys + phys_offset));
// }

// void
// memory_manager_ut::test_virt_to_phys_with_cr3_1g()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     g_pte_large_page = true;
//     g_pte_large_page_count = 2;
//     g_pte_large_page_reset = 2;
//     auto ___ = gsl::finally([&] { g_pte_large_page = false; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&phys = bfvmm::x64::virt_to_phys_with_cr3(valid_virt, valid_phys);
//         CHECK(phys == valid_phys);
//     });
// }

// void
// memory_manager_ut::test_virt_to_phys_with_cr3_2m()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     g_pte_large_page = true;
//     g_pte_large_page_count = 3;
//     g_pte_large_page_reset = 3;
//     auto ___ = gsl::finally([&] { g_pte_large_page = false; });

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&phys = bfvmm::x64::virt_to_phys_with_cr3(valid_virt, valid_phys);
//         CHECK(phys == valid_phys);
//     });
// }

// void
// memory_manager_ut::test_virt_to_phys_with_cr3_4k()
// TEST_CASE("alloc null")
// {
//     MockRepository mocks;
//     setup_mm(mocks);
//     setup_pt(mocks);

//     RUN_UNITTEST_WITH_MOCKS(mocks, [&]
//     {
//         auto &&phys = bfvmm::x64::virt_to_phys_with_cr3(valid_virt, valid_phys);
//         CHECK(phys == valid_phys);
//     });
// }
