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

#include <vector>

#include <test.h>
#include <memory.h>
#include <memory_manager/map_ptr_x64.h>
#include <memory_manager/memory_manager_x64.h>

#include <intrinsics/x64.h>
using namespace x64;

extern "C" int64_t
add_md(struct memory_descriptor *md) noexcept;

void
memory_manager_ut::test_memory_manager_x64_size_out_of_bounds()
{
    this->expect_true(g_mm->size(nullptr) == 0);
    this->expect_true(g_mm->size(make_ptr(0xFFFFFFFFFFFFFF00)) == 0);
    this->expect_true(g_mm->size_map(nullptr) == 0);
    this->expect_true(g_mm->size_map(make_ptr(0xFFFFFFFFFFFFFF00)) == 0);
}

void
memory_manager_ut::test_memory_manager_x64_malloc_out_of_memory()
{
    this->expect_true(g_mm->alloc(0) == nullptr);
    this->expect_true(g_mm->alloc_map(0) == nullptr);

    this->expect_true(g_mm->alloc(0xFFFFFFFFFFFFFF00) == nullptr);
    this->expect_true(g_mm->alloc_map(0xFFFFFFFFFFFFFF00) == nullptr);
}

void
memory_manager_ut::test_memory_manager_x64_malloc_heap()
{
    auto &&ptr = g_mm->alloc(cache_line_size);

    this->expect_true(ptr != nullptr);
    this->expect_true(g_mm->size(ptr) == cache_line_size);

    g_mm->free(ptr);
}

void
memory_manager_ut::test_memory_manager_x64_malloc_page()
{
    auto &&ptr = g_mm->alloc(page_size);

    this->expect_true(ptr != nullptr);
    this->expect_true(g_mm->size(ptr) == page_size);

    g_mm->free(ptr);
}

void
memory_manager_ut::test_memory_manager_x64_malloc_map()
{
    auto &&ptr = g_mm->alloc_map(page_size);

    this->expect_true(ptr != nullptr);
    this->expect_true(g_mm->size_map(ptr) == page_size);

    g_mm->free_map(ptr);
}

void
memory_manager_ut::test_memory_manager_x64_add_md()
{
    memory_descriptor md = {0, 0, 0};

    this->expect_true(add_md(nullptr) == MEMORY_MANAGER_FAILURE);
    this->expect_true(add_md(&md) == MEMORY_MANAGER_FAILURE);
}

void
memory_manager_ut::test_memory_manager_x64_add_md_invalid_type()
{
    memory_manager_x64::integer_pointer virt = 0x12345000;
    memory_manager_x64::integer_pointer phys = 0x54321000;
    memory_manager_x64::attr_type attr = 0;

    this->expect_exception([&] { g_mm->add_md(virt, phys, attr); }, ""_ut_ffe);
    this->expect_true(g_mm->descriptors().empty());
}

void
memory_manager_ut::test_memory_manager_x64_add_md_unaligned_physical()
{
    memory_manager_x64::integer_pointer virt = 0x12345000;
    memory_manager_x64::integer_pointer phys = 0x54321123;
    memory_manager_x64::attr_type attr = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E;

    this->expect_exception([&] { g_mm->add_md(virt, phys, attr); }, ""_ut_ffe);
    this->expect_true(g_mm->descriptors().empty());
}

void
memory_manager_ut::test_memory_manager_x64_add_md_unaligned_virtual()
{
    memory_manager_x64::integer_pointer virt = 0x12345123;
    memory_manager_x64::integer_pointer phys = 0x54321000;
    memory_manager_x64::attr_type attr = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E;

    this->expect_exception([&] { g_mm->add_md(virt, phys, attr); }, ""_ut_ffe);
    this->expect_true(g_mm->descriptors().empty());
}

void
memory_manager_ut::test_memory_manager_x64_remove_md_invalid_virt()
{
    memory_manager_x64::integer_pointer virt = 0x12345000;
    memory_manager_x64::integer_pointer phys = 0x54321000;
    memory_manager_x64::attr_type attr = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E;

    this->expect_no_exception([&] { g_mm->add_md(virt, phys, attr); });
    this->expect_false(g_mm->descriptors().empty());

    this->expect_no_exception([&] { g_mm->remove_md(0); });
    this->expect_no_exception([&] { g_mm->remove_md(virt + 0x10); });
    this->expect_no_exception([&] { g_mm->remove_md(virt); });
    this->expect_true(g_mm->descriptors().empty());
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_physint_failure()
{
    this->expect_exception([&] { g_mm->virtint_to_physint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtint_to_physint(0x54321000); }, ""_ut_ore);
}

void
memory_manager_ut::test_memory_manager_x64_physint_to_virtint_failure()
{
    this->expect_exception([&] { g_mm->physint_to_virtint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->physint_to_virtint(0x12346000); }, ""_ut_ore);
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_attrint_failure()
{
    this->expect_exception([&] { g_mm->virtint_to_attrint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtint_to_attrint(0x54321000); }, ""_ut_ore);
}

template<class F> auto test_with_md(F f)
{
    auto &&ret = false;
    memory_manager_x64::integer_pointer virt = 0x12345000;
    memory_manager_x64::integer_pointer phys = 0x54321000;
    memory_manager_x64::attr_type attr = MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E;

    {
        g_mm->add_md(virt, phys, attr);

        auto ___ = gsl::finally([&]
        { g_mm->remove_md(virt); });

        ret = f();
    }

    return ret && g_mm->descriptors().empty();
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_physint_random_address()
{
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_physint(0x12345ABC) == 0x54321ABC; }));
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_physint(0x12345FFF) == 0x54321FFF; }));
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_physint(0x12345000) == 0x54321000; }));
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_physint_nullptr()
{
    this->expect_exception([&] { g_mm->virtint_to_physint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtptr_to_physint(nullptr); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtint_to_physptr(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtptr_to_physptr(nullptr); }, ""_ut_ffe);
}

void
memory_manager_ut::test_memory_manager_x64_physint_to_virtint_random_address()
{
    this->expect_true(test_with_md([&] { return g_mm->physint_to_virtint(0x54321ABC) == 0x12345ABC; }));
    this->expect_true(test_with_md([&] { return g_mm->physint_to_virtint(0x54321FFF) == 0x12345FFF; }));
    this->expect_true(test_with_md([&] { return g_mm->physint_to_virtint(0x54321000) == 0x12345000; }));
}

void
memory_manager_ut::test_memory_manager_x64_physint_to_virtint_nullptr()
{
    this->expect_exception([&] { g_mm->physint_to_virtint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->physptr_to_virtint(nullptr); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->physint_to_virtptr(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->physptr_to_virtptr(nullptr); }, ""_ut_ffe);
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_attrint_random_address()
{
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_attrint(0x12345ABC) == (MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E); }));
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_attrint(0x12345FFF) == (MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E); }));
    this->expect_true(test_with_md([&] { return g_mm->virtint_to_attrint(0x12345000) == (MEMORY_TYPE_R | MEMORY_TYPE_W | MEMORY_TYPE_E); }));
}

void
memory_manager_ut::test_memory_manager_x64_virtint_to_attrint_nullptr()
{
    this->expect_exception([&] { g_mm->virtint_to_attrint(0); }, ""_ut_ffe);
    this->expect_exception([&] { g_mm->virtptr_to_attrint(nullptr); }, ""_ut_ffe);
}
