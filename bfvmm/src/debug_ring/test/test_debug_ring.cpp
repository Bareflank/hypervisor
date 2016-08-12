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
#include <debug_ring/debug_ring.h>

#include <gsl/gsl>

debug_ring_resources_t *drr;

char rb[DEBUG_RING_SIZE];
char wb[DEBUG_RING_SIZE + 100];

bool out_of_memory = false;

void *
operator new(std::size_t size)
{
    if (out_of_memory)
        throw std::bad_alloc();
    else
        return malloc(size);
}

void
operator delete(void *ptr, std::size_t size) throw()
{
    (void) size;
    free(ptr);
}

void
operator delete(void *ptr) throw()
{
    operator delete(ptr, std::size_t(0));
}

void
init_wb(uint64_t num, char val = 'A')
{
    for (auto i = 0U; i < num; i++)
        gsl::at(wb, i) = val;

    gsl::at(wb, num) = 0;
}

void
debug_ring_ut::test_get_drr_invalid_drr()
{
    EXPECT_TRUE(get_drr(0, nullptr) == GET_DRR_FAILURE);
}

void
debug_ring_ut::test_get_drr_invalid_vcpuid()
{
    EXPECT_TRUE(get_drr(0x1000, &drr) == GET_DRR_FAILURE);
}

void
debug_ring_ut::test_constructor_out_of_memory()
{
    out_of_memory = true;
    debug_ring dr(0);
    out_of_memory = false;
}

void
debug_ring_ut::test_write_out_of_memory()
{
    out_of_memory = true;
    debug_ring dr(0);
    out_of_memory = false;
    EXPECT_NO_EXCEPTION(dr.write("hello"));
}

void
debug_ring_ut::test_read_with_invalid_drr()
{
    EXPECT_TRUE(debug_ring_read(nullptr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::test_read_with_null_string()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    EXPECT_TRUE(debug_ring_read(drr, nullptr, DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::test_read_with_zero_length()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), 0) == 0);
}

void
debug_ring_ut::test_write_with_zero_length()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto wb = "";

    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));
}

void
debug_ring_ut::test_write_string_to_dr_that_is_larger_than_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE);

    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));
}

void
debug_ring_ut::test_write_string_to_dr_that_is_much_larger_than_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE + 50);

    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));
}

void
debug_ring_ut::test_write_one_small_string_to_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto wb = "01234";

    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));
    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 5);
}

void
debug_ring_ut::test_fill_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 1);

    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));
    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == DEBUG_RING_SIZE);
    EXPECT_TRUE(rb[DEBUG_RING_SIZE - 1] == '\0');
}

void
debug_ring_ut::test_overcommit_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 10, 'A');
    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));

    init_wb(100, 'B');
    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));

    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 100);
    EXPECT_TRUE(rb[0] == 'B');
}

void
debug_ring_ut::test_overcommit_dr_more_than_once()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 150, 'A');
    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));

    init_wb(DEBUG_RING_SIZE - 150, 'B');
    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));

    init_wb(DEBUG_RING_SIZE - 150, 'C');
    EXPECT_NO_EXCEPTION(dr.write(static_cast<const char *>(wb)));

    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == DEBUG_RING_SIZE - 150);
    EXPECT_TRUE(rb[0] == 'C');
}

void
debug_ring_ut::test_read_with_empty_dr()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::acceptance_test_stress()
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto wb = "012";

    for (auto i = 0U; i < DEBUG_RING_SIZE; i++)
        dr.write(static_cast<const char *>(wb));

    // The total number of bytes that we read out, should be equal to
    // the total number of strings that can fit into the debug ring, minus
    // the '\0' for each string (as they are stripped).

    auto num = DEBUG_RING_SIZE / (strlen(static_cast<const char *>(wb)) + 1);
    auto total = num * strlen(static_cast<const char *>(wb));

    EXPECT_TRUE(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == total);
    EXPECT_TRUE(rb[0] == '0');
}
