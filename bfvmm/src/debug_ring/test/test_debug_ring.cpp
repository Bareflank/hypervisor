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

debug_ring_resources_t *drr;

char rb[DEBUG_RING_SIZE];
char wb[DEBUG_RING_SIZE + 100];

void
init_wb(uint64_t num, char val = 'A')
{
    for (auto i = 0U; i < num; i++)
        wb[i] = val;

    wb[num] = 0;
}

void
debug_ring_ut::test_write_with_invalid_dr()
{
    debug_ring dr(10000);

    auto wb = "01234";

    EXPECT_EXCEPTION(dr.write(wb), bfn::invalid_debug_ring_error);
}

void
debug_ring_ut::test_read_with_invalid_drr()
{
    EXPECT_TRUE(debug_ring_read(NULL, rb, DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::test_read_with_null_string()
{
    debug_ring dr(0);
    drr = get_drr(0);

    EXPECT_TRUE(debug_ring_read(drr, NULL, DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::test_read_with_zero_length()
{
    debug_ring dr(0);
    drr = get_drr(0);

    EXPECT_TRUE(debug_ring_read(drr, rb, 0) == 0);
}

void
debug_ring_ut::test_write_with_zero_length()
{
    debug_ring dr(0);
    drr = get_drr(0);

    auto wb = "";

    EXPECT_NO_EXCEPTION(dr.write(wb));
}

void
debug_ring_ut::test_write_string_to_dr_that_is_larger_than_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    init_wb(DEBUG_RING_SIZE);

    EXPECT_EXCEPTION(dr.write(wb), bfn::range_error);
}

void
debug_ring_ut::test_write_string_to_dr_that_is_much_larger_than_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    init_wb(DEBUG_RING_SIZE + 50);

    EXPECT_EXCEPTION(dr.write(wb), bfn::range_error);
}

void
debug_ring_ut::test_write_one_small_string_to_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    auto wb = "01234";

    EXPECT_NO_EXCEPTION(dr.write(wb));
    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 5);
}

void
debug_ring_ut::test_fill_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    init_wb(DEBUG_RING_SIZE - 1);

    EXPECT_NO_EXCEPTION(dr.write(wb));
    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == DEBUG_RING_SIZE);
    EXPECT_TRUE(rb[DEBUG_RING_SIZE - 1] == '\0');
}

void
debug_ring_ut::test_overcommit_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    init_wb(DEBUG_RING_SIZE - 10, 'A');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    init_wb(100, 'B');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 100);
    EXPECT_TRUE(rb[0] == 'B');
}

void
debug_ring_ut::test_overcommit_dr_more_than_once()
{
    debug_ring dr(0);
    drr = get_drr(0);

    init_wb(100, 'A');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    init_wb(100, 'B');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    init_wb(100, 'C');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    init_wb(DEBUG_RING_SIZE - 150, 'D');
    EXPECT_NO_EXCEPTION(dr.write(wb));

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == DEBUG_RING_SIZE - 50);
    EXPECT_TRUE(rb[0] == 'C');
}

void
debug_ring_ut::test_read_with_empty_dr()
{
    debug_ring dr(0);
    drr = get_drr(0);

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == 0);
}

void
debug_ring_ut::acceptance_test_stress()
{
    debug_ring dr(0);
    drr = get_drr(0);

    auto wb = "012";

    for (auto i = 0U; i < DEBUG_RING_SIZE; i++)
        dr.write(wb);

    // The total number of bytes that we read out, should be equal to
    // the total number of strings that can fit into the debug ring, minus
    // the '\0' for each string (as they are stripped).

    auto num = DEBUG_RING_SIZE / (strlen(wb) + 1);
    auto total = num * strlen(wb);

    EXPECT_TRUE(debug_ring_read(drr, rb, DEBUG_RING_SIZE) == total);
    EXPECT_TRUE(rb[0] == '0');
}
