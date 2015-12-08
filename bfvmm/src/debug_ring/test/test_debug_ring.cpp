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
#include <debug_ring/debug_ring_base.h>

#define BUF_SIZE 10
#define DRR_SIZE 4096

debug_ring dr;

char rb[BUF_SIZE] = {0};
debug_ring_resources *drr = NULL;
debug_ring_resources *bad_drr = NULL;

bool
debug_ring_ut::init_debug_ring()
{
    drr = (debug_ring_resources *)calloc(DRR_SIZE, 1);
    bad_drr = (debug_ring_resources *)calloc(DRR_SIZE, 1);

    drr->len = BUF_SIZE;

    return true;
}

bool
debug_ring_ut::fini_debug_ring()
{
    free(drr);
    free(bad_drr);

    return true;
}

void
debug_ring_ut::test_init_dr_with_null_drr()
{
    EXPECT_TRUE(dr.init(NULL) == debug_ring_error::invalid);
}

void
debug_ring_ut::test_init_dr_with_zero_length()
{
    EXPECT_TRUE(dr.init(bad_drr) == debug_ring_error::invalid);
}

void
debug_ring_ut::test_read_with_invalid_drr()
{
    EXPECT_TRUE(debug_ring_read(NULL, rb, BUF_SIZE) == DEBUG_RING_READ_ERROR);
}

void
debug_ring_ut::test_write_with_invalid_dr()
{
    auto wb = "01234";

    EXPECT_TRUE(dr.init(NULL) == debug_ring_error::invalid);
    EXPECT_TRUE(dr.write(wb, strlen(wb)) == debug_ring_error::invalid);
}

void
debug_ring_ut::test_read_with_null_string()
{
    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, NULL, BUF_SIZE) == DEBUG_RING_READ_ERROR);
}

void
debug_ring_ut::test_read_with_zero_length()
{
    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, 0) == DEBUG_RING_READ_ERROR);
}

void
debug_ring_ut::test_write_with_null_string()
{
    auto wb = "01234";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(NULL, strlen(wb)) == debug_ring_error::failure);
}

void
debug_ring_ut::test_write_with_zero_length()
{
    auto wb = "01234";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb, 0) == debug_ring_error::failure);
}

void
debug_ring_ut::test_write_string_to_dr_that_is_larger_than_dr()
{
    auto wb = "0123456789";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb, strlen(wb)) == debug_ring_error::failure);
}

void
debug_ring_ut::test_write_string_to_dr_that_is_much_larger_than_dr()
{
    auto wb = "0123456789ABCDEFG";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb, strlen(wb)) == debug_ring_error::failure);
}

void
debug_ring_ut::test_write_one_small_string_to_dr()
{
    auto wb = "01234";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb, strlen(wb)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == 6);
}

void
debug_ring_ut::test_fill_dr()
{
    auto wb = "012345678";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb, strlen(wb)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == BUF_SIZE);
    EXPECT_TRUE(rb[BUF_SIZE - 1] == '\0');
}

void
debug_ring_ut::test_overcommit_dr()
{
    auto wb1 = "012345678";
    auto wb2 = "ABCDE";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb1, strlen(wb1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb2, strlen(wb2)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == 6);
    EXPECT_TRUE(rb[0] == 'A');
}

void
debug_ring_ut::test_overcommit_dr_more_than_once()
{
    auto wb1 = "012345678";
    auto wb2 = "ABCDE";
    auto wb3 = "FG";
    auto wb4 = "012345";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb1, strlen(wb1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb2, strlen(wb2)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb3, strlen(wb3)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(wb4, strlen(wb4)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == BUF_SIZE);
    EXPECT_TRUE(rb[0] == 'F');
}

void
debug_ring_ut::test_read_with_empty_dr()
{
    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == 0);
}

void
debug_ring_ut::acceptance_test_stress()
{
    auto wb = "012";

    EXPECT_TRUE(dr.init(drr) == debug_ring_error::success);

    for (auto i = 0; i < 1000; i++)
        dr.write(wb, strlen(wb));

    EXPECT_TRUE(debug_ring_read(drr, rb, BUF_SIZE) == 8);
    EXPECT_TRUE(rb[0] == '0');
}
