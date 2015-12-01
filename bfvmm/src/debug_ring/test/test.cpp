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

debug_ring_ut::debug_ring_ut()
{
}

bool
debug_ring_ut::init()
{
    return true;
}

bool
debug_ring_ut::fini()
{
    return true;
}

bool
debug_ring_ut::list()
{
    this->test_create_dr_with_null_drr();
    this->test_create_dr_with_zero_length();
    this->test_read_with_invalid_drr();
    this->test_write_with_invalid_dr();
    this->test_read_with_null_string();
    this->test_read_with_zero_length();
    this->test_write_with_null_string();
    this->test_write_with_zero_length();
    this->test_write_string_to_dr_that_is_larger_than_dr();
    this->test_write_string_to_dr_that_is_much_larger_than_dr();
    this->test_write_one_small_string_to_dr();
    this->test_fill_dr();
    this->test_overcommit_dr();
    this->test_overcommit_dr_more_than_once();
    this->test_read_with_empty_dr();
    this->test_clear_empty_dr();
    this->test_write_dr_and_clear();
    this->test_overcommit_dr_and_clear();
    this->test_overcommit_dr_and_clear_and_write();

    this->acceptance_test_stress();

    return true;
}

#define BUF_SIZE 10
#define DRR_SIZE 4096

debug_ring_resources *
create_drr()
{
    int len = DRR_SIZE;
    debug_ring_resources *drr = (debug_ring_resources *)malloc(len);

    memset(drr, 0, len);
    drr->len = BUF_SIZE;

    return drr;
}

void
delete_drr(debug_ring_resources *drr)
{
    if (drr == NULL)
        return

            free(drr);
}

void debug_ring_ut::test_create_dr_with_null_drr()
{
    debug_ring dr(NULL);

    EXPECT_TRUE(dr.is_valid() == false);
}

void debug_ring_ut::test_create_dr_with_zero_length()
{
    debug_ring_resources *drr = create_drr();
    drr->len = 0;

    debug_ring dr(drr);

    EXPECT_TRUE(dr.is_valid() == false);

    delete_drr(drr);
}

void debug_ring_ut::test_read_with_invalid_drr()
{
    debug_ring dr(NULL);
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(debug_ring_read(NULL, r_buf, sizeof(r_buf)) == DEBUG_RING_READ_ERROR);
}

void debug_ring_ut::test_write_with_invalid_dr()
{
    debug_ring dr(NULL);
    char w_buf[] = "01234";

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::invalid);
}

void debug_ring_ut::test_read_with_null_string()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(debug_ring_read(drr, NULL, sizeof(r_buf)) == DEBUG_RING_READ_ERROR);

    delete_drr(drr);
}

void debug_ring_ut::test_read_with_zero_length()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(debug_ring_read(drr, r_buf, 0) == DEBUG_RING_READ_ERROR);

    delete_drr(drr);
}

void debug_ring_ut::test_write_with_null_string()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "01234";

    EXPECT_TRUE(dr.write(NULL, strlen(w_buf)) == debug_ring_error::failure);

    delete_drr(drr);
}

void debug_ring_ut::test_write_with_zero_length()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "01234";

    EXPECT_TRUE(dr.write(w_buf, 0) == debug_ring_error::failure);

    delete_drr(drr);
}

void debug_ring_ut::test_write_string_to_dr_that_is_larger_than_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "0123456789";

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::failure);

    delete_drr(drr);
}

void debug_ring_ut::test_write_string_to_dr_that_is_much_larger_than_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "0123456789ABCDEFG";

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::failure);

    delete_drr(drr);
}

void debug_ring_ut::test_write_one_small_string_to_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "01234";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 6);

    delete_drr(drr);
}

void debug_ring_ut::test_fill_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "012345678";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == BUF_SIZE);
    EXPECT_TRUE(r_buf[BUF_SIZE - 1] == '\0');

    delete_drr(drr);
}

void debug_ring_ut::test_overcommit_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf1[] = "012345678";
    char w_buf2[] = "ABCDE";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf1, strlen(w_buf1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf2, strlen(w_buf2)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 6);
    EXPECT_TRUE(r_buf[0] == 'A');

    delete_drr(drr);
}

void debug_ring_ut::test_overcommit_dr_more_than_once()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf1[] = "012345678";
    char w_buf2[] = "ABCDE";
    char w_buf3[] = "FG";
    char w_buf4[] = "012345";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf1, strlen(w_buf1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf2, strlen(w_buf2)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf3, strlen(w_buf3)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf4, strlen(w_buf4)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == BUF_SIZE);
    EXPECT_TRUE(r_buf[0] == 'F');

    delete_drr(drr);
}

void debug_ring_ut::test_read_with_empty_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 0);

    delete_drr(drr);
}

void debug_ring_ut::test_clear_empty_dr()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char r_buf[BUF_SIZE];

    dr.clear();

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 0);

    delete_drr(drr);
}

void debug_ring_ut::test_write_dr_and_clear()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "01234";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf, strlen(w_buf)) == debug_ring_error::success);

    dr.clear();

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 0);

    delete_drr(drr);
}

void debug_ring_ut::test_overcommit_dr_and_clear()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf1[] = "012345678";
    char w_buf2[] = "ABCDE";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf1, strlen(w_buf1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf2, strlen(w_buf2)) == debug_ring_error::success);

    dr.clear();

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 0);

    delete_drr(drr);
}

void debug_ring_ut::test_overcommit_dr_and_clear_and_write()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf1[] = "012345678";
    char w_buf2[] = "ABCDE";
    char w_buf3[] = "FGHIJ";
    char r_buf[BUF_SIZE];

    EXPECT_TRUE(dr.write(w_buf1, strlen(w_buf1)) == debug_ring_error::success);
    EXPECT_TRUE(dr.write(w_buf2, strlen(w_buf2)) == debug_ring_error::success);

    dr.clear();

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 0);

    EXPECT_TRUE(dr.write(w_buf3, strlen(w_buf3)) == debug_ring_error::success);
    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 6);
    EXPECT_TRUE(r_buf[0] == 'F');

    delete_drr(drr);
}

void debug_ring_ut::acceptance_test_stress()
{
    debug_ring_resources *drr = create_drr();
    debug_ring dr(drr);
    char w_buf[] = "012";
    char r_buf[BUF_SIZE];

    for (auto i = 0; i < 1000; i++)
        dr.write(w_buf, strlen(w_buf));

    EXPECT_TRUE(debug_ring_read(drr, r_buf, sizeof(r_buf)) == 8);
    EXPECT_TRUE(r_buf[0] == '0');

    delete_drr(drr);
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(debug_ring_ut);
}
