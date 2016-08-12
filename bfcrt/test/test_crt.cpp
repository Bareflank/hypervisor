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

#include <crt.h>
#include <eh_frame_list.h>

int64_t
register_eh_frame(void *addr, uint64_t size) noexcept
{
    (void) addr;
    (void) size;

    return REGISTER_EH_FRAME_SUCCESS;
}

void
func1()
{ }

void
func2()
{ }

void
crt_ut::test_coveralls()
{
    EXPECT_TRUE(register_eh_frame(nullptr, 0) == REGISTER_EH_FRAME_SUCCESS);
    func1();
    func2();
}

void
crt_ut::test_local_init_invalid_arg()
{
    MockRepository mocks;
    mocks.NeverCallFunc(register_eh_frame);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(0) == CRT_FAILURE)
    });
}

void
crt_ut::test_local_init_invalid_addr()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.NeverCallFunc(func1);
    mocks.NeverCallFunc(func2);
    mocks.ExpectCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    info.ctors_size = 16;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_init_invalid_size()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.NeverCallFunc(func1);
    mocks.NeverCallFunc(func2);
    mocks.ExpectCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.ctors_addr = (void *)func_list;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_init_register_eh_frame_failure()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2);
    mocks.ExpectCallFunc(register_eh_frame).With((void *)10, 100).Return(REGISTER_EH_FRAME_FAILURE);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.ctors_size = 16;
    info.ctors_addr = (void *)func_list;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == REGISTER_EH_FRAME_FAILURE);
    });
}

void
crt_ut::test_local_init_valid_stop_at_size()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2);
    mocks.ExpectCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.ctors_addr = (void *)func_list;
    info.ctors_size = 16;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_init_valid_stop_at_null()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2);
    mocks.ExpectCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    void *func_list[3] = {(void *)func1, (void *)func2, 0};

    info.ctors_addr = (void *)func_list;
    info.ctors_size = 32;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_init_catch_exception()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2).Throw(std::runtime_error("error"));
    mocks.OnCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.ctors_addr = (void *)func_list;
    info.ctors_size = 16;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_init(&info) == CRT_FAILURE);
    });
}

void
crt_ut::test_local_fini_invalid_arg()
{
    EXPECT_TRUE(local_fini(0) == CRT_FAILURE);
}

void
crt_ut::test_local_fini_invalid_addr()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.NeverCallFunc(func1);
    mocks.NeverCallFunc(func2);

    info.dtors_size = 16;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_fini(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_fini_invalid_size()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.NeverCallFunc(func1);
    mocks.NeverCallFunc(func2);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.dtors_addr = (void *)func_list;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_fini(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_fini_valid_stop_at_size()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.dtors_addr = (void *)func_list;
    info.dtors_size = 16;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_fini(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_fini_valid_stop_at_null()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2);

    void *func_list[3] = {(void *)func1, (void *)func2, 0};

    info.dtors_addr = (void *)func_list;
    info.dtors_size = 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_fini(&info) == CRT_SUCCESS);
    });
}

void
crt_ut::test_local_fini_catch_exception()
{
    section_info_t info;

    memset(&info, 0, sizeof(info));

    MockRepository mocks;
    mocks.ExpectCallFunc(func1);
    mocks.ExpectCallFunc(func2).Throw(std::runtime_error("error"));
    mocks.OnCallFunc(register_eh_frame).With((void *)10, 100).Return(0);

    void *func_list[2] = {(void *)func1, (void *)func2};

    info.dtors_addr = (void *)func_list;
    info.dtors_size = 16;
    info.eh_frame_addr = (void *)10;
    info.eh_frame_size = 100;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(local_fini(&info) == CRT_FAILURE);
    });
}

