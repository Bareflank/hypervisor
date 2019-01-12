//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#include <catch/catch.hpp>

#include <bfgsl.h>
#include <bfdwarf.h>
#include <bfsupport.h>
#include <bfehframelist.h>
#include <bfconstants.h>

using init_t = void (*)();
using fini_t = void (*)();

extern "C" int mock_main(int argc, const char *argv[]);
extern "C" int64_t bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
extern "C" void __bareflank_init(const section_info_t *info);
extern "C" void __bareflank_fini(const section_info_t *info);
extern "C" void __bareflank_register_eh_frame(const section_info_t *info);
extern "C" void __bareflank_register_debug_info(const section_info_t *info);
extern "C" int64_t _start_c(const crt_info_t *info) noexcept;

int __g_eh_frame_list_num = 0;
eh_frame_t __g_eh_frame_list[MAX_NUM_MODULES] = {};
int __g_dwarf_sections_num = 0;
dwarf_sections_t __g_dwarf_sections[MAX_NUM_MODULES] = {};

bool init_called = false;
bool fini_called = false;

extern "C" void mock_init()
{ init_called = true; }

extern "C" void mock_fini()
{ fini_called = true; }

extern "C" void mock_abort() noexcept(false)
{ throw 42; }

TEST_CASE("bfmain and mock_main")
{
    CHECK(bfmain(0, 0, 0, 0) == -1);
    CHECK(mock_main(0, nullptr) == -1);

    try {
        mock_abort();
    }
    catch (...)
    { }
}

TEST_CASE("__bareflank_init: init")
{
    section_info_t info{};
    info.init_addr = reinterpret_cast<void *>(mock_init);

    auto ___ = gsl::finally([&] {
        init_called = false;
    });

    __bareflank_init(&info);
    CHECK(init_called);
}

TEST_CASE("__bareflank_init: valid init array, 0 entries")
{
    section_info_t info{};
    info.init_array_size = 0;
    info.init_array_addr = reinterpret_cast<void *>(mock_init);

    auto ___ = gsl::finally([&] {
        init_called = false;
    });

    __bareflank_init(&info);
    CHECK(!init_called);
}

TEST_CASE("__bareflank_init: valid init array")
{
    init_t array[1] = {mock_init};

    section_info_t info{};
    info.init_array_size = 8;
    info.init_array_addr = array;

    auto ___ = gsl::finally([&] {
        init_called = false;
    });

    __bareflank_init(&info);
    CHECK(init_called);
}

TEST_CASE("__bareflank_fini: fini")
{
    section_info_t info{};
    info.fini_addr = reinterpret_cast<void *>(mock_fini);

    auto ___ = gsl::finally([&] {
        fini_called = false;
    });

    __bareflank_fini(&info);
    CHECK(fini_called);
}

TEST_CASE("__bareflank_fini: valid fini array, 0 entries")
{
    section_info_t info{};
    info.fini_array_size = 0;
    info.fini_array_addr = reinterpret_cast<void *>(mock_fini);

    auto ___ = gsl::finally([&] {
        fini_called = false;
    });

    __bareflank_fini(&info);
    CHECK(!fini_called);
}

TEST_CASE("__bareflank_fini: valid fini array")
{
    fini_t array[1] = {mock_fini};

    section_info_t info{};
    info.fini_array_size = 8;
    info.fini_array_addr = array;

    auto ___ = gsl::finally([&] {
        fini_called = false;
    });

    __bareflank_fini(&info);
    CHECK(fini_called);
}

TEST_CASE("__bareflank_register_eh_frame: success")
{
    section_info_t info{};

    auto ___ = gsl::finally([&] {
        __g_eh_frame_list_num = 0;
    });

    CHECK_NOTHROW(__bareflank_register_eh_frame(&info));
}

TEST_CASE("__bareflank_register_eh_frame: too many")
{
    section_info_t info{};

    auto ___ = gsl::finally([&] {
        __g_eh_frame_list_num = 0;
    });

    for (auto i = 0U; i < MAX_NUM_MODULES; i++) {
        CHECK_NOTHROW(__bareflank_register_eh_frame(&info));
    }

    CHECK_THROWS(__bareflank_register_eh_frame(&info));
}

TEST_CASE("__bareflank_register_debug_info: success")
{
    section_info_t info{};

    auto ___ = gsl::finally([&] {
        __g_dwarf_sections_num = 0;
    });

    CHECK_NOTHROW(__bareflank_register_debug_info(&info));
}

TEST_CASE("__bareflank_register_debug_info: too many")
{
    section_info_t info{};

    auto ___ = gsl::finally([&] {
        __g_dwarf_sections_num = 0;
    });

    for (auto i = 0U; i < MAX_NUM_MODULES; i++) {
        CHECK_NOTHROW(__bareflank_register_debug_info(&info));
    }

    CHECK_THROWS(__bareflank_register_debug_info(&info));
}

TEST_CASE("_start_c: invalid info")
{
    CHECK(_start_c(nullptr) == -1);
}

TEST_CASE("_start_c: main success")
{
    crt_info_t info{};
    info.info_num = 5;

    auto ___ = gsl::finally([&] {
        __g_eh_frame_list_num = 0;
        __g_dwarf_sections_num = 0;
    });

    CHECK(_start_c(&info) == -1);
}

TEST_CASE("_start_c: bfmain init success")
{
    crt_info_t info{};
    info.arg_type = 1;
    info.info_num = 5;
    info.request = BF_REQUEST_INIT;

    auto ___ = gsl::finally([&] {
        __g_eh_frame_list_num = 0;
        __g_dwarf_sections_num = 0;
    });

    CHECK(_start_c(&info) == -1);
}

TEST_CASE("_start_c: bfmain fini success")
{
    crt_info_t info{};
    info.arg_type = 1;
    info.info_num = 5;
    info.request = BF_REQUEST_FINI;

    auto ___ = gsl::finally([&] {
        __g_eh_frame_list_num = 0;
        __g_dwarf_sections_num = 0;
    });

    CHECK(_start_c(&info) == -1);
}
