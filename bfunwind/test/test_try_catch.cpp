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
#include <string>
#include <exception.h>

enum throw_type
{
    throw_bool,
    throw_int,
    throw_cstr,
    throw_string,
    throw_exception,
    throw_custom_exception
};

throw_type g_throw_type = throw_exception;

auto g_raii_count = 0;

class raii
{
public:
    raii() = default;
    ~raii() { g_raii_count++; }
};

void
throw_bool_func()
{ throw true; }

void
throw_int_func()
{ throw 5; }

void
throw_cstr_func()
{ throw "1234"; }

void
throw_string_func()
{ throw std::string("1234"); }

void
throw_exception_func()
{ throw std::exception(); }

void
throw_custom_exception_func()
{ throw bfn::general_exception(); }

std::ostream &operator<<(std::ostream &os, const raii &unused)
{
    (void) unused;

    throw_exception_func();
    return os;
}

void
level2()
{
    switch (g_throw_type)
    {
        case throw_bool:
            throw_bool_func();
        case throw_int:
            throw_int_func();
        case throw_cstr:
            throw_cstr_func();
        case throw_string:
            throw_string_func();
        case throw_exception:
            throw_exception_func();
        case throw_custom_exception:
            throw_custom_exception_func();
    }
}

void
level1()
{ level2(); }

void
bfunwind_ut::test_catch_all()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_exception;
        level1();
    }
    catch (...)
    {
        caught = true;
    }

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_bool()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_bool;
        level1();
    }
    catch (bool val)
    {
        caught = true;
        this->expect_true(val);
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_int()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_int;
        level1();
    }
    catch (int val)
    {
        caught = true;
        this->expect_true(val == 5);
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_cstr()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_cstr;
        level1();
    }
    catch (const char *val)
    {
        caught = true;
        this->expect_true(strcmp(val, "1234") == 0);
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_string()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_string;
        level1();
    }
    catch (std::string &val)
    {
        caught = true;
        this->expect_true(val.compare("1234") == 0);
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_exception()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_exception;
        level1();
    }
    catch (std::exception &e)
    {
        caught = true;
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_custom_exception()
{
    auto caught = false;

    try
    {
        g_throw_type = throw_custom_exception;
        level1();
    }
    catch (bfn::general_exception &ge)
    {
        caught = true;
    }
    catch (...)
    {}

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_multiple_catches_per_function()
{
    auto caught = false;

    try
    {
        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
    caught = false;

    try
    {
        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
    caught = false;

    try
    {
        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_raii()
{
    auto caught = false;

    try
    {
        g_raii_count = 0;
        auto raii1 = raii();
        auto raii2 = raii();
        auto raii3 = raii();
        auto raii4 = raii();
        auto raii5 = raii();

        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
    this->expect_true(g_raii_count == 5);
}

void
bfunwind_ut::test_catch_throw_from_stream()
{
    auto caught = false;

    try
    {
        auto raii1 = raii();
        std::cout << raii1 << '\n';
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
}

void
bfunwind_ut::test_catch_nested_throw_in_catch()
{
    auto caught1 = false;
    auto caught2 = false;

    try
    {
        try
        {
            throw_exception_func();
        }
        catch (std::exception &e)
        {
            caught1 = true;
            throw_exception_func();
        }

    }
    catch (std::exception &e)
    {
        caught2 = true;
    }

    this->expect_true(caught1);
    this->expect_true(caught2);
}

void
bfunwind_ut::test_catch_nested_throw_outside_catch()
{
    auto caught1 = false;
    auto caught2 = false;

    try
    {
        try
        {
            throw_exception_func();
        }
        catch (std::exception &e)
        {
            caught1 = true;
        }

        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught2 = true;
    }

    this->expect_true(caught1);
    this->expect_true(caught2);
}

void
bfunwind_ut::test_catch_nested_throw_uncaught()
{
    auto caught1 = false;
    auto caught2 = false;

    try
    {
        try
        {
            throw_exception_func();
        }
        catch (bool val)
        {
            caught1 = true;
        }
    }
    catch (std::exception &e)
    {
        caught2 = true;
    }

    this->expect_false(caught1);
    this->expect_true(caught2);
}

void
bfunwind_ut::test_catch_nested_throw_rethrow()
{
    auto caught1 = false;
    auto caught2 = false;

    try
    {
        try
        {
            throw_exception_func();
        }
        catch (std::exception &e)
        {
            caught1 = true;
            throw e;
        }
    }
    catch (std::exception &e)
    {
        caught2 = true;
    }

    this->expect_true(caught1);
    this->expect_true(caught2);
}

void
bfunwind_ut::test_catch_throw_with_lots_of_register_mods()
{
    auto caught = false;

    auto r01 = 1;
    auto r02 = 2;
    auto r03 = 3;
    auto r04 = 4;
    auto r05 = 5;
    auto r06 = 6;
    auto r07 = 7;

    try
    {
        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
    this->expect_true(r01 == 1);
    this->expect_true(r02 == 2);
    this->expect_true(r03 == 3);
    this->expect_true(r04 == 4);
    this->expect_true(r05 == 5);
    this->expect_true(r06 == 6);
    this->expect_true(r07 == 7);

    caught = false;

    auto r11 = 1;
    auto r12 = 2;
    auto r13 = 3;
    auto r14 = 4;
    auto r15 = 5;
    auto r16 = 6;
    auto r17 = 7;

    try
    {
        throw_exception_func();
    }
    catch (std::exception &e)
    {
        caught = true;
    }

    this->expect_true(caught);
    this->expect_true(r11 == 1);
    this->expect_true(r12 == 2);
    this->expect_true(r13 == 3);
    this->expect_true(r14 == 4);
    this->expect_true(r15 == 5);
    this->expect_true(r16 == 6);
    this->expect_true(r17 == 7);
}
