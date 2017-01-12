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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>
#include <bfelf_loader.h>

class bfunwind_ut : public unittest
{
public:

    bfunwind_ut();
    ~bfunwind_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_catch_all();
    void test_catch_bool();
    void test_catch_int();
    void test_catch_cstr();
    void test_catch_string();
    void test_catch_exception();
    void test_catch_custom_exception();
    void test_catch_multiple_catches_per_function();
    void test_catch_raii();
    void test_catch_throw_from_stream();
    void test_catch_nested_throw_in_catch();
    void test_catch_nested_throw_outside_catch();
    void test_catch_nested_throw_uncaught();
    void test_catch_nested_throw_rethrow();
    void test_catch_throw_with_lots_of_register_mods();
};

#endif
