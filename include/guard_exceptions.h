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

#ifndef GUARD_EXCEPTIONS_H
#define GUARD_EXCEPTIONS_H

#include <iostream>
#include <error_codes.h>

template<class T, class E> E
guard_exceptions(E error_code, T func)
{
    try
    {
        func();

        return SUCCESS;
    }
    catch (std::bad_alloc &e)
    {
        return BF_BAD_ALLOC;
    }
    catch (std::exception &e)
    {
        std::cout << '\n';
        std::cerr << "----------------------------------------" << '\n';
        std::cerr << "- Standard Exception Caught            -" << '\n';
        std::cerr << "----------------------------------------" << '\n';
        std::cerr << e.what() << '\n';
    }
    catch (...)
    {
        std::cout << '\n';
        std::cerr << "----------------------------------------" << '\n';
        std::cerr << "- Unknown Exception Caught             -" << '\n';
        std::cerr << "----------------------------------------" << '\n';
    }

    return error_code;
}

template<class T> void
guard_exceptions(T &&func)
{
    guard_exceptions(0L, std::forward<T>(func));
}

#endif
