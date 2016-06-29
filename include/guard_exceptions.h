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

#include <debug.h>
#include <exception.h>
#include <error_codes.h>

template<class T> int64_t
guard_exceptions(int64_t error_code, T func)
{
    try
    {
        func();

        return SUCCESS;
    }
    catch (bfn::general_exception &ge)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- General Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << ge << bfendl;
    }
    catch (std::exception &e)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Standard Exception Caught            -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
        bfinfo << e.what() << bfendl;
    }
    catch (...)
    {
        bferror << "----------------------------------------" << bfendl;
        bferror << "- Unknown Exception Caught             -" << bfendl;
        bferror << "----------------------------------------" << bfendl;
    }

    return error_code;
}

#endif
