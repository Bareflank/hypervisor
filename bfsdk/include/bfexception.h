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

///
/// @file bfexception.h
///

#ifndef BFEXCEPTION_H
#define BFEXCEPTION_H

#include <typeinfo>
#include <exception>

#include <bftypes.h>
#include <bfdebug.h>
#include <bferrorcodes.h>

/// Guard Exceptions
///
/// Catches all exceptions and prints the exception that occurred. The point of
/// this function is to prevent any exception from bubbling beyond this point.
///
/// @expects
/// @ensures
///
/// @param error_code an error code to return if an exception occurs
/// @param func the function to run that is guarded
/// @return error_code on failure, SUCCESS on success
///
template<class T>
int64_t
guard_exceptions(int64_t error_code, T func)
{
    try {
        func();
        return SUCCESS;
    }
    catch (std::bad_alloc &) {
        return BF_BAD_ALLOC;
    }
    catch (std::exception &e) {
        bfdebug_transaction(1, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, typeid(e).name(), msg);
            bferror_brk1(0, msg);
            bferror_info(0, e.what(), msg);
        });
    }
    catch (...) {
        bfdebug_transaction(1, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, "unknown exception", msg);
            bferror_brk1(0, msg);
        });
    }

    return error_code;
}

/// Guard Exceptions
///
/// Catches all exceptions and prints the exception that occurred. The point of
/// this function is to prevent any exception from bubbling beyond this point.
///
/// @expects
/// @ensures
///
/// @param func the function to run that is guarded
///
template<class T>
void
guard_exceptions(T &&func)
{ guard_exceptions(0L, std::forward<T>(func)); }

#endif
