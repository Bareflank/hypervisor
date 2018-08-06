//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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
/// @param error_func the function to run when an exception occurs
/// @return error_code on failure, SUCCESS on success
///
template <
    typename FUNC,
    typename ERROR_FUNC,
    typename = std::enable_if<std::is_pointer<FUNC>::value>,
    typename = std::enable_if<std::is_pointer<ERROR_FUNC>::value>
    >
int64_t
guard_exceptions(int64_t error_code, FUNC func, ERROR_FUNC error_func)
{
    try {
        func();
        return SUCCESS;
    }
    catch (std::bad_alloc &) {
        error_func();
        return BF_BAD_ALLOC;
    }
    catch (std::exception &e) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, typeid(e).name(), msg);
            bferror_brk1(0, msg);
            bferror_info(0, e.what(), msg);
        });
    }
    catch (...) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, "unknown exception", msg);
            bferror_brk1(0, msg);
        });
    }

    error_func();
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
/// @param error_code an error code to return if an exception occurs
/// @param func the function to run that is guarded
/// @return error_code on failure, SUCCESS on success
///
template <
    typename FUNC,
    typename = std::enable_if<std::is_pointer<FUNC>::value>
    >
int64_t
guard_exceptions(int64_t error_code, FUNC && func)
{ return guard_exceptions(error_code, std::forward<FUNC>(func), [] {}); }

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
template <
    typename FUNC,
    typename = std::enable_if<std::is_pointer<FUNC>::value>
    >
void
guard_exceptions(FUNC && func)
{ guard_exceptions(0L, std::forward<FUNC>(func), [] {}); }

/// Guard Exceptions
///
/// Catches all exceptions and prints the exception that occurred. The point of
/// this function is to prevent any exception from bubbling beyond this point.
///
/// @expects
/// @ensures
///
/// @param func the function to run that is guarded
/// @param error_func the function to run when an exception occurs
///
template <
    typename FUNC,
    typename ERROR_FUNC,
    typename = std::enable_if<std::is_pointer<FUNC>::value>,
    typename = std::enable_if<std::is_pointer<ERROR_FUNC>::value>
    >
void
guard_exceptions(FUNC && func, ERROR_FUNC && error_func)
{ guard_exceptions(0L, std::forward<FUNC>(func), std::forward<ERROR_FUNC>(error_func)); }

#endif
