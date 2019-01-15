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
