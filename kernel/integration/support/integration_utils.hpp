/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef INTEGRATION_UTILS_HPP
#define INTEGRATION_UTILS_HPP

#include <bf_control_ops.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace integration
{
    /// <!-- description -->
    ///   @brief Reports passed/failed so that a script can detect if the
    ///     failed text shows up in the log. If the test fails, this
    ///     function will abort.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test the results to query
    ///   @param sloc used to identify the location in the integration test
    ///     where a check failed.
    ///
    constexpr void
    require(bool const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            syscall::bf_control_op_exit();
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Reports passed/failed so that a script can detect if the
    ///     failed text shows up in the log. If the test fails, this
    ///     function will abort.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ec the results to query
    ///   @param sloc used to identify the location in the integration test
    ///     where a check failed.
    ///
    constexpr void
    require(bsl::errc_type const ec, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!ec.success())) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            syscall::bf_control_op_exit();
        }
        else {
            bsl::touch();
        }
    }
}

#endif
